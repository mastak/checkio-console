import base64
import struct

from tornado import stack_context, httputil, gen
from tornado.escape import utf8
from tornado.log import app_log
from tornado.simple_httpclient import SimpleAsyncHTTPClient, _HTTPConnection
from tornado.http1connection import HTTP1Connection, HTTP1ConnectionParameters, _ExceptionLoggingContext

STREAM_HEADER_SIZE_BYTES = 8


class SimpleAsyncDockerClient(SimpleAsyncHTTPClient):

    @classmethod
    def configurable_base(cls):
        return SimpleAsyncDockerClient

    @classmethod
    def configurable_default(cls):
        return SimpleAsyncDockerClient

    def _handle_request(self, request, release_callback, final_callback):
        HTTPConnection(self.io_loop, self, request, release_callback,
                        final_callback, self.max_buffer_size, self.tcp_client,
                        self.max_header_size)


class HTTPConnection(_HTTPConnection):

    def _on_connect(self, stream):
        if self.final_callback is None:
            # final_callback is cleared if we've hit our timeout.
            stream.close()
            return
        self.stream = stream
        self.stream.set_close_callback(self.on_connection_close)
        self._remove_timeout()
        if self.final_callback is None:
            return
        if self.request.request_timeout:
            self._timeout = self.io_loop.add_timeout(
                self.start_time + self.request.request_timeout,
                stack_context.wrap(self._on_timeout))
        if (self.request.method not in self._SUPPORTED_METHODS and
                not self.request.allow_nonstandard_methods):
            raise KeyError("unknown method %s" % self.request.method)
        for key in ('network_interface',
                    'proxy_host', 'proxy_port',
                    'proxy_username', 'proxy_password'):
            if getattr(self.request, key, None):
                raise NotImplementedError('%s not supported' % key)
        if "Connection" not in self.request.headers:
            self.request.headers["Connection"] = "close"
        if "Host" not in self.request.headers:
            if '@' in self.parsed.netloc:
                self.request.headers["Host"] = self.parsed.netloc.rpartition('@')[-1]
            else:
                self.request.headers["Host"] = self.parsed.netloc
        username, password = None, None
        if self.parsed.username is not None:
            username, password = self.parsed.username, self.parsed.password
        elif self.request.auth_username is not None:
            username = self.request.auth_username
            password = self.request.auth_password or ''
        if username is not None:
            if self.request.auth_mode not in (None, "basic"):
                raise ValueError("unsupported auth_mode %s",
                                 self.request.auth_mode)
            auth = utf8(username) + b":" + utf8(password)
            self.request.headers["Authorization"] = (b"Basic " +
                                                     base64.b64encode(auth))
        if self.request.user_agent:
            self.request.headers["User-Agent"] = self.request.user_agent
        if not self.request.allow_nonstandard_methods:
            if self.request.method in ("POST", "PATCH", "PUT"):
                if (self.request.body is None and
                        self.request.body_producer is None):
                    raise AssertionError(
                        'Body must not be empty for "%s" request'
                        % self.request.method)
            else:
                if (self.request.body is not None or
                        self.request.body_producer is not None):
                    raise AssertionError(
                        'Body must be empty for "%s" request'
                        % self.request.method)
        if self.request.expect_100_continue:
            self.request.headers["Expect"] = "100-continue"
        if self.request.body is not None:
            # When body_producer is used the caller is responsible for
            # setting Content-Length (or else chunked encoding will be used).
            self.request.headers["Content-Length"] = str(len(
                self.request.body))
        if (self.request.method == "POST" and
                "Content-Type" not in self.request.headers):
            self.request.headers["Content-Type"] = "application/x-www-form-urlencoded"
        if self.request.decompress_response:
            self.request.headers["Accept-Encoding"] = "gzip"
        req_path = ((self.parsed.path or '/') +
                    (('?' + self.parsed.query) if self.parsed.query else ''))
        self.stream.set_nodelay(True)
        self.connection = _HTTP1Connection(
            self.stream, True,
            HTTP1ConnectionParameters(
                no_keep_alive=True,
                max_header_size=self.max_header_size,
                decompress=self.request.decompress_response),
            self._sockaddr)
        start_line = httputil.RequestStartLine(self.request.method,
                                               req_path, 'HTTP/1.1')
        self.connection.write_headers(start_line, self.request.headers)
        if self.request.expect_100_continue:
            self._read_response()
        else:
            self._write_body(True)


class _HTTP1Connection(HTTP1Connection):

    def _read_body(self, code, headers, delegate):
        return self._read_chunked_body(delegate)

    @gen.coroutine
    def _read_chunked_body(self, delegate):
        while True:
            chunk_header = yield self.stream.read_bytes(STREAM_HEADER_SIZE_BYTES)
            if chunk_header == 0:
                return
            _, chunk_len = struct.unpack('>BxxxL', chunk_header)
            if chunk_len == 0:
                return

            bytes_to_read = chunk_len
            while bytes_to_read:
                chunk = yield self.stream.read_bytes(bytes_to_read)
                if not chunk:
                    return
                bytes_to_read -= len(chunk)
                if not self._write_finished or self.is_client:
                    with _ExceptionLoggingContext(app_log):
                        yield gen.maybe_future(delegate.data_received(chunk))
