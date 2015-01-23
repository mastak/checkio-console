import logging
import signal

from tornado.escape import json_encode, json_decode
from tornado.ioloop import IOLoop
from tornado.tcpserver import TCPServer


class ClientDataInterface(object):

    @staticmethod
    def handle_data(data):
        logging.info("[CONSOLE-SERVER] :: Data recived: {}".format(data))


class TCPConsoleServer(TCPServer):

    PORT = 7878

    data_interface = ClientDataInterface

    def handle_stream(self, stream, address):
        StreamReader(stream, address, self)


class StreamReader(object):

    terminator = b'\n'

    def __init__(self, stream, address, server):
        self.stream = stream
        self.address = address
        self.server = server
        self._is_connection_closed = False
        self.stream.set_close_callback(self._on_client_connection_close)
        self._read_data()

    def _on_client_connection_close(self):
        self._is_connection_closed = True
        logging.info("Client at address {} has closed the connection".format(self.address))

    def _read_data(self):
        self.stream.read_until(self.terminator, self._on_data)

    def _on_data(self, data):
        data = data.decode('utf-8')
        if data is None:
            message = dict(err='invalid_data', desc='Client sent an empty data')
            return self.send_client_response(message)

        data = json_decode(data)
        response = self.server.data_interface.handle_data(data)
        if response is not None:
            return self.send_client_response(response)

    def send_client_response(self, message):
        if self._is_connection_closed:
            return
        if isinstance(message, dict):
            message = json_encode(message)

        try:
            self.stream.write("{}\n".format(message))
        except Exception as e:
            logging.error(e)


def thread_runner(io_loop=None):
    server = TCPConsoleServer(io_loop=io_loop)
    logging.info("Running tcp server")
    server.listen(TCPConsoleServer.PORT)

    if io_loop is None:
        IOLoop.instance().start()


if __name__ == '__main__':
    def exit_signal(sig, frame):
        IOLoop.instance().add_callback(IOLoop.instance().stop)

    signal.signal(signal.SIGINT, exit_signal)
    signal.signal(signal.SIGTERM, exit_signal)

    _server = TCPConsoleServer()
    _server.listen(TCPConsoleServer.PORT)
    IOLoop.instance().start()
