import os
import json
import logging
import socket
import tempfile

from io import BytesIO

from docker import Client
from docker.utils import kwargs_from_env

from tornado.ioloop import IOLoop
from tornado.httputil import url_concat
from tornado.httpclient import HTTPRequest

from checkio_console.mission import MissionFilesHandler
from checkio_console.tcpserver import TCPConsoleServer
from checkio_console.docker_ext.docker_async import SimpleAsyncDockerClient


class DockerClient():

    PREFIX_IMAGE = 'checkio'
    MEM_LIMIT = '512m'
    CPU_SHARES = '512'  # Default 2014

    def __init__(self, name_image, environment):
        self._client = Client(**kwargs_from_env(assert_hostname=False))
        self.name_image = "{}/{}-{}".format(self.PREFIX_IMAGE, name_image, environment)
        self.environment = environment
        self._container = None

    def run(self):
        self.create_container()
        self.start()

    def create_container(self):
        local_ip = socket.gethostbyname(socket.gethostname())
        command = "{} {}".format(local_ip, TCPConsoleServer.PORT)
        self._container = self._client.create_container(
            image=self.name_image,
            command=command,
            mem_limit=self.MEM_LIMIT,
            cpu_shares=self.CPU_SHARES
        )

    def start(self):
        self._client.start(container=self._container.get('Id'))

    def stop(self):
        self._client.stop(container=self._container.get('Id'))

    def logs(self, stream=False, logs=False):
        return self._client.attach(container=self.container_id, stream=True, logs=logs)

    @property
    def container_id(self):
        return self._container.get('Id')

    def cert_kwargs_from_env(self):
        cert_path = os.environ.get('DOCKER_CERT_PATH')
        return {
            'ca_certs': os.path.join(cert_path, 'ca.pem'),
            'client_cert': os.path.join(cert_path, 'cert.pem'),
            'client_key': os.path.join(cert_path, 'key.pem'),
            }

    def async_logs(self, io_loop, streaming_callback):
        def handle_request(response):
            if response.error:
                print("Error:", response.error)
            else:
                print(response.body)

        url = self._client._url("/containers/{0}/attach".format(self.container_id))
        url = url_concat(url, {
            'logs': 1,
            'stdout': 1,
            'stderr': 1,
            'stream': 1,
        })
        request = HTTPRequest(url=url, body=b'', method='POST', validate_cert=False,
                              connect_timeout=0,
                              streaming_callback=streaming_callback, **self.cert_kwargs_from_env())

        http_client = SimpleAsyncDockerClient(io_loop=io_loop)
        http_client.fetch(request, handle_request)

    def build_mission_image(self, path):
        with tempfile.TemporaryDirectory() as tmp_dir:
            mission_source = MissionFilesHandler(self.environment, path, tmp_dir)
            mission_source.schema_parse()
            mission_source.pull_base()
            mission_source.copy_user_files()
            mission_source.make_dockerfile()
            self._build(name=self.name_image, path=mission_source.path_destination_source)

    def _build(self, name, path=None, dockerfile_content=None):
        fileobj = None
        if dockerfile_content is not None:
            fileobj = BytesIO(dockerfile_content.encode('utf-8'))

        logging.info("Before build")
        for line in self._client.build(path=path, fileobj=fileobj, tag=name, nocache=True):
            line = self._format_ouput_line(line)
            if line is not None:
                print(line)

    def _format_ouput_line(self, line):
        line_str = line.decode().strip()
        value = json.loads(line_str)['stream'].strip()
        if not value:
            return None
        return value


def thread_runner(io_loop, mission, environment, path=None):
    docker = DockerClient(mission, environment)
    if path:
        docker.build_mission_image(path)
        logging.info('Image has build')
    logging.info('Run docker:')
    docker.run()

    def handle_streaming(data):
        logging.info(data.decode())

    docker.async_logs(io_loop=io_loop, streaming_callback=handle_streaming)

    if io_loop is None:
        IOLoop.instance().start()
