# Console tool for running missions at own computer.
#
# Author: CheckiO <igor@checkio.org>
# Last Change:
# URL: https://github.com/CheckiO/checkio-console

"""
:py:mod:`checkio_console.cli` - Command line interface for CheckiO
==============================================================================
"""

import signal
import argparse
import logging
import sys
import textwrap
import coloredlogs
import threading
from threading import Thread

from tornado.ioloop import IOLoop

from checkio_console import tcpserver
from checkio_console.docker_ext import docker_client

exit_event = threading.Event()
logger = logging.getLogger(__name__)

parser = argparse.ArgumentParser(description='Command line interface for CheckiO')
parser.add_argument('-e', '--environment', help='Mission environment name')
parser.add_argument('-p', '--path', help='Mission files path for build image')
parser.add_argument('-m', '--mission', help='Mission name', required=True)
options = parser.parse_args()


def main():
    """The command line interface for the ``checkio`` program."""
    def exit_signal(sig, frame):
        logging.info("Trying exit")
        io_loop.add_callback(IOLoop.instance().stop)
        exit_event.set()

    signal.signal(signal.SIGINT, exit_signal)
    signal.signal(signal.SIGTERM, exit_signal)

    if not options:
        usage()
        sys.exit(0)

    coloredlogs.install()
    logging.info('Run...')

    io_loop = IOLoop.instance()
    thread_tcpserver = Thread(target=tcpserver.thread_runner, args=(io_loop,))

    args_docker = (io_loop, options.mission, options.environment, options.path)
    thread_docker = Thread(target=docker_client.thread_runner, args=args_docker)

    thread_tcpserver.start()
    thread_docker.start()
    io_loop.start()


def usage():
    """Print a usage message to the terminal."""
    print(textwrap.dedent("""
        Usage: checkio-cli [ARGS]
        The checkio-cli ....
        For more information please refer to the GitHub project page
        at https://github.com/CheckiO/checkio-cli
    """).strip())


if __name__ == '__main__':
    main()
