#!/usr/bin/env python

from distutils.core import setup

setup(
    name='CheckiO console',
    version='1.0',
    description='CheckiO console for run and debug mission',
    author='CheckiO',
    author_email='igor@checkio.org',
    entry_points={
        'console_scripts': ['checkio-cli = checkio_console.cli:main'],
    },
)
