#!/usr/bin/env python3
# -*- coding: UTF-8 -*-

__author__ = "Alain Maibach"
__status__ = "Beta tests"

'''
    PyKI - PKI openssl for managing TLS certificates
    Copyright (C) 2016 MAIBACH ALAIN

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.

    Contact: alain.maibach@gmail.com / 34 rue appienne 13480 - FRANCE.
'''

try:
  from setuptools import setup
except ImportError:
  from distutils.core import setup

import sys
from setuptools.command.test import test as TestCommand
from setuptools.command.install import install as InstallCommand

version = "1.3"
requirements = "libxml2-dev libxslt-dev python-dev libcurl-openssl-dev"

class Install(InstallCommand):
  '''
  '''
  def run(self):
    '''
    params = "{install_params} {requirements}".format(
      install_params="install", requirements=requirements)
    cmd = "{command} {params}".format(command="apt-get", params=params)
    proc = subprocess.Popen(cmd, shell=True)
    proc.wait()
    '''
    InstallCommand.run(self)

class Test(TestCommand):
  '''
  '''
  user_options = [('pytest-args=', 'a', "")]

  def initialize_options(self):
    TestCommand.initialize_options(self)
    self.pytest_args = []

  def finalize_options(self):
    TestCommand.finalize_options(self)
    self.test_args = []
    self.test_suite = True

  def run_tests(self):

    import pytest
    errno = pytest.main(self.pytest_args)
    sys.exit(errno)

config = {
    'name': 'PyKI',
    'version': str(version),
    'description': 'TLS PKI manager',
    'author': 'Maibach Alain',
    'author_email': 'alain.maibach@gmail.com',
    'maintainer': 'Maibach Alain',
    'url': 'https://github.com/pykiki',
    'download_url': 'https://github.com/pykiki/PyKI',
    'packages': ['PyKI'],
    'scripts': [
      'tools/bin/pyki-check_key_vs_cert',
      'tools/bin/pyki-create_pkcs12',
      'tools/bin/pyki-extract_pkcs12',
      'tools/bin/pyki-gen_cert',
      'tools/bin/pyki-gen_csr',
      'tools/bin/pyki-get_infocert',
      'tools/bin/pyki-get_inforeq',
      'tools/bin/pyki-get_nameList',
      'tools/bin/pyki-get_passphrases',
      'tools/bin/pyki-get_validity',
      'tools/bin/pyki-is_conform',
      'tools/bin/pyki-read_crl',
      'tools/bin/pyki-read_pki_db',
      'tools/bin/pyki-removePass',
      'tools/bin/pyki-renew_crl',
      'tools/bin/pyki-revoke_cert',
      'tools/bin/pyki-sign_csr',
    ],
    'data_files': [
    (
    '/etc', ['tools/config/pyki-config.ini']
    )
    ],
    'license': 'GNU GPLv3',
    'install_requires': [
        'cffi',
        'cryptography',
        'idna',
        'pyasn1',
        'pycparser',
        'pycrypto',
        'pyOpenSSL',
        'pytz',
        'six',
        'xkcdpass'],
    'platforms': [
        'Linux',
        'OSX'],
    'zip_safe': False,
    'keywords': 'PKI, TLS, python, module, library, certificates, openssl',
    'classifiers': [
        'Development Status :: 2 - Pre-Alpha',
        'Environment :: Web Environment',
        'Environment :: Console',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: BSD License',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3.6',
        'Topic :: Internet',
        'Topic :: Software Development :: Libraries :: Python Modules',
        'Topic :: Utilities']}

setup(**config)
