#!/usr/bin/env python3
# -*- coding: UTF-8 -*-
# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4
r'''
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

__author__ = "Alain Maibach"
__status__ = "Beta tests"

try:
    from setuptools import setup, find_packages
except ImportError:
    from distutils.core import setup
from distutils.command.clean import clean

import os
import shutil
from glob import glob
from setuptools.command.install import install as InstallCommand

SOFTWARE_VERSION = "1.3"
SOFTWARE_REQUIREMENTS = "libxml2-dev libxslt-dev python-dev libcurl-openssl-dev pytest"


class Install(InstallCommand):
    '''
        This must help us to install OS specific packages.
        Unused from now on.
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


class MyClean(clean):
    """
        Custom clean command to tidy up the project root.
    """
    CLEAN_FILES = './build ./dist ./*.pyc ./*.tgz ./*.egg-info'.split(' ')

    user_options = []

    def initialize_options(self):
        '''
            Nothing to init'
        '''
        # pass

    def finalize_options(self):
        '''
            Nothing to finalize
        '''
        # pass

    def run(self):
        '''
          Main part which clean what we need.
        '''
        cur_script_dir = os.path.dirname(os.path.abspath(__file__))

        for path_spec in self.CLEAN_FILES:
            # Make paths absolute and relative to this path
            abs_paths = glob(os.path.normpath(
                                os.path.join(cur_script_dir,
                                             path_spec)))
            for path in [str(p) for p in abs_paths]:
                if not path.startswith(cur_script_dir):
                    raise ValueError("%s is not part of %s" % (path,
                                                               cur_script_dir))
                print('removing %s' % os.path.relpath(path))
                shutil.rmtree(path)


config = {
    'name': 'PyKI',
    'version': str(SOFTWARE_VERSION),
    'description': 'TLS PKI manager',
    'author': 'Maibach Alain',
    'author_email': 'alain.maibach@gmail.com',
    'maintainer': 'Maibach Alain',
    'url': 'https://github.com/pykiki',
    'download_url': 'https://github.com/pykiki/PyKI',
    'packages':find_packages(exclude=['tests']),
    'scripts': [
      'tools/bin/pyki-init',
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
    'tests_require': [
            'mock',
            'pytest',
            'pytz',
    ],
    'install_requires': [
        'cffi',
        'cryptography',
        'idna',
        'pyasn1',
        'pycparser',
        #  'PyCryptodome',
        'pycrypto',
        'pyOpenSSL',
        'pytz',
        'pytest',
        'six',
        'wheel',
        'xkcdpass'],
    #  'cmdclass': {
    #      'test': pytest
    #  },
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

if __name__ == '__main__':
    setup(**config)
