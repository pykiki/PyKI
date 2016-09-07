#!/usr/bin/env python3
# -*- coding: UTF-8 -*-

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

    Contact: alain.maibach@gmail.com / 1133 route de Saint Jean 06600 Antibes - FRANCE.
'''
import argparse

from sys import path as syspath, argv
import os
from PyKI import PyKInit


def argCommandline(argv):
    """
    Manage cli script args
    """
    parser = argparse.ArgumentParser(
        description='Get informations from Certificate Signing Request')
    parser.add_argument(
        "-f",
        "--file-path",
        action="store",
        dest="filepath",
        type=str,
        help=u"Certificate request file path",
        metavar='path/to/request/file',
        required=False)
    parser.add_argument(
        "-n",
        "--name",
        action="store",
        dest="filename",
        type=str,
        help=u"Certificate request pki file name",
        metavar='csrname',
        required=False)
    parser.add_argument(
        "-v",
        "--verbose",
        action='store_true',
        dest='mainVerbosity',
        help=u"Add output verbosity",
        required=False)

    args = parser.parse_args()
    result = vars(args)
    return(result)

if __name__ == '__main__':
    args = argCommandline(argv)

    curScriptDir = os.path.dirname(os.path.abspath(__file__))
    configFilePath = curScriptDir + '/config/config.ini'

    pyki = PyKInit.PyKIsetup(configFilePath)
    pki = pyki.pki
    if not pki:
        print("ERROR: Errors found during init")
        exit(1)
    pki.set_verbosity(args['mainVerbosity'])

    if not args['filepath'] and not args['filename']:
        print("ERROR: Please specify CSR name in the PKI or the csr file path.")
        exit(1)

    if args['filepath']:
        if not os.path.exists(args['filepath']):
            print("ERROR: File " + args['filepath'] + " not found")
            exit(1)
        filepath = args['filepath']
    else:
        filepath = pki.csrDir + '/' + \
            args['filename'] + '/' + args['filename'] + '.csr'

    print("\nCertificate request informations for " + filepath)
    csr_info = pki.get_csrinfo(filepath)
    print("\n" + csr_info['message'])

    pki.remove_lockf("INFO: PKI unlocked.")
    del(pki)
    exit(0)
