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
        description='Check that certificate and key are mathching and belong each others.')
    parser.add_argument(
        "-c",
        "--cert-path",
        action="store",
        dest="certpath",
        type=str,
        help=u"Certificate file path",
        metavar='path/to/cert/file',
        required=True)
    parser.add_argument(
        "-k",
        "--key-path",
        action="store",
        dest="keypath",
        type=str,
        help=u"Private key file path",
        metavar='/path/to/key/file',
        required=True)
    parser.add_argument(
        "-s",
        "--cert-pass",
        action='store',
        dest="certPass",
        type=str,
        default=False,
        help=u"Private key passphrase",
        metavar='mypassphrase',
        required=False)
    parser.add_argument(
        "-p",
        "--prompt",
        action='store_true',
        dest="stdin",
        help=u"Use STDIN to give certificate passphrase",
        required=False)
    parser.add_argument(
        "-v",
        "--verbose",
        action='store_true',
        dest='mainVerbosity',
        help=u"Add output verbosity",
        required=False)
    args = parser.parse_args()

    if len(argv) <= 1:
        parser.print_help()
        exit(1)

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

    if args['stdin']:
        args['certPass'] = None
    else:
        if args['certPass'] and (
                args['certPass'] == '' or args['certPass'] == ' '):
            args['certPass'] = None

    # Check that the key generated match the cert signed
    # If you do not specify password and the private key is protected, you
    # will be ask for it.
    reschk = pki.check_cer_vs_key(
        cert=args['certpath'],
        key=args['keypath'],
        keypass=args['certPass'])
    print(reschk['message'])

    pki.remove_lockf("INFO: PKI unlocked.")
    del(pki)
    exit(0)
