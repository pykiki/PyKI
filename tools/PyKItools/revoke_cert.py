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
        description='Revoke a certificate by its name in the PKI.')
    parser.add_argument(
        "-n",
        "--cn",
        action="store",
        dest="cn",
        type=str,
        help=u"Certificate common name",
        metavar='Common Name',
        required=True)
    parser.add_argument(
        "-r",
        "--reason",
        action='store',
        dest="reason",
        type=str,
        default='cessationOfOperation',
        metavar='unspecified|keyCompromise|CACompromise|affiliationChanged|superseded|cessationOfOperation|certificateHold',
        choices=[
            'unspecified',
            'keyCompromise',
            'CACompromise',
            'affiliationChanged',
            'superseded',
            'cessationOfOperation',
            'certificateHold'],
        help=u"Select which type of use is required for the certificate",
        required=True)
    parser.add_argument(
        "-d",
        "--date",
        action='store',
        dest="revokdate",
        type=str,
        default=False,
        metavar='"%d/%m/%Y"',
        help=u"Define a specific date for the revocation to take place.",
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

    if args['cn'] not in pki.nameList:
        print('ERROR: Certificate ' + args['cn'] + " doesn't exist.")
        exit(1)

    if args['mainVerbosity']:
        print(
            "INFO: Revoking certificate " +
            args['cn'] +
            " for " +
            args['reason'])

    if args['revokdate']:
        crl = pki.revoke_cert(certname=args['cn'], reason=args['reason'], date=args['revokdate'])
    else:
        crl = pki.revoke_cert(certname=args['cn'], reason=args['reason'])
    if crl['error']:
        print(crl['message'])
    elif args['mainVerbosity']:
        print(crl['message'])

    pki.remove_lockf("INFO: PKI unlocked.")
    del(pki)
    exit(0)
