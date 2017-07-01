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

from sys import argv
import os
from PyKI import PyKInit


def argCommandline(argv):
    """
    Manage cli script args
    """
    parser = argparse.ArgumentParser(
        description='Sign Certificate request and store them in the PKI signed directory')
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
        "-d",
        "--duration",
        action='store',
        dest="duration",
        type=int,
        default=360,
        help=u"Number of days for certificate validity period",
        metavar='X',
        required=False)
    parser.add_argument(
        "-k",
        "--key-usage",
        action='store',
        dest="usage",
        type=str,
        default=False,
        metavar='digitalSignature, nonRepudiation, contentCommitment, keyEncipherment, dataEncipherment, keyAgreement, keyCertSign, cRLSign, encipherOnly, decipherOnly',
        help=u"Select which type of use is required for the certificate",
        required=False)
    parser.add_argument(
        "-p",
        "--purpose",
        action='store',
        dest="purpose",
        type=str,
        default='server',
        metavar='client|server',
        choices=[
            'server',
            'client'],
        help=u"Select which type of use is required for the certificate",
        required=True)
    parser.add_argument(
        "-e",
        "--encryption",
        action='store',
        dest="encryption",
        type=str,
        default=False,
        help=u"Certificate encryption level",
        metavar="SHA1|SHA256|SHA512",
        choices=[
            'SHA1',
            'SHA256',
            'SHA512'],
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

    if args['purpose'] == 'server':
        args['purpose'] = 'serverAuth'
    elif args['purpose'] == 'client':
        args['purpose'] = 'clientAuth'

    print("INFO: Signing Certificate Request " + filepath +
          " for " + str(args['duration']) + " days of validity...")

    signRes = pki.sign_csr(
        csr=filepath,
        KeyPurpose=args['purpose'],
        KeyUsage=args['usage'],
        days_valid=args['duration'],
        encryption=args['encryption'])
    if signRes['error']:
        print(
            "ERROR: Unable to generate certificate for csr " +
            filepath +
            " properly --> " +
            signRes['message'] +
            ", aborting...")
        exit(1)
    else:
        print(signRes['message'])
        print('INFO: The certificate is available in: /opt/PyKI_data/CERTS/signed/')

    pki.remove_lockf("INFO: PKI unlocked.")
    del(pki)
    exit(0)
