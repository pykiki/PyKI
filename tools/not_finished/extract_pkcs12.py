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

from socket import gethostname
from os import path as ospath, sys
from getpass import getpass
from PyKI import PyKI

if __name__ == '__main__':
    mainVerbosity = False
    # passphrase of the private key requested for pki authentication
    privateKeyPassphrase = getpass('PKI Authentication private key password: ')

    # pki authentication private key path
    pkeyPath = "./pki_auth_cert.pem"

    pkcspw = getpass('PKCS12 file passphrase: ')

    # Init with privkey loaded from file
    pkey = open(pkeyPath ,'rt')
    pkeyStr = pkey.read()
    pkey.close()
    pki = PyKI(authKeypass=privateKeyPassphrase, privkeyStr=pkeyStr)
    
    # Set pki verbosity after init
    pki.set_verbosity(mainVerbosity)

    # try to extract ca, cert and key from pkcs12 file
    pkcsfile = '/opt/PyKI_data/CERTS/servers/MBP.local/MBP.local.p12'
    dstdata = pkcsfile+'_extracted/'
    if mainVerbosity:
        print("INFO: Extract pkcs12 content from file "+pkcsfile+" to "+dstdata+"...")
    extractres = pki.extract_pkcs12(pkcs12file = pkcsfile, pkcs12pwd = pkcspw, destdir = dstdata)
    print(extractres['message'])
