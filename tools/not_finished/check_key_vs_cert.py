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
    
    certPass = None

    # passphrase of the private key requested for pki authentication
    privateKeyPassphrase = getpass('PKI Auth key password: ')
    
    # pki authentication private key path
    pkeyPath = "./pki_auth_cert.pem"

    # Init with privkey loaded from file
    pkey = open(pkeyPath ,'rt')
    pkeyStr = pkey.read()
    pkey.close()
    pki = PyKI(authKeypass=privateKeyPassphrase, privkeyStr=pkeyStr)
    
    # Set pki verbosity after init
    pki.set_verbosity(mainVerbosity)

    certpath = "/opt/PyKI_data/CERTS/signed/test_gencsr/test_gencsr.crt"
    keypath = "/opt/PyKI_data/CERTS/requests/test_gencsr/test_gencsr.key"

    # if you do not specify it, and the key is encrypted, you will be prompted for it
    certPass = getpass('Certificate private key passphrase: ')
    if certPass == '' or certPass == ' ':
        certPass = None

    # check that the key generated match the cert signed
    reschk = pki.check_cer_vs_key(cert = certpath, key = keypath, keypass = certPass)
    print(reschk['message'])
