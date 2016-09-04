#!/usr/bin/env python3
# -*- coding: UTF-8 -*-

from os import path as ospath, sys
curScriptDir = ospath.dirname(ospath.abspath(__file__))
PyKImodPath = curScriptDir + "/../"
sys.path.append(PyKImodPath)
from PyKI import PyKI

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

if __name__ == '__main__':
    mainVerbosity = True
    # passphrase of the private key requested for pki authentication
    #privateKeyPassphrase = getpass('PKI Auth key password: ')
    privateKeyPassphrase = 'a'
    # pki authentication private key path
    pkeyPath = "./pki_auth_cert.pem"

    #pkcspw = getpass('pkcs12 passphrase: ')
    pkcspw = "azerty"

    # first init, creating private key
    if not ospath.exists(pkeyPath):
        print(
            "\n!!!!! INFO: The auth private key will be saved in " +
            pkeyPath +
            " !!!!!\n")
        pki = PyKI(
            verbose=False,
            authKeypass=privateKeyPassphrase,
            authKeylen=1024,
            KEY_SIZE=1024,
            SIGN_ALGO='SHA1')
        #pki = PyKI(verbose = False, authKeypass=privateKeyPassphrase)

        # get private key for authentication after first init
        authprivkey = pki.initPkey
        # writing key to file
        try:
            wfile = open(pkeyPath, "wt")
        except IOError:
            print('ERROR: unable to open file ' + pkeyPath)
            exit(1)
        else:
            try:
                wfile.write(authprivkey)
            except IOError:
                print('ERROR: Unable to write to file ' + pkeyPath)
                exit(1)
            else:
                if mainVerbosity:
                    print('INFO: File ' + pkeyPath + ' written')
        finally:
            wfile.close()
            authprivkey = None

    # Init with privkey loaded from file
    pkey = open(pkeyPath, 'rt')
    pkeyStr = pkey.read()
    pkey.close()
    pki = PyKI(authKeypass=privateKeyPassphrase, privkeyStr=pkeyStr)

    # Set pki verbosity after init
    pki.set_verbosity(mainVerbosity)

    # try to extract ca, cert and key from pkcs12 file
    pkcsfile = '/opt/PyKI_data/CERTS/servers/wiki.maibach.fr/wiki.maibach.fr.p12'
    dstdata = pkcsfile + '_extracted/'
    if mainVerbosity:
        print(
            "INFO: Extract pkcs12 content from file " +
            pkcsfile +
            " to " +
            dstdata +
            "...")
    extractres = pki.extract_pkcs12(
        pkcs12file=pkcsfile,
        pkcs12pwd=pkcspw,
        destdir=dstdata)
    if extractres['error']:
        print(extractres['message'])
    elif mainVerbosity:
        print(extractres['message'])
