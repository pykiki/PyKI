#!/usr/bin/env python3
# -*- encoding: UTF-8 -*-
'''# encoding: utf-8'''

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
curScriptDir = ospath.dirname(ospath.abspath(__file__))
PyKImodPath = curScriptDir + "/../../"
sys.path.append(PyKImodPath)
from PyKI import PyKI

def genCert(name, pki, passphrase, usage, altnames = False, size = False, certenc = False, days = False):
    '''
    tools Generatin key and certificate
    '''

    if mainVerbosity:
        print("INFO: Generating server private key for "+name+"...")
    key = pki.create_key(passphrase=passphrase, keysize = size, name = name, usage = usage)
    if key['error'] :
        print("ERROR: Unable to generate key "+name+" properly, aborting...")
        return(False)
    elif mainVerbosity:
        print("INFO: Key "+name+" done.")

    if mainVerbosity:
        print("INFO: Generating certificate whith alt-names...")
    cert = pki.create_cert(
                            country = 'FR', state = 'PACA', city = 'Antibes',
                            org = 'Maibach.fr', ou = 'IT',
                            email = 'alain@maibach.fr',
                            KeyUsage = usage,
                            subjectAltName = altnames,
                            cn = name,
                            encryption = certenc,
                            days_valid = days
                          )
    if cert['error'] :
        print("ERROR: Unable to generate certificate "+name+" properly --> "+cert['message']+", aborting...")
        return(False)
    else:
        if mainVerbosity:
            print(cert['message'])

    return(True)

if __name__ == '__main__':
    mainVerbosity = True
    # passphrase of the private key requested for pki authentication
    #privateKeyPassphrase = getpass('PKI Auth key password: ')
    privateKeyPassphrase = 'a'
    # pki authentication private key path
    pkeyPath = "./pki_auth_cert.pem"

    # first init, creating private key
    if not ospath.exists(pkeyPath):
        print("\n!!!!! INFO: The auth private key will be saved in "+pkeyPath+" !!!!!\n")
        pki = PyKI(verbose = False, authKeypass=privateKeyPassphrase, authKeylen = 1024, KEY_SIZE = 1024, SIGN_ALGO = 'SHA1')
        #pki = PyKI(verbose = False, authKeypass=privateKeyPassphrase)

        # get private key for authentication after first init
        authprivkey = pki.initPkey
        # writing key to file
        try:
            wfile = open(pkeyPath, "wt")
        except IOError:
            print('ERROR: unable to open file '+pkeyPath)
            exit(1)
        else:
            try:
                wfile.write(authprivkey)
            except IOError:
                print('ERROR: Unable to write to file '+pkeyPath)
                exit(1)
            else:
                if mainVerbosity:
                    print('INFO: File ' + pkeyPath + ' written')
        finally:
            wfile.close()
            authprivkey = None

    # Init with privkey loaded from file
    pkey = open(pkeyPath ,'rt')
    pkeyStr = pkey.read()
    pkey.close()
    pki = PyKI(authKeypass=privateKeyPassphrase, privkeyStr=pkeyStr)
    
    # Set pki verbosity after init
    pki.set_verbosity(mainVerbosity)

    # gen server cert for 180 days
    subjectAltName = ['DNS:kiki.ritano.fr', 'DNS:wiki.maibach.fr', 'IP:37.187.105.119'] # Options are 'email', 'URI', 'IP', 'DNS'
    genCert(name = "wiki.maibach.fr", pki = pki, passphrase = 'azerty', altnames = subjectAltName, size = 1024, usage = 'serverAuth' , days = 180, certenc = 'sha1')

    # gen client cert for 180 days
    subjectAltName = ['DNS:kiki.ritano.fr', 'DNS:wiki.amaibach.fr', 'IP:37.187.105.119'] # Options are 'email', 'URI', 'IP', 'DNS'
    genCert(name = "kiki.ritano.fr", pki = pki, passphrase = 'azerty', altnames = subjectAltName, size = 4096, usage = 'clientAuth' , days = 180)
