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

from socket import gethostname
from os import path as ospath, sys
from getpass import getpass
from PyKI import PyKI

def getPass(name, pki):
    passphrases = pki.loadpassDB()
    if not passphrases['error']:
        # we are calling pki func cleanStr() to match the correct certname in database
        database_certname = passphrases['message'][pki.cleanStr(name)]
    else:
        database_certname = False
    passphrases.clear()
    return(database_certname)

def rmPass(name, pki, passphrase):
    '''
    Remove passphrase from key
    '''
    # define type in pkicert.db /get path in crt dir
    print("INFO: Removing passphrase from "+name)

    unprotectres = pki.unprotect_key(keyname = name, privKeypass = passphrase)
    if unprotectres['error']:
        print(unprotectres['message'])
        return(False)

    print(unprotectres['message'])
    return(True)

if __name__ == '__main__':
    mainVerbosity = True

    # passphrase of the private key requested for pki authentication
    privateKeyPassphrase = getpass('PKI Authentication private key password: ')
    
    # pki authentication private key path
    pkeyPath = "./pki_auth_cert.pem"

    # Init with privkey loaded from file
    pkey = open(pkeyPath ,'rt')
    pkeyStr = pkey.read()
    pkey.close()
    pki = PyKI(authKeypass=privateKeyPassphrase, privkeyStr=pkeyStr)
    
    # Set pki verbosity after init
    pki.set_verbosity(mainVerbosity)

    cn = 'PyKIflask'
    passwd = getPass(name=cn, pki=pki)
    if not passwd:
        print("Unable to find certificate private key passphrase for "+cn)
        exit(1)

    # Remove passphrase from cert
    rmPass(name = cn, pki = pki, passphrase = passwd)
