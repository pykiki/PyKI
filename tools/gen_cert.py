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
import random, string

curScriptDir = ospath.dirname(ospath.abspath(__file__))

def codegenerator(pwlen = 25, alphabet = False):
    if not alphabet:
        #alphabet = string.printable
        alphabet = string.digits + string.ascii_letters + string.punctuation

    pw_length = pwlen
    mypw = ""

    for i in range(pw_length):
        next_index = random.randrange(len(alphabet))
        mypw = mypw + alphabet[next_index]
    return mypw

def genCert(name, pki, passphrase, usage, altnames = False, size = False, certenc = False, days = False):
    '''
    tools Generatin key and certificate
    '''

    print("INFO: Generating server private key for "+name+"...")
    key = pki.create_key(passphrase=passphrase, keysize = size, name = name, usage = usage)
    if key['error'] :
        print("ERROR: Unable to generate key "+name+" properly: "+key['message']+", aborting...")
        return(False)
    else:
        print("INFO: Key "+name+" done.")

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
        print(cert['message']+", aborting...")
        res=False
    else:
        print(cert['message'])
        res=True

    return(res)

if __name__ == '__main__':
    mainVerbosity = False
    passwd = None
    subjectAltName = None

    # passphrase of the private key requested for pki authentication
    privateKeyPassphrase = getpass('PKI Authentication private key password: ')

    # pki authentication private key path
    pkeyPath = "./pki_auth_cert.pem"
    pkey = open(pkeyPath ,'rt')
    pkeyStr = pkey.read()
    pkey.close()

    # Init with privkey loaded from file
    pki = PyKI(authKeypass=privateKeyPassphrase, privkeyStr=pkeyStr)
    # Set pki verbosity after init
    pki.set_verbosity(mainVerbosity)

    #purpose = 'server'
    #cn = "PyKIflask"
    # Options are 'email', 'URI', 'IP', 'DNS'
    #subjectAltName = ['DNS:MBP.local', 'DNS:mbp.local.net', 'IP:172.17.22.35', 'IP:127.0.0.1', 'DNS:localhost']
    #subjectAltName = ['DNS:'+cn, 'DNS:localhost', 'URI:172.17.22.35']

    purpose = 'client'
    cn = 'client_vpnKimsufi'
    #passwd = 'azerty'

    if not passwd:
        passwd = codegenerator(pwlen = 26)

    if purpose == "server":
        duration = 730
        genCert(name = cn, pki = pki, passphrase = passwd, altnames = subjectAltName, size = 8192, usage = 'serverAuth' , days = duration)
    else:
        duration = 365
        genCert(name=cn, pki=pki, passphrase=passwd, size=4096, usage='clientAuth', days=duration)
