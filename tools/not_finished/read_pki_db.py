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

    pkidb = pki.pkidbDict

    # for sorting names befor printing datas
    certsname = []
    for certname in pkidb:
        certsname.append(certname)
    # sort list insensitively
    certsname.sort(key=lambda x: x.lower())

    # process name list to print datas
    for name in certsname:
        status = pkidb[name]['state']
        serial = pkidb[name]['serial']
        validity_time = pkidb[name]['duration']
        cert_shasum = pkidb[name]['shasum']
        cert_usage = pkidb[name]['type']
        if cert_usage == 'CLT':
            cert_usage = 'client authentication'
        elif cert_usage == "SRV":
            cert_usage = 'server authentication'
        cert_encrytion = pkidb[name]['shaenc']
        creation_date = pkidb[name]['created']

        print(
              'Certificate name: ' +name+ '\n',
              '\tCertificate state: ' +status+ '\n',
              '\tCertificate serial number: ', serial, '\n',
              '\tCertificate creation date: ' +creation_date+ '\n',
              '\tDays of validity after creation: ', validity_time, '\n',
              '\tCertificate sha sum: ' +cert_shasum+ '\n',
              '\tCertificate usage type: ' +cert_usage+ '\n',
              '\tCertificate encrytpion level: ' +cert_encrytion
        )
