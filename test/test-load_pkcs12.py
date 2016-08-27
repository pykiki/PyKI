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

from OpenSSL import crypto, SSL

filePath = "/Users/albookpro/Downloads/pyTLSpki/building/pki/CERTS/clients/clientPKCS.p12"

#passphrase = False
passphrase = b'azerty'

if passphrase :
    #try:
    bufferObj = open(filePath).read(2)
#    pkcs12object = crypto.load_pkcs12(bufferObj, passphrase)
    #except:
    #    print("Error opening pkcs12 file\n")
    #    exit(1)
else:
    # if the key is passphrase protected, you will be interactively prompt for it
    try:
        pkcs12object = crypto.load_pkcs12(
            open(filePath).read())
    except:
        print("Error opening pkcs12 file\n")
        exit(1)

# you have now your OpenSSL.crypto.PKey object
print(pkcs12object)
