#!/usr/bin/env python3
# -*- coding: UTF-8 -*-

from OpenSSL import crypto

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

    Contact: alain.maibach@gmail.com / 34 rue appienne 13480 - FRANCE.
'''

filePath = "/Users/albookpro/Downloads/pyTLSpki/building/pki/CERTS/clients/clientKey.pem"

#passphrase = False
passphrase = b'azerty'

if passphrase:
    try:
        sslkeyObject = crypto.load_privatekey(
            crypto.FILETYPE_PEM, open(filePath).read(), passphrase)
    except:
        print("Error reading key\n")
        exit(1)
else:
    # if the key is passphrase protected, you will be interactively prompt for
    # it
    try:
        sslkeyObject = crypto.load_privatekey(
            crypto.FILETYPE_PEM, open(filePath).read())
    except:
        print("Error reading key\n")
        exit(1)

# you have now your OpenSSL.crypto.PKey object
print(sslkeyObject)
