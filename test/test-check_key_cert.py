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
from os import path

certPath = "/Users/albookpro/Downloads/pyTLSpki/building/pki/CERTS/clients/newcsr/newcsr.crt"
keyPath = "/Users/albookpro/Downloads/pyTLSpki/building/pki/CERTS/clients/newcsr/newcsr.key"

def check_cer_vs_key(cert, key, keypass = False):
    if not path.exists(cert): 
        print("Error, unable to find "+cert+"\n")
        exit(1)
    elif not path.exists(key):
        print("Error, unable to find "+key+"\n")
        exit(1)

    if not keypass:
        keyObj = crypto.load_privatekey(crypto.FILETYPE_PEM, open(key).read())
    else:
        keyObj = crypto.load_privatekey(crypto.FILETYPE_PEM, open(key).read(), keypass)

    certObj = crypto.load_certificate(crypto.FILETYPE_PEM, open(cert).read())

    ctx = SSL.Context(SSL.TLSv1_METHOD)
    ctx.use_privatekey(keyObj)
    ctx.use_certificate(certObj)

    try:
      ctx.check_privatekey()
    except SSL.Error:
      print("Incorrect key.\n")
    else:
      print("Key matches certificate.\n")

# interactive mode
#check_cer_vs_key(certPath, keyPath)
check_cer_vs_key(certPath, keyPath, b'azerty')
