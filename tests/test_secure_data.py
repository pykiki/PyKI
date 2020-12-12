#!/usr/bin/env python3
# coding: utf-8

from Crypto.Hash import SHA256
from Crypto import Random
from Crypto.Cipher import AES

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


def encryptData(key, data):
    """ Encrypts a file using AES (CBC mode) with the
        given key.

        key:
            The encryption key - a string that must be
            either 16, 24 or 32 bytes long. Longer keys
            are more secure.

        data:
            data to encrypt
    """

    ''' with CBC
    # generating random entropy for Initialization Vector
    iv = Random.new().read(AES.block_size)
    # converting passkey to a 32 bytes len str
    key = SHA256.new(key.encode('utf-8')).digest()

    encryptor = AES.new(key, AES.MODE_CBC, iv)

    data = data.encode('utf-8')
    if len(data) % 16 != 0:
        dataTmp = ' ' * (16 - len(data) % 16)
        data += dataTmp.encode('utf-8')

    data = iv + encryptor.encrypt(data)
    return(data)
    '''

    # converting passkey to a 32 bytes len str
    key = SHA256.new(key.encode('utf-8')).digest()
    # generating random entropy for Initialization Vector
    iv = Random.new().read(AES.block_size)

    cipher = AES.new(key, AES.MODE_CFB, iv)
    encdata = (iv + cipher.encrypt(data))
    return(encdata)


def decryptData(key, encdata):
    """ Decrypts a file using AES (CBC mode) with the
        given key. Parameters are similar to encrypt_file
    """

    ''' with CBC
    # converting passkey to a 32 bytes len str
    key = SHA256.new(key.encode('utf-8')).digest()
    iv = encdata[:16]
    decryptor = AES.new(key, AES.MODE_CBC, iv)
    data = decryptor.decrypt(encdata[16:])
    return(data)
    '''

    # converting passkey to a 32 bytes len str
    key = SHA256.new(key.encode('utf-8')).digest()
    iv = encdata[:16]
    cipher = AES.new(key, AES.MODE_CFB, iv)
    data = cipher.decrypt(encdata[16:])
    return(data)

if __name__ == '__main__':
    password = 'azerty'

    # decrypt string content
    encDatas = encryptData(password, 'azerty cool :)')
    print(
        decryptData(password, encDatas)
    )

    # decrypt a file content
    ofile = open('./toto.txt.enc', 'rb')
    encdatafile = ofile.read()
    ofile.close()
    datafile = decryptData(password, encdatafile)
    print(str(datafile[8:]).replace('\\n', '\n'))
