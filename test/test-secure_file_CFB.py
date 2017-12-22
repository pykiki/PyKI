#!/usr/bin/env python3
# coding: utf-8

from os import path as ospath, walk, getcwd, remove
import struct
from sys import argv as sysargv
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

# alternativ :
#              https://pypi.python.org/pypi/cryptoshop
#              https://stevenwooding.com/python-example-encryption-using-aes-in-counter-mode/


def encryptFile(key, in_filename, out_filename=None, chunksize=64 * 1024):
    """ Encrypts a file using AES (CFB mode) with the
        given key.

        key:
            The encryption key - a string that must be
            either 16, 24 or 32 bytes long. Longer keys
            are more secure.

        in_filename:
            Name of the input file

        out_filename:
            If None, '<in_filename>.enc' will be used.

        chunksize:
            Sets the size of the chunk which the function
            uses to read and encrypt the file. Larger chunk
            sizes can be faster for some files and machines.
            chunksize must be divisible by 16.
    """
    if not out_filename:
        out_filename = in_filename + '.enc'

    # generating random entropy for Initialization Vector
    iv = Random.new().read(AES.block_size)
    # converting passkey to a 32 bytes len str
    key = SHA256.new(key.encode('utf-8')).digest()

    encryptor = AES.new(key, AES.MODE_CFB, iv)
    filesize = ospath.getsize(in_filename)

    with open(in_filename, 'rb') as infile:
        with open(out_filename, 'wb') as outfile:
            outfile.write(struct.pack('<Q', filesize))
            outfile.write(iv)

            while True:
                chunk = infile.read(chunksize)
                if len(chunk) == 0:
                    break

                outfile.write(encryptor.encrypt(chunk))


def decryptFile(key, in_filename, out_filename=None, chunksize=24 * 1024):
    """ Decrypts a file using AES (CFB mode) with the
        given key. Parameters are similar to encrypt_file,
        with one difference: out_filename, if not supplied
        will be in_filename without its last extension
        (i.e. if in_filename is 'aaa.zip.enc' then
        out_filename will be 'aaa.zip')
    """
    if not out_filename:
        out_filename = ospath.splitext(in_filename)[0]

    # converting passkey to a 32 bytes len str
    key = SHA256.new(key.encode('utf-8')).digest()

    with open(in_filename, 'rb') as infile:
        origsize = struct.unpack('<Q', infile.read(struct.calcsize('Q')))[0]
        iv = infile.read(16)

        decryptor = AES.new(key, AES.MODE_CFB, iv)

        with open(out_filename, 'wb') as outfile:
            while True:
                chunk = infile.read(chunksize)
                if len(chunk) == 0:
                    break
                outfile.write(decryptor.decrypt(chunk))

            outfile.truncate(origsize)


def getFiles(path):
    if not ospath.exists(path):
        res = {'error': True, 'message': 'ERROR: path ' + path + ' not found'}
        return(res)

    allFiles = []

    if ospath.isdir(path):
        for root, subfiles, files in walk(path):
            for names in files:
                allFiles.append(ospath.join(root, names))
    else:
        allFiles.append(path)

    res = {'error': False, 'message': allFiles}
    return(res)

if __name__ == '__main__':
    choice = input("Do you want to (E)ncrypt or (D)ecrypt? ")

    if choice == "E":
        filepath = input(
            "Enter the filename or dirname containing files to encrypt: ")

        encFiles = getFiles(filepath)
        if not encFiles['error']:
            encFiles = encFiles['message']
        else:
            print(encFiles['message'])
            exit(1)

        password = input("Enter password for encrypting file(s): ")

        for Tfiles in encFiles:
            extension = ospath.splitext(Tfiles)[1][1:]
            if extension == "enc":
                print("%s is already encrypted" % str(Tfiles))

            elif Tfiles == ospath.join(getcwd(), sysargv[0]):
                pass
            else:
                encryptFile(password, str(Tfiles))
                print("Done encrypting %s" % str(Tfiles))
                remove(Tfiles)

    elif choice == "D":
        filepath = input(
            "Enter the filename or dirname containing files to decrypt: ")
        encFiles = getFiles(filepath)
        if not encFiles['error']:
            encFiles = encFiles['message']
        else:
            print(encFiles['message'])
            exit(1)

        password = input("Enter password for decrypting file(s): ")

        for Tfiles in encFiles:
            extension = ospath.splitext(Tfiles)[1][1:]
            if extension != "enc":
                print("%s is not encrypted" % Tfiles)
            else:
                decryptFile(password, Tfiles)
                print("Done decrypting %s" % Tfiles)
                remove(Tfiles)
    else:
        print("Please choose a valid command.")
        exit(1)
