#!/usr/bin/env python3
# coding: utf-8

from os import path as ospath, makedirs, remove
from Crypto.PublicKey import RSA
from Crypto import Random

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


def create_dir(pathDir, mode):
    if not ospath.exists(pathDir):
        try:
            makedirs(pathDir, mode)
        except OSError as exception:
            if exception.errno != errno.EEXIST:
                res = {"error": True, "message": "ERROR: " + exception}
                return(res)

        res = {
            "error": False,
            "message": "INFO: Missing directory " +
            pathDir +
            " created"}
        return(res)
    else:
        res = {
            "error": False,
            "message": "WARN: Directory " +
            pathDir +
            " already exists"}
        return(res)


def writeKey(wFile, wContent):
    try:
        file = open(wFile, "wb")
    except IOError:
        res = {
            "error": True,
            "message": "ERROR: Unable to open file " +
            str(wFile)}
        return(res)
    finally:
        try:
            file.write(wContent)
        except IOError:
            res = {
                "error": True,
                "message": 'ERROR: Unable to write to file ' +
                wFile}
            return(res)
        finally:
            file.close()
            res = {
                "error": False,
                "message": 'INFO: File ' +
                wFile +
                ' written'}
            return(res)


def genKey(keypass, keylen, keydir):
    '''
        gen public/private key pair
    '''

    random_generator = Random.new().read
    key = RSA.generate(keylen, random_generator)
    encrypted_key = key.exportKey(format='PEM', passphrase=keypass, pkcs=8)
    public_key = key.publickey().exportKey()

    if keydir[-1] != '/':
        keydir = keydir + "/"

    cdres = create_dir(keydir, 0o750)
    if cdres['error']:
        res = {"error": True, "message": 'ERROR: ' + cdres['message']}
        return(res)

    wpures = writeKey(keydir + "public_key.pem", public_key)
    if wpures['error']:
        res = {"error": True, "message": 'ERROR: ' + wpures['message']}
        return(res)

    # return private key to user and delete it from the pki filesystem
    wpres = writeKey(keydir + "private_key.pem", encrypted_key)
    if wpres['error']:
        res = {"error": True, "message": 'ERROR: ' + wpres['message']}
        return(res)
    try:
        with open(keydir + "private_key.pem", "rt") as pkey:
            res = {
                "error": False,
                "message": 'INFO: Please keep this private key carefully, this will allow you to init the pki:\n' +
                pkey.read()}
            pkey.close()
    except FileNotFoundError as e:
        res = {
            "error": True,
            "message": 'ERROR: Fichier ' +
            keydir +
            "private_key.pem not found."}
    finally:
        remove(keydir + "private_key.pem")
    return(res)


def authBykey(pubkeydir, privkeyString, passph):
    # encrypt with pubkey
    if pubkeydir[-1] != '/':
        pubkeydir = pubkeydir + "/"

    try:
        pkey = open(pubkeydir + "public_key.pem", "rt")
        public_key = RSA.importKey(pkey.read())
        pkey.close()
    except FileNotFoundError as e:
        res = {"error": True, "message": 'ERROR: Public key not found.'}
        return(res)
    except:
        res = {"error": True, "message": 'ERROR: Problem reading public key'}
        return(res)

    randomData = Random.get_random_bytes(32)
    enc_data = public_key.encrypt(b'success', randomData)

    # decrypt with private key
    private_key = RSA.importKey(privkeyString, passph)
    dec_data = private_key.decrypt(enc_data)
    if dec_data == b'success':
        # self.__token = SHA256.new(private_key.exportKey()).digest()
        res = {"error": False, "message": "INFO: Successfully authenticated"}
        return(res)
    else:
        res = {"error": True, "message": 'ERROR: Unable to authenticate'}
        return(res)

if __name__ == '__main__':
    verbose = True

    # gen key priv and pub key pair
    '''
    keylen = 1024
    code = 'azerty'
    gres = genKey(keypass = code, keylen = keylen, keydir = "./temp")
    if gres['error']:
        print(gres['message'])
        exit(1)
    else:
        if verbose:
            print(gres['message'])
    '''

    # try to authenticate with private key
    # passphrase of the private key
    mdp = 'azerty'
    # private key it self
    privkey = open("./test.pem", 'rt')
    privkeyStr = privkey.read()
    privkey.close()

    # sending authentication try
    resauth = authBykey(
        pubkeydir="./temp",
        privkeyString=privkeyStr,
        passph=mdp)
    if resauth['error']:
        print(resauth['message'])
    else:
        if verbose:
            print(resauth['message'])
