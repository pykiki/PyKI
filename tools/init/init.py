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

import random, string
import configparser
from getpass import getpass
from PyKI import PyKI
from email.utils import parseaddr

from os import path as ospath
curScriptDir = ospath.dirname(ospath.abspath(__file__))

def createConf(configFile):
    '''
    Creates default ini config file.

    :param configFile: Ini config file containing pki parameters.
    :type configFile: String.

    :returns: Informational result dict {'error': Boolean, 'message': String}
    :rtype: Dict.
    '''
    action=False
    config = configparser.ConfigParser(delimiters=':', comment_prefixes='#')

    # No need to create this section
    #config.add_section('DEFAULT')
    config.set('DEFAULT', 'verbose', 'False')

    try:
        config.add_section('pki auth')
    except ConfigParser.DuplicateSectionError:
        print("INFO: Section 'pki auth' already exist, nothing to do.")
    else:
        action=True
        config.set('pki auth', 'private key', './pki_auth.pem')
        config.set('pki auth', 'key length', '8192')
        config.set('pki auth', 'passphrase', '')

    try:
        config.add_section('pki params')
    except ConfigParser.DuplicateSectionError:
        print("INFO: Section 'pki params' already exist, nothing to do.")
    else:
        action=True
        config.set('pki params','c','Country Name (2 letter code)')
        config.set('pki params','st','State or Province Name (full name)')
        config.set('pki params','l','Locality Name (eg, city)')
        config.set('pki params','o','Organization Name (eg, company)')
        config.set('pki params','ou','Organizational Unit Name (eg, section)')
        config.set('pki params','email','Email Address')
        config.set('pki params','issuer','CA name which will appear in issuer string')
        config.set('pki params','private key size','4096')
        config.set('pki params','certificate encryption','sha512')
        config.set('pki params','private key cipher','des3')
        config.set('pki params','crl encryption','sha256')

    if not action:
        res = {"error":False, "message":"INFO: Nothing to do for " + str(wfile) + ".\nIf your sections are empty, please remove your config file and launch me again."}
        return(res)
    else:
        try:
            wfile = open(configFile, 'wt')
        except IOError:
            res = {"error":True, "message":"ERROR: Unable to open file " + str(wfile)}
            return(res)
        else:
            try:
                config.write(wfile)
            except IOError:
                res = {"error":True, "message":"ERROR: Unable to open file " + str(wfile)}
                return(res)
        finally:
            wfile.close()

        res = {"error":False, "message":"INFO: Config file " + str(wfile) + " written"}
        return(res)

def pkinit(configFile=str(curScriptDir)+'/config.ini'):
    '''
    Init the PyKI easyly, using ini config file.

    :param configFile: Ini config file containing pki parameters.
    :type configFile: String.

    :returns: Informational result dict {'error': Boolean, 'message': String}
    :rtype: PyKI class object.
    '''
    # Creating default setup if it does not exists
    if not ospath.exists(configFile):
        createRes = createConf(configFile)
        if createRes['error']:
            print(createRes['message'])
            return(False)
        print("INFO: Default configuration done! Please edit "+configFile+" before launching init again")
        exit(0)

    # Get param from config file .ini
    config = configparser.ConfigParser()
    try:
        config.read(configFile)
    except ConfigParser.ParsingError as e:
        print(e)
        return(False)
    except ConfigParser.Error as e:
        print(e)
        return(False)

    config.sections()

    if not 'pki auth' in config :
        print('ERROR: Missing "pki auth" section in your configuration file: '+configFile)
        return(False)
    if not 'pki params' in config:
        print('ERROR: Missing "pki params" section in your configuration file: '+configFile)
        return(False)
    if not 'DEFAULT' in config:
        print('ERROR: Missing "DEFAULT" section in your configuration file: '+configFile)
        return(False)

    intVal=[1024,2048,4096,8192]
    certAlgo=['sha1','sha256','sha512']
    keyCipher=['des','des3','seed','aes128','aes192','aes256','camellia128','camellia192','camellia256']
    crlAlgo=['md2','md5','mdc2','rmd160','sha','sha1','sha224','sha256','sha384','sha512']

    # get verbosity level
    # check if in, ignoring case
    mainVerbosity=config.getboolean('DEFAULT','verbose')

    pkiAuthpK=config['pki auth']['private key']

    pkiAuthKlen=config.getint('pki auth', 'key length')
    if pkiAuthKlen not in intVal:
        print('ERROR: Please choose a value in range '+str(intVal)+' for the pki auth key length item')
        return(False)

    try:
        AuthPkPass=config.get('pki auth', 'passphrase')
    except ConfigParser.NoOptionError:
        AuthPkPass = getpass('Give the PKI Authentication private key password: ')
    else:
        if AuthPkPass == '' or AuthPkPass == ' ':
            AuthPkPass = getpass('Give the PKI Authentication private key password: ')

    if AuthPkPass == '' or AuthPkPass == ' ' or AuthPkPass is None or not AuthPkPass:
        print('ERROR: You must give the pki authentication password')
        return(False)

    issuer=config['pki params']['issuer'].strip().replace(" ","_")
    C=config['pki params']['c'].strip()
    ST=config['pki params']['st'].strip()
    L=config['pki params']['l'].strip()
    O=config['pki params']['o'].strip()
    OU=config['pki params']['ou'].strip()
    
    email=config['pki params']['email']
    if not '@' in parseaddr(email)[1] or parseaddr(email)[1] == '':
        print('ERROR: Invalid e-mail address format')
        return(False)

    default_pkeySize=config.getint('pki params', 'private key size')
    if default_pkeySize not in intVal:
        print('ERROR: Please choose a value in range '+str(intVal)+' for the pki params private key size item')
        return(False)
        
    default_certEncrypt=config['pki params']['certificate encryption'].lower()
    if not default_certEncrypt in certAlgo:
        print('ERROR: Please choose a value in range '+str(certAlgo)+' for the pki params certificate encryption item')
        return(False)
        
    default_pkeyCipher=config['pki params']['private key cipher'].lower()
    if not default_pkeyCipher in keyCipher:
        print('ERROR: Please choose a value in range '+str(keyCipher)+' for the pki params private key cipher item')
        return(False)

    crlEncrypt=config['pki params']['crl encryption'].lower()
    if not crlEncrypt in crlAlgo:
        print('ERROR: Please choose a value in range '+str(crlAlgo)+' for the pki params crl encryption item')
        return(False)

    # first init, creating private key
    if not ospath.exists(pkiAuthpK):
        print("\n!!!!! INFO: The auth private key will be saved in "+pkiAuthpK+" !!!!!\n")
        pki = PyKI(issuerName=issuer, authKeypass=AuthPkPass, C=C, ST=ST, L=L, O=O, OU=OU, adminEmail=email, verbose=mainVerbosity, KEY_SIZE=default_pkeySize, SIGN_ALGO=default_certEncrypt, KEY_CIPHER=default_pkeyCipher, CRL_ALGO=crlEncrypt, authKeylen=pkiAuthKlen)

        # get private key for authentication after first init
        authprivkey = pki.initPkey
        # writing key to file
        try:
            wfile = open(pkiAuthpK, "wt")
        except IOError:
            print('ERROR: unable to open file '+pkiAuthpK)
            return(False)
        else:
            try:
                wfile.write(authprivkey)
            except IOError:
                print('ERROR: Unable to write to file '+pkiAuthpK)
                return(False)
            else:
                if mainVerbosity:
                    print('INFO: File ' + pkiAuthpK + ' written')
        finally:
            wfile.close()
            authprivkey = None

    # Init with privkey loaded from file
    pkey = open(pkiAuthpK ,'rt')
    pkeyStr = pkey.read()
    pkey.close()

    pki = PyKI(issuerName=issuer, authKeypass=AuthPkPass, C=C, ST=ST, L=L, O=O, OU=OU, adminEmail=email, verbose=mainVerbosity, KEY_SIZE=default_pkeySize, SIGN_ALGO=default_certEncrypt, KEY_CIPHER=default_pkeyCipher, CRL_ALGO=crlEncrypt, authKeylen=pkiAuthKlen, privkeyStr=pkeyStr)
    
    return(pki)

if __name__ == '__main__':
    pki=pkinit()
    if not pki:
        print("ERROR: Errors found during init")
        exit(1)
    else:
        print(pki.nameList)
        exit(0)
