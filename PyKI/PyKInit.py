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

    Contact: alain.maibach@gmail.com / 34 rue appienne 13480 - FRANCE.
'''

import configparser
import getpass
import email.utils
import signal
import os
from PyKI import PyKIcore


class PyKIsetup():
    '''
        Init module to help using PyKIcore library
    '''

    cwd = os.getcwd()

    def __init__(self, configFile=str(cwd) + '/config.ini'):
        '''
        Init the PyKI easyly, using ini config file.

        :param configFile: Ini config file containing pki parameters.
        :type configFile: String.

        :returns: Informational result dict {'error': Boolean, 'message': String}
        :rtype: PyKI class object.
        '''

        # calling signal handler
        signal.signal(signal.SIGINT, self.sigint_handler)

        self.__config = configFile
        self.__pki = False

        # Creating default setup if it does not exists
        if not os.path.exists(self.__config):
            print(self.__config)
            createRes = self.__createConf()
            if createRes['error']:
                print(createRes['message'])
                exit(1)
            print("INFO: Default configuration done! Please edit " +
                  self.__config + " before launching init again")
            exit(0)

        # Get param from config file .ini
        config = configparser.ConfigParser()
        try:
            config.read(self.__config)
        except ConfigParser.ParsingError as e:
            print(e)
            exit(1)
        except ConfigParser.Error as e:
            print(e)
            exit(1)

        config.sections()

        if 'pki auth' not in config:
            print(
                'ERROR: Missing "pki auth" section in your configuration file: ' +
                self.__config)
            exit(1)
        if 'pki params' not in config:
            print(
                'ERROR: Missing "pki params" section in your configuration file: ' +
                self.__config)
            exit(1)
        if 'DEFAULT' not in config:
            print(
                'ERROR: Missing "DEFAULT" section in your configuration file: ' +
                self.__config)
            exit(1)

        intVal = [1024, 2048, 4096, 8192]
        certAlgo = ['sha1', 'sha256', 'sha512']
        keyCipher = [
            'des',
            'des3',
            'seed',
            'aes128',
            'aes192',
            'aes256',
            'camellia128',
            'camellia192',
            'camellia256']
        crlAlgo = [
            'md2',
            'md5',
            'mdc2',
            'rmd160',
            'sha',
            'sha1',
            'sha224',
            'sha256',
            'sha384',
            'sha512']

        # get verbosity level
        # check if in, ignoring case
        mainVerbosity = config.getboolean('DEFAULT', 'verbose')

        pkiAuthpK = config['pki auth']['private key']

        pkiAuthKlen = config.getint('pki auth', 'key length')
        if pkiAuthKlen not in intVal:
            print('ERROR: Please choose a value in range ' +
                  str(intVal) + ' for the pki auth key length item')
            exit(1)

        try:
            AuthPkPass = config.get('pki auth', 'passphrase')
        except ConfigParser.NoOptionError:
            AuthPkPass = getpass.getpass(
                'Give the PKI Authentication private key password: ')
        else:
            if AuthPkPass == '' or AuthPkPass == ' ':
                AuthPkPass = getpass.getpass(
                    'Give the PKI Authentication private key password: ')

        if AuthPkPass == '' or AuthPkPass == ' ' or AuthPkPass is None or not AuthPkPass:
            print('ERROR: You must give the pki authentication password')
            exit(1)

        issuer = config['pki params']['issuer'].strip().replace(" ", "_")
        C = config['pki params']['c'].strip()
        ST = config['pki params']['st'].strip()
        L = config['pki params']['l'].strip()
        O = config['pki params']['o'].strip()
        OU = config['pki params']['ou'].strip()

        email_param = config['pki params']['email']
        if '@' not in email.utils.parseaddr(
                email_param)[1] or email.utils.parseaddr(email_param)[1] == '':
            print('ERROR: Invalid e-mail address format')
            exit(1)

        default_pkeySize = config.getint('pki params', 'private key size')
        if default_pkeySize not in intVal:
            print(
                'ERROR: Please choose a value in range ' +
                str(intVal) +
                ' for the pki params private key size item')
            exit(1)

        default_certEncrypt = config['pki params'][
            'certificate encryption'].lower()
        if default_certEncrypt not in certAlgo:
            print('ERROR: Please choose a value in range ' + str(certAlgo) +
                  ' for the pki params certificate encryption item')
            exit(1)

        default_pkeyCipher = config['pki params']['private key cipher'].lower()
        if default_pkeyCipher not in keyCipher:
            print(
                'ERROR: Please choose a value in range ' +
                str(keyCipher) +
                ' for the pki params private key cipher item')
            exit(1)

        crlEncrypt = config['pki params']['crl encryption'].lower()
        if crlEncrypt not in crlAlgo:
            print(
                'ERROR: Please choose a value in range ' +
                str(crlAlgo) +
                ' for the pki params crl encryption item')
            exit(1)

        # first init, creating private key
        if not os.path.exists(pkiAuthpK):
            print(
                "\n!!!!! INFO: The auth private key will be saved in " +
                pkiAuthpK +
                " !!!!!\n")
            self.__pki = PyKIcore.PyKI(
                issuerName=issuer,
                authKeypass=AuthPkPass,
                C=C,
                ST=ST,
                L=L,
                O=O,
                OU=OU,
                adminEmail=email_param,
                verbose=mainVerbosity,
                KEY_SIZE=default_pkeySize,
                SIGN_ALGO=default_certEncrypt,
                KEY_CIPHER=default_pkeyCipher,
                CRL_ALGO=crlEncrypt,
                authKeylen=pkiAuthKlen)

            # get private key for authentication after first init
            authprivkey = self.__pki.initPkey
            # writing key to file
            try:
                wfile = open(pkiAuthpK, "wt")
            except IOError:
                print('ERROR: unable to open file ' + pkiAuthpK)
                exit(1)
            else:
                try:
                    wfile.write(authprivkey)
                except IOError:
                    print('ERROR: Unable to write to file ' + pkiAuthpK)
                    exit(1)
                else:
                    if mainVerbosity:
                        print('INFO: File ' + pkiAuthpK + ' written')
            finally:
                wfile.close()
                authprivkey = None

        # Init with privkey loaded from file
        pkey = open(pkiAuthpK, 'rt')
        pkeyStr = pkey.read()
        pkey.close()

        self.__pki = PyKIcore.PyKI(
            issuerName=issuer,
            authKeypass=AuthPkPass,
            C=C,
            ST=ST,
            L=L,
            O=O,
            OU=OU,
            adminEmail=email_param,
            verbose=mainVerbosity,
            KEY_SIZE=default_pkeySize,
            SIGN_ALGO=default_certEncrypt,
            KEY_CIPHER=default_pkeyCipher,
            CRL_ALGO=crlEncrypt,
            authKeylen=pkiAuthKlen,
            privkeyStr=pkeyStr)

    def sigint_handler(self, signum, frame):
        '''
        Class sig handler for ctrl+c interrupt
        '''

        if self.__verbose:
            print('\nINFO: Execution interrupted by pressing [CTRL+C]')

        exit(0)

    def __createConf(self):
        '''
        Creates default ini config file for PyKI init. This implementation is used to
        make it more easier to load the pki throught the tool set.

        :returns: Informational result dict {'error': Boolean, 'message': String}
        :rtype: Dict.
        '''
        action = False
        config = configparser.ConfigParser(
            delimiters=':', comment_prefixes='#')

        # No need to create this section
        # config.add_section('DEFAULT')
        config.set('DEFAULT', 'verbose', 'False')

        try:
            config.add_section('pki auth')
        except ConfigParser.DuplicateSectionError:
            print("INFO: Section 'pki auth' already exist, nothing to do.")
        else:
            action = True
            config.set('pki auth', 'private key', './pki_auth.pem')
            config.set('pki auth', 'key length', '8192')
            config.set('pki auth', 'passphrase', '')

        try:
            config.add_section('pki params')
        except ConfigParser.DuplicateSectionError:
            print("INFO: Section 'pki params' already exist, nothing to do.")
        else:
            action = True
            config.set('pki params', 'c', 'Country Name (2 letter code)')
            config.set(
                'pki params',
                'st',
                'State or Province Name (full name)')
            config.set('pki params', 'l', 'Locality Name (eg, city)')
            config.set('pki params', 'o', 'Organization Name (eg, company)')
            config.set(
                'pki params',
                'ou',
                'Organizational Unit Name (eg, section)')
            config.set('pki params', 'email', 'Email Address')
            config.set(
                'pki params',
                'issuer',
                'CA name which will appear in issuer string')
            config.set('pki params', 'private key size', '4096')
            config.set('pki params', 'certificate encryption', 'sha512')
            config.set('pki params', 'private key cipher', 'des3')
            config.set('pki params', 'crl encryption', 'sha256')

        if not action:
            res = {
                "error": False,
                "message": "INFO: Nothing to do for " +
                str(self.__config) +
                ".\nIf your sections are empty, please remove your config file and launch me again."}
            return(res)
        else:
            try:
                wfile = open(self.__config, 'wt')
            except IOError:
                res = {
                    "error": True,
                    "message": "ERROR: Unable to open file " +
                    str(self.__config)}
                return(res)
            else:
                try:
                    config.write(wfile)
                except IOError:
                    res = {
                        "error": True,
                        "message": "ERROR: Unable to open file " +
                        str(wfile)}
                    return(res)
            wfile.close()

            res = {
                "error": False,
                "message": "INFO: Config file " +
                str(wfile) +
                " written"}
            return(res)

    def __del__(self):
        pass

    def get_pkiObj(self):
        return(self.__pki)

    pki = property(
        get_pkiObj,
        None,
        None,
        "Get the PyKI object")


if __name__ == '__main__':
    curScriptDir = os.path.dirname(os.path.abspath(__file__))
    pyki = PyKInit(curScriptDir + '/../tools/PyKItools/config/config.ini')
    if not pyki.pki:
        print("ERROR: Errors found during init")
        exit(1)
    else:
        print(pyki.pki.nameList)
        del(pyki)
        exit(0)
