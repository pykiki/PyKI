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

from OpenSSL import crypto, SSL
from OpenSSL._util import lib as cryptolib
from Crypto.PublicKey import RSA
from Crypto import Random
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from datetime import datetime
from os import makedirs
from os import path as ospath
from os import remove
from os import rmdir
from os import walk as oswalk
#from sys import version_info
import sys
from json import load as jsonLoad, loads as jsonLoadstr, dumps as jsonDump
from random import randrange
import errno
from re import sub as resub, search as research, match as rematch
from unicodedata import normalize as uninormalize
import hashlib
import pytz
import struct
import signal


class PyKI():
    '''
    Main class to instanciate which will load the pki and it's management functions
    All certificates and private keys including crl will be encoded into PEM format and will be encrypted in RSA
    '''

    def __init__(
            self,
            issuerName=None,
            authKeypass=False,
            privkeyStr=False,
            C='FR',
            ST='ALPES MARITIMES',
            L='Antibes',
            O='MAIBACH Corp.',
            OU='IT Department',
            adminEmail='alain.maibach@gmail.com',
            verbose=False,
            KEY_SIZE=8192,
            SIGN_ALGO='SHA512',
            KEY_CIPHER='DES3',
            CRL_ALGO='sha256',
            authKeylen=8192):
        '''
        Init the pki:
            - Initiating global default pki values
            - Constructing pki filesystem
            - Generating pki private key authentication
            - Authenticating pki user with private key
            - Generating CA and intermediate certificates
            - Loading CA and intermediate certificates
            - Checking pki integrity.

        :param verbose: Define verbosity.
        :type verbose: Boolean.

        :param issuerName: Set the ROOT certificates issuer names. You should use your organization name.
        :type issuerName: String.

        :param authKeypass: Define the pki private key passphrase in order to protect the pki calling.
        :type authKeypass: String.

        :param privkeyStr: Must contain the pki private key file content.
        :type privkeyStr: String.

        :param authKeylen: Define PKI authentication private  key size, must be in [1024, 2048, 4096, 8192].
        :type authKeylen: Int.

        :param C: Define default certificate Country name.
        :type C: String.

        :param ST: Define default certificate State name.
        :type ST: String.

        :param L: Define default certificate Locality name.
        :type L: String.

        :param O: Define default certificate Organization name.
        :type O: String.

        :param OU: Define default certificate Organiational Unit name.
        :type OU: String.

        :param adminEmail: Define default certificate administrator e-mail @.
        :type adminEmail: String.

        :param KEY_SIZE: Define default private key size, must be in [1024, 2048, 4096, 8192].
        :type KEY_SIZE: Int.

        :param SIGN_ALGO: Define default certificate encryption (signature algorithm), must be in [SHA1, SHA256, SHA512].
        :type SIGN_ALGO: String.

        :param KEY_CIPHER: Define default rsa private key cipher, must be in [
                                                                             des         (encrypt the generated key with DES in cbc mode)
                                                                             des3        (encrypt the generated key with DES in ede cbc mode (168 bit key)
                                                                             seed        (encrypt PEM output with cbc seed)
                                                                             aes128, aes192, aes256
                                                                                         (encrypt PEM output with cbc aes)
                                                                             camellia128, camellia192, camellia256
                                                                                         (encrypt PEM output with cbc camellia)
                                                                             ]
        :type KEY_CIPHER: String.

        :param CRL_ALGO: Define CRL message digest, must be in ['MD2','MD5','MDC2','RMD160','SHA','SHA1','SHA224','SHA256','SHA384','SHA512'].
        :type CRL_ALGO: String.
        '''

        # calling signal handler
        signal.signal(signal.SIGINT, self.sigint_handler)

        if not authKeypass:
            print("ERROR: You must give a passphrase for the RSA private key which will be generated for PKI authentication purpose.")
            exit(1)

        self.__alreadyUnlocked = False
        self.__endinit = False
        self.__locked = False
        self.__Ilocked = False
        self.__verbose = verbose
        self.__pkiPath = "/opt/PyKI_data"

        self.__init = False

        # init pki filesystem tree
        self.__rootCAdir = self.__pkiPath + '/CA'
        self.__intermediateCAdir = self.__pkiPath + '/INTERMEDIATE'
        self.__crtsDir = self.__pkiPath + '/CERTS'
        self.__srvCRTdir = self.__crtsDir + '/servers'
        self.__cltCRTdir = self.__crtsDir + '/clients'
        self.__csrDir = self.__crtsDir + '/requests'
        self.__signeDir = self.__crtsDir + '/signed'

        if not ospath.exists(self.__pkiPath):
            if self.__verbose:
                print('INFO: Initialising pki...')

            self.__init = True

            result = self.create_dir(self.__pkiPath, 0o750)
            if not result['error']:
                if result['message']:
                    if self.__verbose:
                        print(result['message'])
            else:
                print(result['message'])
                exit(1)

        # create empty lock file to guarantee usage ownership
        self.__lockfile = self.__pkiPath + '/pki.lock'
        if not ospath.exists(self.__lockfile):
            try:
                open(self.__lockfile, 'a').close()
            except OSError as exception:
                print("ERROR: Unable to lock the pki -->", exception)
                exit(1)
            except:
                print("ERROR: Unhandled error. Unable to lock the pki")
                exit(1)
            else:
                self.__Ilocked = True
                self.__locked = True
        else:
            self.__locked = True
            print("ERROR: Pki locked. Already in use...")
            exit(1)

        # checking filesystem tree
        chkres = self.chk_tree()
        if chkres['error']:
            print(chkres['message'])
            # remove lock file
            self.remove_lockf(
                "INFO: PKI unlocked after detecting bad filesystem tree..")
            exit(1)
        else:
            if self.__verbose:
                print(chkres['message'])

        # creating directories, with octal value for dir mode perm'
        result1 = self.create_dir(self.__rootCAdir, 0o750)
        if not result1['error']:
            if result1['message']:
                if self.__verbose:
                    print(result1['message'])
        else:
            print(result1['message'])
            # remove lock file
            self.remove_lockf(
                "INFO: PKI unlocked after error during creating dir..")
            exit(1)

        result2 = self.create_dir(self.__intermediateCAdir, 0o750)
        if not result2['error']:
            if result2['message']:
                if self.__verbose:
                    print(result2['message'])
        else:
            print(result2['message'])
            # remove lock file
            self.remove_lockf(
                "INFO: PKI unlocked after error during creating dir..")
            exit(1)

        result3 = self.create_dir(self.__crtsDir, 0o750)
        if not result3['error']:
            if result3['message']:
                if self.__verbose:
                    print(result3['message'])
        else:
            print(result3['message'])
            # remove lock file
            self.remove_lockf(
                "INFO: PKI unlocked after error during creating dir..")
            exit(1)

        result4 = self.create_dir(self.__srvCRTdir, 0o750)
        if not result4['error']:
            if result4['message']:
                if self.__verbose:
                    print(result4['message'])
        else:
            print(result4['message'])
            # remove lock file
            self.remove_lockf(
                "INFO: PKI unlocked after error during creating dir..")
            exit(1)

        result5 = self.create_dir(self.__cltCRTdir, 0o750)
        if not result5['error']:
            if result5['message']:
                if self.__verbose:
                    print(result5['message'])
        else:
            print(result5['message'])
            # remove lock file
            self.remove_lockf(
                "INFO: PKI unlocked after error during creating dir..")
            exit(1)

        result6 = self.create_dir(self.__signeDir, 0o750)
        if not result6['error']:
            if result6['message']:
                if self.__verbose:
                    print(result6['message'])
        else:
            print(result6['message'])
            # remove lock file
            self.remove_lockf(
                "INFO: PKI unlocked after error during creating dir..")
            exit(1)

        result7 = self.create_dir(self.__csrDir, 0o750)
        if not result7['error']:
            if result7['message']:
                if self.__verbose:
                    print(result7['message'])
        else:
            print(result7['message'])
            # remove lock file
            self.remove_lockf(
                "INFO: PKI unlocked after error during creating dir..")
            exit(1)

        self.__passdir = self.__pkiPath + '/passphrases'
        self.__pubkeypath = self.__passdir + '/public_key.pem'

        # check if key pair for authentication has already been created
        if privkeyStr and not ospath.exists(self.__pubkeypath):
            print("ERROR: You cannot use a private key at this stage, because the pki has not been already initiated !!")
            # remove lock file
            self.remove_lockf(
                "INFO: PKI unlocked after trying to use a private key before pki init'..")
            exit(1)
        if not ospath.exists(self.__pubkeypath):
            if self.__verbose:
                print("WARN: First use of this pki detected, after generating your private key, you will be asked to recall the pki\nINFO: Generate in progress, please wait...")
            # gen key priv and pub key pair
            gres = self.genKey(keypass=authKeypass, keylen=authKeylen)
            if gres['error']:
                print(gres['message'])
                # remove lock file
                self.remove_lockf(
                    "INFO: PKI unlocked after failing to generate auth key pair..")
                exit(1)
            else:
                self.__initPkey = gres['message']
                if self.__verbose:
                    print(
                        "\nINFO: Please save this private key and callback your script with the private key, now exiting...")

                # remove lock file
                self.remove_lockf("INFO: PKI unlocked after first init..")

                return(None)
                exit(0)
        else:
            if not privkeyStr:
                print(
                    "ERROR: Please give your private key to authenticate before continue...")
                # remove lock file
                self.remove_lockf(
                    "INFO: PKI unlocked after authenticate error..")
                exit(1)

        # sending authentication try
        resauth = self.authBykey(privkeyString=privkeyStr, passph=authKeypass)
        if resauth['error']:
            print(resauth['message'])
            # remove lock file
            self.remove_lockf(
                "INFO: PKI unlocked after error during creating dir..")
            exit(1)
        else:
            if self.__verbose:
                print(resauth['message'])

        # check if authentication has succeed
        if not self.__token:
            print("ERROR: Unable to authenticate, please check your private key")
            # remove lock file
            self.remove_lockf(
                "INFO: PKI unlocked after error during creating dir..")
            exit(1)

        # key encryptions def
        self.__KEY_ALGO = crypto.TYPE_RSA

        # certificate hash encryption for pkidb shasum content
        #       sha1, sha224, sha256, sha384, sha512
        self.__HASH_ENC = 'sha1'

        # default value if you do not specify certificates duration at gen time
        self.__VALID_DAYS = 365 * 1

        self.__KEY_SIZE = KEY_SIZE
        self.__SIGN_ALGO = SIGN_ALGO
        self.__KEY_CIPHER = KEY_CIPHER
        self.__CRL_ALGO = CRL_ALGO

        self.__python3 = sys.version_info.major == 3
        self.__python2 = sys.version_info.major == 2

        self.__C = self.rmSpecialChar(C)
        self.__ST = self.rmSpecialChar(ST)
        self.__L = self.rmSpecialChar(L)
        self.__O = self.rmSpecialChar(O)
        self.__OU = self.rmSpecialChar(OU)
        self.__adminEmail = adminEmail
        # too big dependencie with local resolv which may change over time
        #self.__localCN = gethostname()
        if issuerName:
            self.__localCN = self.rmSpecialChar(issuerName)
        else:
            self.__localCN = "PyKI"

        # after authentication ready, init pki required files
        self.__DBfile = self.__pkiPath + '/pkicert.db'
        self.__passDBfile = self.__passdir + '/pkipass.db'
        self.__rootCAkeyfile = self.__rootCAdir + "/cakey.pem"
        self.__rootCAcrtfile = self.__rootCAdir + "/cacert.pem"
        self.__ca_chain = self.__crtsDir + '/chain_cacert.pem'
        self.__crlpath = self.__intermediateCAdir + "/crl.pem"
        self.__intermediateCAkeyfile = self.__intermediateCAdir + "/intermediate_cakey.pem"
        self.__intermediateCAcrtfile = self.__intermediateCAdir + "/intermediate_cacert.pem"
        self.__cacertname = 'PyKI_CA_root'
        self.__intermediateCertname = 'PyKI_CA_intermediate'

        # loading passDB to get passphrases
        passphrases = self.loadpassDB()
        if passphrases['error']:
            print("ERROR: Unable to retrieve passphrases. Exiting...")
            # remove lock file
            self.remove_lockf(
                "INFO: PKI unlocked after failing to loading passphrases..")
            exit(1)
        else:
            passphrases = passphrases['message']

        # define CA passphrase
        if self.__cacertname not in passphrases:
            pwd = self.genpasswd(pwlen=26)
            pwd = pwd['message']
            reseditdb = self.editpassDB(certname=self.__cacertname, passph=pwd)
            if reseditdb['error']:
                print(
                    'ERROR: Unable to add CA passphrase to DB --> ' +
                    reseditdb['message'])
                # remove lock file
                self.remove_lockf(
                    "INFO: PKI unlocked after failing to define CA passphrase..")
                exit(1)
            else:
                if self.__verbose:
                    print(reseditdb['message'] + " for " + self.__cacertname)
            self.__caPass = pwd.encode('utf-8')
        else:
            self.__caPass = passphrases[self.__cacertname].encode('utf-8')

        # define CA intermediate passphrase
        if self.__intermediateCertname not in passphrases:
            pwd = self.genpasswd(pwlen=26)
            pwd = pwd['message']
            reseditdb = self.editpassDB(
                certname=self.__intermediateCertname, passph=pwd)
            if reseditdb['error']:
                print(
                    'ERROR: Unable to add CA intermediate passphrase to DB --> ' +
                    reseditdb['message'])
                # remove lock file
                self.remove_lockf(
                    "INFO: PKI unlocked after failing to define intermediate CA passphrase..")
                exit(1)
            else:
                if self.__verbose:
                    print(
                        reseditdb['message'] +
                        " for " +
                        self.__intermediateCertname)
            self.__intermediatePass = pwd.encode('utf-8')
        else:
            self.__intermediatePass = passphrases[
                self.__intermediateCertname].encode('utf-8')

        # flushing dictionnary
        passphrases.clear()
        pwd = ''

        if not ospath.isfile(self.__rootCAkeyfile):
            if not self.__init:
                if self.__verbose:
                    print("INFO: Initialising pki...")
                self.__init = True
            if self.__verbose:
                print("INFO: Generating CA root private key...")
            rootcakey = self.create_key(
                passphrase=self.__caPass,
                name=self.__cacertname,
                ca=True)

            if rootcakey['error']:
                #print("ERROR: Unable to generate root CA key properly, aborting...")
                print(rootcakey['message'])
                # remove lock file
                self.remove_lockf(
                    "INFO: PKI unlocked after failing to generate CA key..")
                exit(1)
            else:
                if self.__verbose:
                    print("INFO: Root CA key created.")

        if not ospath.isfile(self.__rootCAcrtfile):
            if ospath.isfile(self.__ca_chain):
                remove(self.__ca_chain)

            if not self.__init:
                if self.__verbose:
                    print("INFO: Initialising pki")
                self.__init = True

            if self.__verbose:
                print("INFO: Generating CA root certificate for 20 years...")
            cacert = self.create_cert(
                cn=self.__cacertname,
                ca=True,
                days_valid=20 * 365
            )
            if cacert['error']:
                #print("ERROR: Unable to generate root CA certificate properly, aborting...")
                print(cacert['message'])
                # remove lock file
                self.remove_lockf(
                    "INFO: PKI unlocked after failing to generate CA cert..")
                exit(1)
            else:
                if self.__verbose:
                    print("INFO: Root CA certificate created.")

        # intermediate CA key pair and certificate
        if not ospath.isfile(self.__intermediateCAkeyfile):
            if not self.__init:
                if self.__verbose:
                    print("INFO: Initialising pki...")
                self.__init = True
            if self.__verbose:
                print("INFO: Generating intermediate CA private key...")
            cakey = self.create_key(
                passphrase=self.__intermediatePass,
                name=self.__intermediateCertname,
                ca='intermediate')

            if cakey['error']:
                #print("ERROR: Unable to generate intermediate CA key properly, aborting...")
                print(cakey['message'])
                # remove lock file
                self.remove_lockf(
                    "INFO: PKI unlocked after failing to generate intermediate CA key..")
                exit(1)
            else:
                if self.__verbose:
                    print("INFO: Intermediate CA key created.")

        if not ospath.isfile(self.__intermediateCAcrtfile):
            if ospath.isfile(self.__ca_chain):
                remove(self.__ca_chain)

            if not self.__init:
                if self.__verbose:
                    print("INFO: Initialising pki")
                self.__init = True

            if self.__verbose:
                print("INFO: Generating intermediate CA certificate for 10 years...")
            intermediate = self.create_cert(
                cn=self.__intermediateCertname,
                ca='intermediate',
                days_valid=10 * 365
            )
            if intermediate['error']:
                #print("ERROR: Unable to generate intermediate CA certificate properly, aborting...")
                print(intermediate['message'])
                # remove lock file
                self.remove_lockf(
                    "INFO: PKI unlocked after failing to generate intermediate CA cert..")
                exit(1)
            else:
                if self.__verbose:
                    print("INFO: Intermediate CA certificate created.")

        if not ospath.isfile(self.__ca_chain):
            if self.__verbose:
                print("INFO: Building ca certificates chain file...")

            certs4chain = [self.__intermediateCAcrtfile, self.__rootCAcrtfile]
            built = self.build_chain(certs4chain, self.__ca_chain)

            if not built['error']:
                if self.__verbose:
                    print("INFO: CA certificates chain file created.")
            else:
                #print("ERROR: Unable to generate CA certificates chain file created, aborting...")
                # remove lock file
                self.remove_lockf(
                    "INFO: PKI unlocked after failing to generate CA chain file..")
                print(built['message'])
                exit(1)

        if not ospath.isfile(self.__crlpath):
            if not self.__init:
                if self.__verbose:
                    print("INFO: Initialising pki")
                self.__init = True
            if self.__verbose:
                print("INFO: Generating CRL...")
            crlres = self.renew_crl_date()
            if crlres['error']:
                print(crlres['message'])
                # remove lock file
                self.remove_lockf(
                    "INFO: PKI unlocked after failing to generate CRL..")
                exit(1)

        if not self.__init:
            # checking expiry states in the pki db certs
            chk_pkidb_res = self.set_expiry_pkidb()
            if chk_pkidb_res['error']:
                print(chk_pkidb_res['message'])
                # remove lock file
                self.remove_lockf(
                    "INFO: PKI unlocked after failing to update pki db..")
                exit(1)
            else:
                if self.__verbose:
                    print(chk_pkidb_res['message'])

        self.__endinit = True

    def sigint_handler(self, signum, frame):
        '''
        Class sig handler for ctrl+c interrupt
        '''

        if self.__verbose:
            print('\nINFO: Execution interrupted by pressing [CTRL+C]')

        # remove lock file
        self.remove_lockf(
            message="INFO: PKI unlocked after user interruption..")
        exit(0)

    def chk_tree(self):
        '''
        Checking pki filesystem integrity.
        Returning error if:
            - The user use a private key but the pki file system doesn't exists
            - The pki filesystem path is a symlink
            - The pki filesystem path is a file (not directory)
            - Is missing some pki files needs

        :returns: Informational result dict {'error': Boolean, 'message': String}
        :rtype: Dict.
        '''

        if not ospath.exists(self.__pkiPath):
            res = {'error': True, 'message': "ERROR: Pki Path " + self.__pkiPath +
                   " doesn't exists. Please remove your current private key" +
                   " and init the pki again."}
            return(res)

        # pkipath must be an absolute path, without the final "/" for the
        # realpath check
        if self.__pkiPath[-1] == '/':
            pkipath = self.__pkiPath[:len(self.__pkiPath) - 1]
        else:
            pkipath = self.__pkiPath

        if ospath.realpath(pkipath) != pkipath:
            res = {
                'error': True,
                'message': "ERROR: Pki is a symlink, refusing to init pki."}
            return(res)

        if not ospath.isdir(pkipath):
            res = {
                'error': True,
                'message': "ERROR: Pki init failed, your pki path is already used."}
            return(res)
        else:
            dirnames = []
            filenames = []
            for path, dirs, files in oswalk(pkipath):
                for d in dirs:
                    dirnames.append(d)
                for f in files:
                    filenames.append(f)

            if 'public_key.pem' not in filenames:
                res = {
                    'error': False,
                    'message': "WARN: First init has to be done."}
                return(res)

            dirlen = len(dirnames)
            if dirlen < 6 and dirlen > 0:
                res = {
                    'error': True,
                    'message': "ERROR: Unproper PKI filesystem missing directories. Please erase current file system and re-init' the pki"}
                return(res)

            if 'intermediate_cacert.pem' in filenames or 'cacert.pem' in filenames:
                if 'pkicert.db' not in filenames or 'public_key.pem' not in filenames or 'pkipass.db' not in filenames:
                    res = {
                        'error': True,
                        'message': "ERROR: Unproper PKI filesystem, missing essential files. Please erase current file system and re-init' the pki"}
                    return(res)

        res = {'error': False, 'message': "INFO: PKI Filesystem clean."}
        return(res)

    def strip_accents(self, text):
        '''
        Strip accents from input String.

        :param text: The input string.
        :type text: String.

        :returns: The processed String.
        :rtype: String.
        '''

        try:
            text = unicode(text, 'utf-8')
        except NameError:  # unicode is a default on python 3
            pass
        text = uninormalize('NFD', text)
        text = text.encode('ascii', 'ignore')
        text = text.decode("utf-8")
        return str(text)

    def rmSpecialChar(self, instr):
        '''
        Removing encoded special chars

        :param instr: String to clean
        :type instr: String.

        :returns: The processed String.
        :rtype: String.
        '''

        cleanedStr = resub('\W+', '_', instr)
        return(cleanedStr)

    def cleanStr(self, txt):
        '''
        Clean string removing accents and special chars

        :param txt: String to clean
        :type txt: String.

        :returns: The processed String.
        :rtype: String.
        '''

        string = self.rmSpecialChar(self.strip_accents(txt))
        return(string)

    def set_expiry_pkidb(self):
        '''
        Allow to update pki db file.
        Set 'state' fields to expired if creation date + duration are < to current date and time

        :returns: Informational result dict {'error': Boolean, 'message': String}
        :rtype: Dict.
        '''

        pkidb = self.json2dict(self.__DBfile)
        if not pkidb['error']:
            pkidb = pkidb['message']
        else:
            res = {
                "error": True,
                "message": "ERROR: Unable to read Serial database " +
                self.__DBfile +
                "."}
            return(res)

        modified = False
        critical = False
        for certname in pkidb:
            if certname != 'revoked':
                if pkidb[certname]['state'] == "activ":
                    createdate = pkidb[certname]['created']
                    duration = pkidb[certname]['duration']
                    currentDate = datetime.utcnow()

                    # parse str date to datetime.datetime object
                    createDateTime = datetime.strptime(
                        createdate, '%Y/%m/%d %H:%M:%S')

                    # get timedelta object
                    timeDelta = currentDate - createDateTime

                    # get timedelta in days
                    deltadays = timeDelta.days - 1

                    if deltadays >= duration:
                        pkidb[certname]['state'] = "expired"
                        modified = True

                        if certname == 'cacert':
                            critical = True
                            res = {
                                "error": True,
                                "message": "ERROR: CA certificate is expired."}
                        elif certname == 'intermediate_cacert':
                            critical = True
                            res = {
                                "error": True,
                                "message": "ERROR: Intermediate CA certificate is expired."}
        if critical:
            return(res)

        if modified:
            newjson = jsonDump(pkidb, sort_keys=False)
            wresult = self.writeFile(self.__DBfile, newjson)
            if wresult['error']:
                res = {"error": True, "message": wresult['message']}
                return(res)
            else:
                res = {"error": False, "message": "INFO: Pki db file updated."}
                return(res)
        else:
            res = {"error": False, "message": "INFO: Pki db clean."}
            return(res)

    def gt_to_dt(self, gt):
        '''
        Convert GeneralizedTime string to python datetime object.
        Examples:
        >>> gt_to_dt("20150131143554.230")
        datetime.datetime(2015, 1, 31, 14, 35, 54, 230)
        >>> gt_to_dt("20150131143554.230Z")
        datetime.datetime(2015, 1, 31, 14, 35, 54, 230, tzinfo=<UTC>)
        >>> gt_to_dt("20150131143554.230+0300")
        datetime.datetime(2015, 1, 31, 11, 35, 54, 230, tzinfo=<UTC>)

        :param gt: String of GeneralizedTime to convert.
        :type gt: String.

        :returns: python datetime object.
        :rtype: datetime.date.
        '''

        # check UTC and offset from local time
        utc = False
        if b"Z" in gt.upper():
            utc = True
            gt = gt[:-1]
        if gt[-5] in ['+', '-']:
            # offsets are given from local time to UTC, so substract the offset
            # to get UTC time
            hour_offset, min_offset = - \
                int(gt[-5] + gt[-4:-2]), -int(gt[-5] + gt[-2:])
            utc = True
            gt = gt[:-5]
        else:
            hour_offset, min_offset = 0, 0

        # microseconds are optionnals
        if b"." in gt:
            microsecond = int(gt[gt.index('.') + 1:])
            gt = gt[:gt.index('.')]
        else:
            microsecond = 0

        # seconds and minutes are optionnals too
        if len(gt) == 14:
            year, month, day, hours, minutes, sec = int(gt[:4]), int(
                gt[4:6]), int(gt[6:8]), int(gt[8:10]), int(gt[10:12]), int(gt[12:])
            hours += hour_offset
            minutes += min_offset
        elif len(gt) == 12:
            year, month, day, hours, minutes, sec = int(gt[:4]), int(
                gt[4:6]), int(gt[6:8]), int(gt[8:10]), int(gt[10:]), 0
            hours += hour_offset
            minutes += min_offset
        elif len(gt) == 10:
            year, month, day, hours, minutes, sec = int(gt[:4]), int(
                gt[4:6]), int(gt[6:8]), int(gt[8:]), 0, 0
            hours += hour_offset
            minutes += min_offset
        else:
            # can't be a generalized time
            raise ValueError('This is not a generalized time string')

        # construct aware or naive datetime and format it with strftime
        if utc:
            #dt = datetime(year, month, day, hours, minutes, sec, microsecond, tzinfo=pytz.UTC).strftime('%Y-%m-%d %H:%M:%S')
            dt = datetime(
                year,
                month,
                day,
                hours,
                minutes,
                sec,
                microsecond,
                tzinfo=pytz.UTC).strftime('%d/%m/%Y %H:%M')
        else:
            dt = datetime(year, month, day, hours, minutes, sec,
                          microsecond).strftime('%d/%m/%Y %H:%M')
        # done !
        return(dt)

    def create_dir(self, pathDir, mode):
        '''
        Creating directories recursively, with octal value for dir mode perm'

        :param pathDir: Directory path to create.
        :type pathDir: String.

        :param mode: Octal representation for permission file and dir mode (eg. '0o[0-9]{3}').
        :type mode: Int.

        :returns: Informational result dict {'error': Boolean, 'message': String}
        :rtype: Dict.
        '''

        if not ospath.exists(pathDir):
            try:
                makedirs(pathDir, mode)
            except PermissionError as e:
                res = {
                    'error': True,
                    'message': 'ERROR: Unable to create dir ' + pathDir + ': ' + e.strerror}
                return(res)
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
                "message": "INFO: Directory " +
                pathDir +
                " already exists"}
            return(res)

    def get_csrinfo(self, filepath):
        '''
        Print formatted informations stored in the certificate request.

        :param filepath: CSR file path.
        :type filepath: String.

        :returns: Informational result dict {'error': Boolean, 'message': Formatted string containing all csr text infos}
        :rtype: Dict.
        '''

        try:
            reqObj = crypto.load_certificate_request(
                crypto.FILETYPE_PEM, open(filepath).read())
        except crypto.Error as e:
            res = {
                "error": True,
                "message": "ERROR: Unable to read CSR for " +
                csrname +
                " --> " +
                e.args[0][0][2]}
            return(res)
        except FileNotFoundError:
            res = {
                "error": True,
                "message": "ERROR: Unable to read CSR for " +
                csrname +
                " --> File not found"}
            return(res)

        formatted_res = ''

        ########################################
        # Get certificate subject informations #
        ########################################

        subject = reqObj.get_subject()
        certSubjectInfos = subject.get_components()
        unhandled = []
        for i in certSubjectInfos:
            if(i[0] == b'CN'):
                CN = i[1]
            elif(i[0] == b'C'):
                C = i[1]
            elif(i[0] == b'ST'):
                ST = i[1]
            elif(i[0] == b'L'):
                L = i[1]
            elif(i[0] == b'O'):
                O = i[1]
            elif(i[0] == b'OU'):
                OU = i[1]
            elif(i[0] == b'emailAddress'):
                email = i[1]
            else:
                unhandled.append(i)

        if len(unhandled) > 0:
            formatted_res += "INFOS: Unhandled items found:\n"
            for h in unhandled:
                formatted_res += '\t' + h[0].decode('utf-8') + '\n'
                # print value of item
                #print( h[1] )

        # Now print the subject Common Name of the certificate
        if CN:
            formatted_res += "Subject Common Name: " + \
                CN.decode('utf-8') + '\n'
        else:
            formatted_res += "Subject Common Name not found\n"

        if C:
            formatted_res += "Subject Country Name: " + \
                C.decode('utf-8') + '\n'

        if ST:
            formatted_res += "Subject State or Province: " + \
                ST.decode('utf-8') + '\n'

        if L:
            formatted_res += "Subject Locality Name: " + \
                L.decode('utf-8') + '\n'

        if O:
            formatted_res += "Subject Organization Name: " + \
                O.decode('utf-8') + '\n'

        if OU:
            formatted_res += "Subject Organizational Unit Name: " + \
                OU.decode('utf-8') + '\n'

        if email:
            formatted_res += "Subject Owner email is: " + \
                email.decode('utf-8') + '\n'

        ####################
        # Get cert version #
        ####################

        cert_ver = reqObj.get_version()
        formatted_res += "\nCertificate Version number: " + \
            str(cert_ver) + '\n'

        ################################
        # Format a public key as a PEM #
        ################################

        bio = crypto._new_mem_buf()
        cryptolib.PEM_write_bio_PUBKEY(bio, reqObj.get_pubkey()._pkey)
        pubkey = crypto._bio_to_string(bio)

        pubkey_size = reqObj.get_pubkey().bits()

        formatted_res += "\nPublic key size: " + str(pubkey_size) + '\n'
        formatted_res += "Public key:\n\n" + pubkey.decode('utf-8') + '\n'

        #########################################################
        # Get all extensions of the certificate in list of dict #
        #########################################################

        formatted_res += "\nCertificate extensions list:\n"

        extensions = {}
        X509exts = reqObj.get_extensions()
        for ext in X509exts:
            ext_name = ext.get_short_name().decode('utf-8')
            ext_data = ext.__str__()
            ext_critical = ext.get_critical()
            extensions[ext_name] = {'critical': ext_critical, 'data': ext_data}

        # Now extensions contains all extensions infoso we can consult it like that
        # print(extensions)
        formatted_res += '\n'

        # print info of extensions which you are looking for
        if 'extendedKeyUsage' in extensions:
            formatted_res += '\tExtended key usage: ' + \
                extensions['extendedKeyUsage']['data'] + '\n'
            extensions.pop('extendedKeyUsage', None)

        if 'basicConstraints' in extensions:
            formatted_res += '\tBasic constraints: ' + \
                extensions['basicConstraints']['data'] + '\n'
            extensions.pop('basicConstraints', None)

        if 'subjectAltName' in extensions:
            formatted_res += 'Subject alt-names:\n'
            for altname in extensions['subjectAltName']['data'].split(', '):
                formatted_res += "\t" + altname.split(':')[1] + '\n'
            extensions.pop('subjectAltName', None)

        # for all unhandled extensions
        for key, value in extensions.items():
            formatted_res += '\t' + key + ': ' + value + '\n'

        formatted_res += "\n"

        res = {'error': False, 'message': formatted_res}
        return(res)

    def get_certinfo(self, certname):
        '''
        Print formatted informations stored in the certificate

        :param certname: certificate name in the PKI.
        :type certname: String.

        :returns: Informational result dict {'error': Boolean, 'message': Formatted string containing all certificate text infos}
        :rtype: Dict.
        '''

        typeCert = self.reqType(certname)
        if not typeCert['error']:
            typeCert = typeCert['message']
        else:
            res = {
                "error": True,
                "message": "ERROR: Unable to find certificate type for " +
                certname +
                " --> " +
                typeCert['message']}
            return(res)

        if typeCert == 'SRV':
            CRTdir = self.__srvCRTdir
        elif typeCert == 'CLT':
            CRTdir = self.__cltCRTdir
        else:
            CRTdir = self.__srvCRTdir

        filespath = CRTdir + '/' + certname + '/' + certname
        certfilepath = filespath + '.crt'
        # if we do not find cert, trying to find it in signed dir
        if not ospath.isfile(certfilepath):
            certfilepath = self.__signeDir + '/' + certname + '/' + certname + '.crt'

        # loading certificate into X509 object
        try:
            latest_cert = crypto.load_certificate(
                crypto.FILETYPE_PEM, open(certfilepath).read())
        except FileNotFoundError as e:
            res = {'error': True, 'message': "ERROR: " +
                   e.strerror + ": " + certfilepath}
            return(res)
        except:
            res = {
                'error': True,
                'message': "ERROR: Unhandled error opening file: " + certfilepath}
            return(res)

        formatted_res = ""
        #################################
        # Get issuer infos: C, ST, etc. #
        #################################

        issuer = latest_cert.get_issuer()
        certIssuerInfos = issuer.get_components()
        unhandled = []
        for i in certIssuerInfos:
            if(i[0] == b'CN'):
                CN = i[1]
            elif(i[0] == b'C'):
                C = i[1]
            elif(i[0] == b'ST'):
                ST = i[1]
            elif(i[0] == b'L'):
                L = i[1]
            elif(i[0] == b'O'):
                O = i[1]
            elif(i[0] == b'OU'):
                OU = i[1]
            elif(i[0] == b'emailAddress'):
                email = i[1]
            else:
                unhandled.append(i)

        if len(unhandled) > 0:
            formatted_res += "INFOS: Unhandled items found:\n"
            for h in unhandled:
                formatted_res += '\t' + h[0].decode('utf-8') + '\n'
                # print value of item
                #print( h[1] )

        # Now print the issuer Common Name of the certificate
        if CN:
            formatted_res += "Issuer Common Name: " + CN.decode('utf-8') + '\n'
        else:
            formatted_res += "Issuer Common Name: Not found\n"

        if C:
            formatted_res += "Issuer Country Name: " + C.decode('utf-8') + '\n'

        if ST:
            formatted_res += "Issuer State or Province: " + \
                ST.decode('utf-8') + '\n'

        if L:
            formatted_res += "Issuer Locality Name: " + \
                L.decode('utf-8') + '\n'

        if O:
            formatted_res += "Issuer Organization Name: " + \
                O.decode('utf-8') + '\n'

        if OU:
            formatted_res += "Issuer Organizational Unit Name: " + \
                OU.decode('utf-8') + '\n'

        if email:
            formatted_res += "Issuer Owner email is: " + \
                email.decode('utf-8') + '\n'

        ########################################
        # Get certificate subject informations #
        ########################################

        cert_subjectname_hash = latest_cert.subject_name_hash()
        formatted_res += "\nSubject name hash: " + \
            str(cert_subjectname_hash) + '\n'

        subject = latest_cert.get_subject()
        certSubjectInfos = subject.get_components()
        unhandled = []
        for i in certSubjectInfos:
            if(i[0] == b'CN'):
                CN = i[1]
            elif(i[0] == b'C'):
                C = i[1]
            elif(i[0] == b'ST'):
                ST = i[1]
            elif(i[0] == b'L'):
                L = i[1]
            elif(i[0] == b'O'):
                O = i[1]
            elif(i[0] == b'OU'):
                OU = i[1]
            elif(i[0] == b'emailAddress'):
                email = i[1]
            else:
                unhandled.append(i)

        if len(unhandled) > 0:
            formatted_res += "INFOS: Unhandled items found:\n"
            for h in unhandled:
                formatted_res += '\t' + h[0].decode('utf-8') + '\n'
                # print value of item
                #print( h[1] )

        # Now print the subject Common Name of the certificate
        if CN:
            formatted_res += "Subject Common Name: " + \
                CN.decode('utf-8') + '\n'
        else:
            formatted_res += "Subject Common Name not found\n"

        if C:
            formatted_res += "Subject Country Name: " + \
                C.decode('utf-8') + '\n'

        if ST:
            formatted_res += "Subject State or Province: " + \
                ST.decode('utf-8') + '\n'

        if L:
            formatted_res += "Subject Locality Name: " + \
                L.decode('utf-8') + '\n'

        if O:
            formatted_res += "Subject Organization Name: " + \
                O.decode('utf-8') + '\n'

        if OU:
            formatted_res += "Subject Organizational Unit Name: " + \
                OU.decode('utf-8') + '\n'

        if email:
            formatted_res += "Subject Owner email is: " + \
                email.decode('utf-8') + '\n'

        ####################################
        # Check if certificate has expired #
        ####################################

        formatted_res += "\n"
        expired = latest_cert.has_expired()
        if not expired:
            formatted_res += 'Status: Not expired\n'
        else:
            formatted_res += 'Status: Expired\n'

        ############################
        # Get certificate validity #
        ############################

        fromdate = latest_cert.get_notBefore()
        todate = latest_cert.get_notAfter()
        formatted_res += "Valid from " + \
            self.gt_to_dt(fromdate) + " to " + self.gt_to_dt(todate) + '\n'

        ###############################
        # Get some other informations #
        ###############################

        cert_sn = latest_cert.get_serial_number()
        cert_algo_sign = latest_cert.get_signature_algorithm().decode('utf-8')
        cert_ver = latest_cert.get_version()
        formatted_res += "\nCertificate Serial Number: " + str(cert_sn) + '\n'
        formatted_res += "\nCertificate algorithm signature: " + cert_algo_sign + '\n'
        formatted_res += "\nCertificate Version number: " + \
            str(cert_ver) + '\n'

        ################################
        # Format a public key as a PEM #
        ################################

        bio = crypto._new_mem_buf()
        cryptolib.PEM_write_bio_PUBKEY(bio, latest_cert.get_pubkey()._pkey)
        pubkey = crypto._bio_to_string(bio)

        pubkey_size = latest_cert.get_pubkey().bits()

        formatted_res += "\nPublic key size: " + str(pubkey_size) + '\n'
        formatted_res += "Public key:\n\n" + pubkey.decode('utf-8') + '\n'

        #########################################################
        # Get all extensions of the certificate in list of dict #
        #########################################################

        formatted_res += "Certificate extensions list:\n"

        extensions = {}
        extnbr = latest_cert.get_extension_count()
        for count in range(extnbr):
            ext_name = latest_cert.get_extension(
                count).get_short_name().decode('utf-8')
            ext_critical = latest_cert.get_extension(count).get_critical()
            ext_data = latest_cert.get_extension(count).__str__()
            extensions[ext_name] = {'critical': ext_critical, 'data': ext_data}

        # Now extensions contains all extensions infoso we can consult it like that
        # print(extensions)

        # print info of extensions which you are looking for
        if 'extendedKeyUsage' in extensions:
            formatted_res += '\tExtended key usage: ' + \
                extensions['extendedKeyUsage']['data'] + '\n'
            extensions.pop('extendedKeyUsage', None)

        if 'basicConstraints' in extensions:
            formatted_res += '\tBasic constraints: ' + \
                extensions['basicConstraints']['data'] + '\n'
            extensions.pop('basicConstraints', None)

        if 'subjectAltName' in extensions:
            formatted_res += '\tSubject alt-names:\n'
            for altname in extensions['subjectAltName']['data'].split(', '):
                formatted_res += "\t\t" + altname.split(':')[1] + '\n'
            extensions.pop('subjectAltName', None)

        if 'keyUsage' in extensions:
            formatted_res += '\tKey Usage: ' + \
                extensions['keyUsage']['data'] + '\n'
            extensions.pop('keyUsage', None)

        # for all unhandled extensions
        for key, value in extensions.items():
            if key == 'crlDistributionPoints':
                formatted_res += '\t' + key + ': \n\t\t' + \
                    value['data'].strip('\nFull Name:\n') + '\n'
            else:
                formatted_res += '\t' + key + ': \n\t\t' + \
                    value['data'].strip() + '\n'

        res = {'error': False, 'message': formatted_res}
        return(res)

    def writeFile(self, wFile, wContent, mode='text'):
        '''
        Print formatted informations stored in the certificate

        :param wFile: destination file path.
        :type wFile: String.

        :param wContent: File writing content.
        :type wContent: String or bytes.

        :param mode: open file mode. Must be 'text' or 'bytes' (Default: text).
        :type mode: String.

        :returns: Informational result dict {'error': Boolean, 'message': String}
        :rtype: Dict.
        '''

        try:
            if mode == 'text':
                file = open(wFile, "wt")
            elif mode == 'bytes':
                file = open(wFile, "wb")
            else:
                res = {
                    "error": True,
                    "message": "ERROR: Please choose mode text or bytes to open your file " +
                    str(wFile)}
                return(res)
        except IOError:
            res = {
                "error": True,
                "message": "ERROR: Unable to open file " +
                str(wFile)}
            return(res)
        else:
            try:
                file.write(wContent)
            except IOError:
                res = {
                    "error": True,
                    "message": 'ERROR: Unable to write to file ' +
                    wFile}
                return(res)
            else:
                res = {
                    "error": False,
                    "message": 'INFO: File ' +
                    wFile +
                    ' written'}
                return(res)
            finally:
                file.close()

    def json2dict(self, fname):
        '''
        Convert a json file into python dict.
        :param fname: Json file path.
        :type fname: String.

        :returns: Informational result dict {'error': Boolean, 'message': String if error else Dict}
        :rtype: Dict.
        '''

        try:
            db = open(fname, "r")
            try:
                # load json from reading stream
                json = jsonLoad(db)
            except ValueError as e:
                json = 'ERROR: Json format error ' + \
                    str(fname) + ' --> ' + str(e)
                res = {"error": True, "message": json}
            else:
                res = {"error": False, "message": json}
        except IOError:
            json = 'ERROR: Unable to open file ' + fname
            res = {"error": True, "message": json}
        else:
            db.close()
        finally:
            return(res)

    def getSN(self):
        '''
        Define the last serial number available for generating a new certificate.

        :returns: Informational result dict {'error': Boolean, 'message': String if error else Int}
        :rtype: Dict.
        '''

        if self.__DBfile == "":
            res = {
                "error": True,
                "message": "ERROR: Empty serial database path"}
            return(res)
        elif not ospath.isfile(self.__DBfile):
            res = {
                "error": False,
                "message": "WARN: Serial database " +
                self.__DBfile +
                " not found"}
            return(res)
        else:
            jsondict = self.json2dict(self.__DBfile)
            if not jsondict['error']:
                jsondict = jsondict['message']
            else:
                res = {
                    "error": True,
                    "message": "ERROR: Unable to read Serial database " +
                    self.__DBfile +
                    "."}
                return(res)

            if isinstance(jsondict, dict):
                values = jsondict.values()
                v = list(values)
                size = len(v)
                if size > 0:
                    serials = []
                    for val in v:
                        if 'serial' in val:
                            serials.append(val['serial'])
                    serials.sort(reverse=True)
                    serialNum = int(serials[0]) + 1
                else:
                    serialNum = 1
            else:
                serialNum = jsondict

            res = {"error": False, "message": serialNum}
            return(res)

    def genpasswd(self, pwlen=25, alphabet=False):
        '''
        Pasword generator.
        :param pwlen: Password length.
        :type pwlen: Int.

        :param alphabet: (Optional) password chars to use.
        :type alphabet: String.

        :returns: Informational result dict {'error': Boolean, 'message': String if error else Dict}
        :rtype: Dict.
        '''

        if not alphabet:
            # Too many dangerous char for json format
            #alphabet = string.digits + string.ascii_letters + string.punctuation
            alphabet = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!#$%&()*+,-.:;<=>?@^_'

        pw_length = pwlen
        mypw = ""

        for i in range(pw_length):
            next_index = randrange(len(alphabet))
            mypw = mypw + alphabet[next_index]

        res = {'error': False, 'message': mypw}
        return(res)

    def writeJsonCert(
            self,
            serial,
            date,
            duration,
            state,
            certpath,
            sha,
            typeCert,
            createMode=False):
        '''
        Edit pki certificates database file.

        :param serial: Certificate serial number.
        :type serial: Int.

        :param date: Creation date string.
        :type date: String.

        :param duration: Number of days the certificate is valid.
        :type duration: Int.

        :param state: Certificate current state, is revoked or not, expired and so on.
        :type state: String.

        :param certpath: file path in the PKI.
        :type certpath: String.

        :param sha: openssl x509 certificate object shasum.
        :type sha: String.

        :param typeCert: Certificate type SRV, CLT or CA.
        :type typeCert: String.

        :param createMode: If the pki db file is to be created or not.
        :type createMode: Boolean.

        :returns: Informational result dict {'error': Boolean, 'message': String}
        :rtype: Dict.
        '''

        certfilename = ospath.basename(certpath)
        cn = ospath.splitext(certfilename)[0]
        certname = self.cleanStr(cn)

        certInfos = {
            'cn': cn,
            'serial': serial,
            'shasum': sha,
            'shaenc': self.__HASH_ENC,
            'created': date,
            'duration': duration,
            'type': typeCert,
            'state': state}

        if not createMode:
            jsondict = self.json2dict(self.__DBfile)
            if not jsondict['error']:
                jsondict = jsondict['message']
            else:
                res = {
                    "error": True,
                    "message": "ERROR: Unable to read pki database " +
                    self.__DBfile +
                    "."}
                return(res)
        else:
            jsondict = {}

        jsondict[certname] = certInfos
        json_out = jsonDump(jsondict, sort_keys=False)
        wresult = self.writeFile(self.__DBfile, json_out)
        if not wresult['error']:
            res = {"error": False, "message": wresult['message']}
            return(res)
        else:
            res = {"error": True, "message": wresult['message']}
            return(res)

    def getFromSTDIN(self, prompt):
        '''
        Get param from user STDIN

        :param prompt: User text to prompt.
        :type prompt: String.

        :returns: STDIN result.
        :rtype: String.
        '''

        if self.__python2:
            userinput = raw_input(prompt + ": ")
        else:
            userinput = input(prompt + ": ")
        return(userinput)

    def getFiles(self, path):
        '''
        Return a list of files in a directory, recursively.

        :param path: directory path in file system.
        :type path: String.

        :returns: Informational result dict {'error': Boolean, 'message': if error String else List}
        :rtype: Dict.
        '''

        if not ospath.exists(path):
            res = {
                'error': True,
                'message': 'ERROR: path ' + path + ' not found'}
            return(res)

        allFiles = []

        if ospath.isdir(path):
            for root, subfiles, files in oswalk(path):
                for names in files:
                    allFiles.append(ospath.join(root, names))
        else:
            allFiles.append(path)

        res = {'error': False, 'message': allFiles}
        return(res)

    def writeKey(self, wFile, wContent):
        '''
        Allow to write the pki authentication public key

        :param wFile: destination file path.
        :type wFile: String.

        :param wContent: File writing content.
        :type wContent: String or bytes.

        :returns: Informational result dict {'error': Boolean, 'message': String}
        :rtype: Dict.
        '''

        try:
            file = open(wFile, "wb")
        except IOError:
            res = {
                "error": True,
                "message": "ERROR: Unable to open file " +
                str(wFile)}
            return(res)
        else:
            try:
                file.write(wContent)
            except IOError:
                res = {
                    "error": True,
                    "message": 'ERROR: Unable to write to file ' +
                    wFile}
                return(res)
            else:
                res = {
                    "error": False,
                    "message": 'INFO: File ' +
                    wFile +
                    ' written'}
                return(res)
            finally:
                file.close()

    def genKey(self, keypass, keylen):
        '''
        Gen public/private RSA key pair in PEM format and password protected.

        :param keylen: Certificate encryption length (in 1024 to 8192).
        :type keylen: Int.

        :param keypass: Private key passphrase.
        :type keypass: String.

        :returns: Informational result dict {'error': Boolean, 'message': String (err or private key)}
        :rtype: Dict.
        '''

        random_generator = Random.new().read
        key = RSA.generate(keylen, random_generator)
        encrypted_key = key.exportKey(format='PEM', passphrase=keypass, pkcs=8)
        public_key = key.publickey().exportKey()

        cdres = self.create_dir(self.__passdir, 0o750)
        if cdres['error']:
            res = {"error": True, "message": 'ERROR: ' + cdres['message']}
            return(res)

        wpures = self.writeKey(wFile=self.__pubkeypath, wContent=public_key)
        if wpures['error']:
            res = {"error": True, "message": 'ERROR: ' + wpures['message']}
            return(res)

        print(
            'INFO: Please keep this private key carefully, this will allow you to init the pki:\n' +
            encrypted_key.decode('utf-8'))
        res = {"error": False, "message": encrypted_key.decode('utf-8')}

        return(res)

    def authBykey(self, privkeyString, passph):
        '''
        Authentication module which will encrypt something with the public key and check if it can be decrypted with the private key exposed by the user.

        :param privkeyString: Private key in string format.
        :type privkeyString: String.

        :param passph: Private key passphrase.
        :type passph: String.

        :returns: Informational result dict {'error': Boolean, 'message': String}
        :rtype: Dict.
        '''

        # encrypt with pubkey
        pubkeydir = self.__passdir
        try:
            pkey = open(pubkeydir + "/public_key.pem", "rt")
            try:
                public_key = RSA.importKey(pkey.read())
            except ValueError as e:
                res = {
                    "error": True,
                    "message": 'ERROR: Unable to import public key --> ' +
                    e.args[0] +
                    ". Unable to authenticate..."}
                return(res)
            finally:
                pkey.close()
        except FileNotFoundError as e:
            res = {"error": True, "message": 'ERROR: Public key not found.'}
            return(res)
        except:
            res = {
                "error": True,
                "message": 'ERROR: Problem reading public key'}
            return(res)

        randomData = Random.get_random_bytes(32)
        enc_data = public_key.encrypt(b'success', randomData)

        # decrypt with private key
        try:
            private_key = RSA.importKey(privkeyString, passph)
        except ValueError as e:
            res = {
                "error": True,
                "message": 'ERROR: Unable to import private key --> ' +
                e.args[0] +
                ". Unable to authenticate..."}
            return(res)

        dec_data = private_key.decrypt(enc_data)
        if dec_data == b'success':
            self.__token = SHA256.new(private_key.exportKey()).digest()
            res = {
                "error": False,
                "message": "INFO: Successfully authenticated"}
            return(res)
        else:
            self.__token = False
            res = {
                "error": True,
                "message": 'ERROR: Unable to authenticate, please check your private key'}
            return(res)

    def encryptFile(
            self,
            key,
            in_filename,
            out_filename=None,
            chunksize=64 *
            1024):
        '''
        Encrypts a file using AES (CFB mode) with the
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
        '''

        if not out_filename:
            out_filename = in_filename + '.enc'

        # generating random entropy for Initialization Vector
        iv = Random.new().read(AES.block_size)
        # converting passkey to a 32 bytes len str
        if not isinstance(key, bytes):
            key = key.encode('utf-8')
        key = SHA256.new(key).digest()

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

    def decryptFile(
            self,
            key,
            in_filename,
            out_filename=None,
            chunksize=24 *
            1024):
        '''
        Decrypts a file using AES (CFB mode) with the
        given key.

        Parameters are similar to encrypt_file,
        with one difference: out_filename, if not supplied
        will be in_filename without its last extension
        (i.e. if in_filename is 'aaa.zip.enc' then
        out_filename will be 'aaa.zip')
        '''

        if not out_filename:
            out_filename = ospath.splitext(in_filename)[0]

        # converting passkey to a 32 bytes len str
        if not isinstance(key, bytes):
            key = key.encode('utf-8')
        key = SHA256.new(key).digest()

        with open(in_filename, 'rb') as infile:
            origsize = struct.unpack(
                '<Q', infile.read(
                    struct.calcsize('Q')))[0]
            iv = infile.read(16)

            decryptor = AES.new(key, AES.MODE_CFB, iv)

            with open(out_filename, 'wb') as outfile:
                while True:
                    chunk = infile.read(chunksize)
                    if len(chunk) == 0:
                        break
                    outfile.write(decryptor.decrypt(chunk))

                outfile.truncate(origsize)

    def encryptData(self, key, data):
        '''
        Encrypts a file using AES (CFB mode) with the
        given key.

        key:
            The encryption key - a string that must be
            either 16, 24 or 32 bytes long. Longer keys
            are more secure.

        data:
            data to encrypt
        '''

        # converting passkey to a 32 bytes len str
        if not isinstance(key, bytes):
            key = key.encode('utf-8')
        key = SHA256.new(key).digest()
        # generating random entropy for Initialization Vector
        iv = Random.new().read(AES.block_size)

        cipher = AES.new(key, AES.MODE_CFB, iv)
        encdata = (iv + cipher.encrypt(data))

        res = {'error': False, 'message': encdata}
        return(res)

    def decryptData(self, key, encdata):
        '''
        Decrypts a file using AES (CFB mode) with the
        given key.
        Parameters are similar to encryptData
        '''

        # converting passkey to a 32 bytes len str
        if not isinstance(key, bytes):
            key = key.encode('utf-8')
        key = SHA256.new(key).digest()
        iv = encdata[:16]
        cipher = AES.new(key, AES.MODE_CFB, iv)
        data = cipher.decrypt(encdata[16:])

        res = {'error': False, 'message': data}
        return(res)

    def decryptDataFile(self, encdatafile, key):
        '''
        Decrypt a file content encrypted in AES(CFB)

        :param encdatafile: Encrypted file path.
        :type encdatafile: String.

        :param key: openssl Private key rsa object.
        :type key: x509object.

        :returns: Informational result dict {'error': Boolean, 'message': String}
        :rtype: Dict.
        '''

        try:
            ofile = open(encdatafile, 'rb')
        except IOError:
            res = {
                "error": True,
                "message": "ERROR: Unable to open file " +
                str(encdatafile)}
            return(res)
        else:
            encdata = ofile.read()
        finally:
            ofile.close()

        datafile = self.decryptData(key, encdata)
        # we are stripin' the 8 first char, and interpreting \n to have a clean
        # output
        data = str(datafile[8:]).replace('\\n', '\n')

        res = {'error': False, 'message': data}
        return(res)

    def loadpassDB(self):
        '''
        Module which decrypt and return pki passphrases DB into a dict

        :returns: Informational result dict {'error': Boolean, 'message': if error String else Dict}
        :rtype: Dict.
        '''

        if not ospath.exists(self.__passDBfile):
            passdb = {}
        else:
            try:
                ofile = open(self.__passDBfile, 'rb')
                try:
                    encdatafile = ofile.read()
                except:
                    res = {
                        "error": True,
                        "message": 'ERROR: Unable to read content of passphrases DB.'}
                    return(res)
            except IOError:
                json = 'ERROR: Unable to open file ' + self.__passDBfile
                res = {"error": True, "message": json}
                return(res)
            finally:
                ofile.close()

            if encdatafile != b'':
                datafile = self.decryptData(
                    key=self.__token, encdata=encdatafile)
                if datafile['error']:
                    res = {"error": True, "message": datafile['message']}
                    return(res)
                else:
                    datafile = datafile['message']

                try:
                    # load json from str decoded in utf-8
                    passdb = jsonLoadstr(datafile.decode("utf-8", "strict"))
                except ValueError as e:
                    json = 'ERROR: Json format error ' + \
                        str(datafile) + ' --> ' + str(e)
                    res = {"error": True, "message": json}
                    return(res)
                finally:
                    datafile = ''
            else:
                passdb = {}

        res = {"error": False, 'message': passdb}
        return(res)

    def reqType(self, certname):
        '''
        This module retrieve the pki certificate type of the given name.
        This will return a string in CA/CLT/SRV, allowing us to know the certificate purpose and it's PKI relative path

        :param certname: Certificate name in the PKI.
        :type : String.

        :returns: Informational result dict {'error': Boolean, 'message': String}
        :rtype: Dict.
        '''

        if self.__DBfile == "":
            res = {"error": True, "message": "ERROR: Empty pki database path"}
            return(res)
        elif not ospath.isfile(self.__DBfile):
            res = {
                "error": False,
                "message": "WARN: pki database " +
                self.__DBfile +
                " not found"}
            return(res)
        else:
            jsondict = self.json2dict(self.__DBfile)
            if not jsondict['error']:
                jsondict = jsondict['message']
            else:
                res = {
                    "error": True,
                    "message": "ERROR: Unable to read pki database " +
                    self.__DBfile +
                    "."}
                return(res)

        if isinstance(jsondict, dict):
            jcertname = self.cleanStr(certname)
            if jcertname in jsondict:
                typeCert = jsondict[jcertname]['type']
            else:
                res = {
                    "error": True,
                    "message": "ERROR: Unable to find certificate " +
                    certname +
                    " in pki database"}
                return(res)
        else:
            res = {"error": True, "message": "ERROR: " + jsondict}
            return(res)

        res = {"error": False, 'message': typeCert}
        return(res)

    def reqPass(self, certname):
        '''
        This module will retrieve the passphrase matching the pki certificate identified by it's name.

        :param certname: Certificate name in the pki which we want to retrieve the passphrase.
        :type : String.

        :returns: Informational result dict {'error': Boolean, 'message': String}
        :rtype: Dict.
        '''

        if not ospath.exists(self.__passDBfile):
            res = {"error": True, "message": 'ERROR: Database not found !'}
            return(res)
        else:
            try:
                ofile = open(self.__passDBfile, 'rb')
                try:
                    encdatafile = ofile.read()
                except:
                    res = {
                        "error": True,
                        "message": 'ERROR: Unable to read content of passphrases DB.'}
                    return(res)
            except IOError:
                json = 'ERROR: Unable to open file ' + self.__passDBfile
                res = {"error": True, "message": json}
                return(res)
            finally:
                ofile.close()

            if encdatafile != b'':
                datafile = self.decryptData(
                    key=self.__token, encdata=encdatafile)
                if datafile['error']:
                    res = {"error": True, "message": datafile['message']}
                    return(res)
                else:
                    datafile = datafile['message']

                try:
                    # load json from str decoded in utf-8
                    passdb = jsonLoadstr(datafile.decode("utf-8", "strict"))
                except ValueError as e:
                    json = 'ERROR: Json format error ' + \
                        str(datafile) + ' --> ' + str(e)
                    res = {"error": True, "message": json}
                    return(res)
                finally:
                    datafile = ''
            else:
                res = {"error": True, "message": 'ERROR: Database empty !'}
                return(res)

        certname = self.cleanStr(certname)
        if certname not in passdb:
            pwd = None
        else:
            pwd = passdb[certname]
        passdb.clear()

        res = {"error": False, 'message': pwd}
        return(res)

    def editpassDB(self, certname, passph):
        '''
        This will allow us to edit the pki passphrases database updating the corresponding certificate name entry.

        :param certname: PKI certificate name to edit.
        :type certname: String.

        :param passph: New PKI certificate passphrase.
        :type passph: String.

        :returns: Informational result dict {'error': Boolean, 'message': String}
        :rtype: Dict.
        '''

        certname = self.cleanStr(certname)
        passdb = self.loadpassDB()
        if passdb['error']:
            res = {"error": True, 'message': passdb['message']}
            return(res)
        else:
            passdb = passdb['message']

        # ecriture dans la db
        if isinstance(passph, bytes):
            passdb[certname] = passph.decode('utf-8')
        else:
            passdb[certname] = passph
        newjson = jsonDump(passdb, sort_keys=False)

        # encrypt data
        encDatas = self.encryptData(key=self.__token, data=newjson)
        encDatas = encDatas['message']

        wresult = self.writeFile(
            wFile=self.__passDBfile,
            wContent=encDatas,
            mode='bytes')
        if wresult['error']:
            res = {"error": True, "message": wresult['message']}
            return(res)
        else:
            passdb.clear()
            newjson = ''
            res = {
                "error": False,
                "message": "INFO: Passphrases db file updated"}
            return(res)

    def create_key(
            self,
            passphrase='None',
            keysize=False,
            name=None,
            KeyPurpose=None,
            ca=False):
        '''
        This module will generate a private key for certificate gen. At the end, the private key will be returned in utf-8 String format.

        :param passphrase: Key encryption passphrase. Can be leave as None to generate an unprotected key (not recommended).
        :type passphrase: String.

        :param keysize: Key encryption length, Must be in [1024,2048,4096,8192].
        :type keysize: Int.

        :param name: key name which must match the certificate common name.
        :type name: String.

        :param KeyPurpose: Define the certificate usage type: serverAuth/clientAuth. By default: serverAuth
        :type usage: String.

        :param ca: Indicate if the key will be use to generate a CA type certificate.
        :type ca: Boolean.

        :returns: Informational result dict {'error': Boolean, 'message': String}
        :rtype: Dict.
        '''

        if not name:
            res = {
                "error": True,
                "message": 'ERROR: Missing certificate common name.'}
            return(res)

        if KeyPurpose == 'serverAuth':
            CRTdir = self.__srvCRTdir
        elif KeyPurpose == 'clientAuth':
            CRTdir = self.__cltCRTdir
        else:
            KeyPurpose = False
            CRTdir = self.__srvCRTdir

        if not ca:
            keyfile = CRTdir + '/' + name + '/' + name + '.key'
        elif ca == 'intermediate':
            keyfile = self.__intermediateCAkeyfile
        else:
            keyfile = self.__rootCAkeyfile

        name = self.cleanStr(name)
        # encoding to utf-8 unicode to be compatible python3/python2
        if isinstance(passphrase, str):
            passphrase = passphrase.encode('utf-8')

        if not keyfile:
            res = {"error": True, "message": "WTF: Fuck, no keyname"}
            return(res)
        else:
            keydir = ospath.dirname(keyfile)
            resultkeydir = self.create_dir(keydir, 0o750)
            if resultkeydir['error']:
                print(resultkeydir['message'])
            else:
                if self.__verbose:
                    print(resultkeydir['message'])

        if ospath.isfile(keyfile):
            if self.__verbose:
                message = "WARN: Key " + keyfile + \
                    " has already been generated, trying to load it..."
                print(message)

            if not passphrase or passphrase == 'None':
                if not name or name == '':
                    if subjectAltName:
                        passname = subjectAltName[0]
                        if not passname or passname == '':
                            res = {
                                "error": True,
                                "message": 'ERROR: Unable to define owner name'}
                            return(res)
                else:
                    passname = name

                # loading passDB to get passphrase
                passphrase = self.reqPass(passname)
                if passphrase['error']:
                    res = {
                        'error': True,
                        'message': 'ERROR: Unable to retrieve passphrase, ' + passphrase['message'] + '. Exiting...'}
                    return(res)
                else:
                    privkeypass = passphrase['message']

                # flushing dictionnary
                if isinstance(passphrase['message'], dict):
                    passphrase['message'].clear()
                else:
                    passphrase['message'] = ''

                if not privkeypass or privkeypass == 'None':
                    key = self.load_pkey(keyfile)
                else:
                    key = self.load_pkey(keyfile, privkeypass)
            else:
                key = self.load_pkey(keyfile, passphrase)

            if not key['error']:
                key = key['message']
            else:
                res = {"error": True, "message": key['message']}
                return(res)

            res = {"error": False, "message": key}
            return(res)
        else:
            key = crypto.PKey()
            if keysize:
                key.generate_key(self.__KEY_ALGO, keysize)
            else:
                key.generate_key(self.__KEY_ALGO, self.__KEY_SIZE)
            if passphrase and passphrase != b'None':
                dumpedKey = crypto.dump_privatekey(
                    crypto.FILETYPE_PEM, key, self.__KEY_CIPHER, passphrase).decode('utf-8')
            else:
                dumpedKey = crypto.dump_privatekey(
                    crypto.FILETYPE_PEM, key).decode('utf-8')

            # addin passphrase to db
            reseditdb = self.editpassDB(certname=name, passph=passphrase)
            if reseditdb['error']:
                res = {
                    "error": True,
                    "message": 'ERROR: Unable to add ' +
                    name +
                    ' passphrase to DB --> ' +
                    reseditdb['message']}
                return(res)
            else:
                if self.__verbose:
                    print(reseditdb['message'] + " for " + name)

            wresult = self.writeFile(keyfile, dumpedKey)
            if not wresult['error']:
                res = {"error": False, "message": key}
                return(res)
            else:
                res = {"error": True, "message": wresult['message']}
                return(res)

    def build_chain(self, filenames, chain):
        '''
        This build the CA certificates chain file glueing files together.

        :param filenames: List of certificate file paths to glue.
        :type filenames: List.

        :param chain: Output file path which will contains the whole result.
        :type chain: String.

        :returns: Informational result dict {'error': Boolean, 'message': String}
        :rtype: Dict.
        '''

        try:
            with open(chain, 'w') as outfile:
                for fname in filenames:
                    with open(fname) as infile:
                        outfile.write(infile.read())
        except:
            raise

        res = {"error": False, "message": "INFO: build chain written"}
        return(res)

    def create_pkcs12(self, pkcs12name, pkcs12pwd=None):
        '''
        Create pkcs12 file of the matching PKI certificate name.

        :param pkcs12name: PKI existing certificate name.
        :type pkcs12name: String.

        :param pkcs12pwd: PKCS12 file password.
        :type pkcs12pwd: String.

        :returns: Informational result dict {'error': Boolean, 'message': String}
        :rtype: Dict.
        '''

        typeCert = self.reqType(pkcs12name)
        if not typeCert['error']:
            typeCert = typeCert['message']
        else:
            res = {
                "error": True,
                "message": "ERROR: Unable to find certificate type for " +
                keyname +
                " --> " +
                typeCert['error']}
            return(res)

        # loading passDB to get passphrase
        passphrase = self.reqPass(pkcs12name)
        if passphrase['error']:
            res = {'error': True, 'message': 'ERROR: Unable to retrieve passphrase, ' +
                   passphrase['message'] + '. Exiting...'}
            return(res)
        else:
            keypass = passphrase['message']

        # flushing dictionnary
        if isinstance(passphrase['message'], dict):
            passphrase['message'].clear()
        else:
            passphrase['message'] = ''

        if typeCert == 'SRV':
            CRTdir = self.__srvCRTdir
        elif typeCert == 'CLT':
            CRTdir = self.__cltCRTdir
        else:
            CRTdir = self.__srvCRTdir

        filespath = CRTdir + '/' + pkcs12name + '/' + pkcs12name
        key = filespath + '.key'
        cert = filespath + '.crt'
        pkcs12filePath = filespath + '.p12'

        if ospath.isfile(pkcs12filePath):
            res = {
                "error": False,
                "message": "WARN: PKCS12 file " +
                pkcs12filePath +
                " has already been generated !"}
            return(res)

        pkcs12 = crypto.PKCS12()

        # if we do not find key, trying to find it in requested dir
        if not ospath.exists(key):
            key = self.__csrDir + '/' + pkcs12name + '/' + pkcs12name + '.key'
        opsslObjKey = self.load_pkey(key, keypass)
        if not opsslObjKey['error']:
            opsslObjKey = opsslObjKey['message']
        else:
            res = {"error": True, "message": opsslObjKey['message']}
            return(res)

        issuerCertObj = self.load_crt(self.__intermediateCAcrtfile)
        if not issuerCertObj['error']:
            issuerCertObj = issuerCertObj['message']
        else:
            res = {"error": True, "message": issuerCertObj['message']}
            return(res)

        # if we do not find cert, trying to find it in signed dir
        if not ospath.isfile(cert):
            cert = self.__signeDir + '/' + pkcs12name + '/' + pkcs12name + '.crt'
        certObj = self.load_crt(cert)
        if not certObj['error']:
            certObj = certObj['message']
        else:
            res = {"error": True, "message": certObj['message']}
            return(res)

        pkcs12.set_certificate(certObj)
        pkcs12.set_privatekey(opsslObjKey)
        pkcs12.set_ca_certificates([issuerCertObj])

        pkcs12dir = ospath.dirname(pkcs12filePath)
        resultpkcs12dir = self.create_dir(pkcs12dir, 0o750)
        if resultpkcs12dir['error']:
            print(resultpkcs12dir['message'])

        try:
            open(
                pkcs12filePath,
                "wb").write(
                pkcs12.export(
                    passphrase=pkcs12pwd,
                    iter=2048,
                    maciter=2048))
        except IOError:
            res = {
                "error": True,
                "message": "ERROR: Unable to create PKCS12 file: " +
                pkcs12filePath}
            return(res)
        res = {
            "error": False,
            "message": "INFO: PKCS12 file created in: " +
            pkcs12filePath}
        return(res)

    def extract_pkcs12(
            self,
            pkcs12file,
            destdir,
            pkcs12pwd=False,
            inPrivKeypass=False):
        '''
        Extract files from pkcs12 file path archive.

        :param pkcs12file: PKCS12 file path to extract.
        :type pkcs12file: String.

        :param pkcs12pwd: PKCS12 file password.
        :type pkcs12pwd: String.

        :param destdir: Extracted files destination directory.
        :type destdir: String.

        :param inPrivKeypass: private key passphrase if the key is protected.
        :type inPrivKeypass: String.

        :returns: Informational result dict {'error': Boolean, 'message': String}
        :rtype: Dict.
        '''

        if ospath.exists(destdir):
            useransw = self.getFromSTDIN(
                "WARN: File has already been extracted in " +
                destdir +
                ", do you want to replace it [y/n]")
            answlist = ['y', 'Y', 'N', 'n']
            count = 0
            while useransw not in answlist:
                count += 1
                if count > 2:
                    res = {
                        "error": True,
                        "message": "ERROR: You must choose y or n, but you entered " +
                        useransw +
                        " aborting extract..."}
                    return(res)
                    # break
                useransw = self.getFromSTDIN(
                    "WARN: File has already been extracted in " +
                    destdir +
                    ", do you want to replace it [y/n]")
            if useransw == 'n' or useransw == 'N':
                res = {"error": False, "message": "INFO: Extract abort."}
                return(res)

        if destdir[-1] != '/':
            destdir = destdir + "/"

        self.create_dir(destdir, 0o750)

        if not pkcs12pwd:
            try:
                pkcsObj = crypto.load_pkcs12(open(pkcs12file, 'rb').read())
            except:
                res = {
                    "error": True,
                    "message": "ERROR: Unable to load pkcs file: " +
                    pkcs12file +
                    " The pkcs file is probably password protected.."}
                return(res)
        else:
            try:
                pkcsObj = crypto.load_pkcs12(
                    open(pkcs12file, 'rb').read(), pkcs12pwd)
            except SSL.Error as e:
                res = {
                    "error": True,
                    "message": "ERROR: " +
                    e.strerror +
                    " " +
                    e.filename}
                return(res)
            except:
                res = {
                    "error": True,
                    "message": "ERROR: Unable to load pkcs file: " +
                    pkcs12file +
                    " Please verify your pkcs12 password."}
                return(res)

        cacert = pkcsObj.get_ca_certificates()
        cert = pkcsObj.get_certificate()
        key = pkcsObj.get_privatekey()

        subject = cert.get_subject()
        subject_infos = subject.get_components()
        for info in subject_infos:
            if info[0] == b'CN':
                commonName = str(info[1].decode('utf-8'))

        if inPrivKeypass:
            dumpedKey = crypto.dump_privatekey(
                crypto.FILETYPE_PEM,
                key,
                self.__KEY_CIPHER,
                inPrivKeypass).decode('utf-8')
        else:
            dumpedKey = crypto.dump_privatekey(
                crypto.FILETYPE_PEM, key).decode('utf-8')

        dumpedCACert = crypto.dump_certificate(
            crypto.FILETYPE_PEM, cacert[0]).decode('utf-8')
        dumpedCert = crypto.dump_certificate(
            crypto.FILETYPE_PEM, cert).decode('utf-8')

        wres1 = self.writeFile(
            destdir +
            "ca_" +
            commonName +
            ".crt",
            dumpedCACert)
        wres2 = self.writeFile(destdir + commonName + ".crt", dumpedCert)
        self.writeFile(destdir + commonName + ".key", dumpedKey)

        if wres1['error']:
            res = {
                "error": True,
                "message": "ERROR: Unable to write " +
                destdir +
                "ca_" +
                commonName +
                ".crt"}
            return(res)
        elif wres1['error']:
            res = {
                "error": True,
                "message": "ERROR: Unable to write " +
                destdir +
                commonName +
                ".crt"}
            return(res)
        elif wres2['error']:
            res = {
                "error": True,
                "message": "ERROR: Unable to write " +
                destdir +
                commonName +
                ".key"}
            return(res)
        else:
            res = {
                "error": False,
                "message": "INFO: File " +
                pkcs12file +
                " extracted successfully in " +
                destdir}
            return(res)

    def unprotect_key(self, keyname, privKeypass):
        '''
        Remove private key passphrase from key matching PKI certificate name.

        :param keyname: PKI certificate name associated to the private key.
        :type keyname: String.

        :param privKeypass: Private key passphrase.
        :type privKeypass: String.

        :returns: Informational result dict {'error': Boolean, 'message': String}
        :rtype: Dict.
        '''

        typeCert = self.reqType(keyname)
        if not typeCert['error']:
            typeCert = typeCert['message']
        else:
            res = {
                "error": True,
                "message": "ERROR: Unable to find certificate type for " +
                keyname +
                " --> " +
                typeCert['error']}
            return(res)

        if typeCert == "SRV":
            keydir = self.__srvCRTdir + "/" + keyname
        if typeCert == "CLT":
            keydir = self.__cltCRTdir + "/" + keyname

        key = keydir + "/" + keyname + ".key"
        #keyfilename = ospath.basename(key)
        #keyname = ospath.splitext(keyfilename)[0]
        #keydir = ospath.dirname(key)

        if ospath.isfile(keydir + "/" + keyname + "_unprotected.key"):
            res = {
                "error": False,
                "message": "WARN: Key " +
                key +
                " already unprotected, see:" +
                keydir +
                "/" +
                keyname +
                "_unprotected.key !"}
            return(res)

        if not ospath.isfile(key):
            # if we do not find key, trying to find it in requested dir
            key = self.__csrDir + '/' + keyname + '/' + keyname + '.key'
            if not ospath.isfile(key):
                res = {
                    "error": True,
                    "message": "ERROR: Unable to find " +
                    key}
                return(res)

        if isinstance(privKeypass, str):
            privKeypass = privKeypass.encode('utf-8')

        keyObj = self.load_pkey(key, privKeypass)
        if not keyObj['error']:
            keyObj = keyObj['message']
        else:
            res = {"error": True, "message": keyObj['message']}
            return(res)

        dumpedKey = crypto.dump_privatekey(
            crypto.FILETYPE_PEM, keyObj).decode('utf-8')

        wresult = self.writeFile(
            keydir +
            "/" +
            keyname +
            "_unprotected.key",
            dumpedKey)
        if wresult['error']:
            res = {"error": True, "message": wresult['message']}
            return(res)
        else:
            res = {
                "error": False,
                "message": "INFO: Unprotected version of private key " +
                key +
                " put in " +
                keydir +
                "/" +
                keyname +
                "_unprotected.key"}
            return(res)

    def create_csr(
            self,
            passphrase=None,
            country='',
            subjectAltName=None,
            state='',
            city='',
            org='',
            ou='',
            cn='',
            email='',
            encryption=False,
            keysize=False):
        '''
        Generate private key with it 's Certificate Signature Request.

        :param passphrase: Private key passphrase.
        :type passphrase: String.

        :param country: Certificate country information.
        :type country: String.

        :param subjectAltName: Certificate Subject Alt-names extension. Must be in this format [ 'type:value' ] and types are 'email', 'URI', 'IP', 'DNS'.
        :type subjectAltName: List of string.

        :param state: Certificate state information.
        :type state: String.

        :param city: Certificate city information.
        :type city: String.

        :param org: Certificate organization information.
        :type org: String.

        :param ou: Certificate organization unit information.
        :type ou: String.

        :param cn: Certificate Common Name.
        :type cn: String.

        :param email: Certificate administrator e-mail information.
        :type email: String.

        :param encryption: Private key encryption (SHA1/SHA256/SHA512).
        :type encryption: String.

        :param keysize: Private key size must be in [1024-8192].
        :type keysize: Int.

        :returns: Informational result dict {'error': Boolean, 'message': String}
        :rtype: Dict.
        '''

        if not cn or cn == '':
            if subjectAltName:
                passname = subjectAltName[0]
                if not passname or passname == '':
                    res = {
                        "error": True,
                        "message": 'ERROR: Unable to define owner name'}
                    return(res)
        else:
            passname = cn

        csrfile = self.__csrDir + "/" + passname + "/" + passname + ".csr"
        csrkey = self.__csrDir + "/" + passname + "/" + passname + ".key"

        if ospath.isfile(csrfile):
            res = {
                "error": False,
                "message": "WARN: CSR " +
                csrfile +
                " has already been generated !"}
            return(res)
        else:
            if country == '':
                country = self.__C
            if state == '':
                state = self.__ST
            if city == '':
                city = self.__L
            if org == '':
                org = self.__O
            if ou == '':
                ou = self.__OU
            if email == '':
                email = self.__adminEmail

            if passphrase:
                # addin passphrase to db
                reseditdb = self.editpassDB(
                    certname=passname, passph=passphrase)
                if reseditdb['error']:
                    res = {
                        "error": True,
                        "message": 'ERROR: Unable to add ' +
                        passname +
                        ' passphrase to DB --> ' +
                        reseditdb['message']}
                    return(res)
                else:
                    if self.__verbose:
                        print(reseditdb['message'] + " for " + passname)

                # encoding to utf-8 unicode to be compatible python3/python2
                if isinstance(passphrase, str):
                    passphrase = passphrase.encode('utf-8')

            csrpathdir = ospath.dirname(csrfile)

            resultdir = self.create_dir(csrpathdir, 0o750)
            if self.__verbose:
                if resultdir['message']:
                    print(resultdir['message'])
            key = crypto.PKey()
            if keysize:
                key.generate_key(self.__KEY_ALGO, keysize)
            else:
                key.generate_key(self.__KEY_ALGO, self.__KEY_SIZE)

            req = crypto.X509Req()

            req.get_subject().C = country
            req.get_subject().ST = state
            req.get_subject().L = city
            req.get_subject().O = org
            req.get_subject().OU = ou
            if cn:
                req.get_subject().CN = cn
            req.get_subject().emailAddress = email
            req.set_pubkey(key)

            if subjectAltName:
                critical = True if not cn else False
                req.add_extensions([crypto.X509Extension(b"subjectAltName", critical, b",     ".join(
                    s.encode('utf-8') for s in subjectAltName))])
            if not encryption:
                req.sign(key, self.__SIGN_ALGO)
            else:
                req.sign(key, encryption)

            # Write private key
            if passphrase:
                dumpedKey = crypto.dump_privatekey(
                    crypto.FILETYPE_PEM, key, self.__KEY_CIPHER, passphrase).decode('utf-8')
            else:
                dumpedKey = crypto.dump_privatekey(
                    crypto.FILETYPE_PEM, key, self.__KEY_CIPHER, passphrase).decode('utf-8')
            wresult = self.writeFile(csrkey, dumpedKey)
            if wresult['error']:
                res = {"error": True, "message": wresult['message']}
                return(res)

            # Write request
            dumpedCsr = crypto.dump_certificate_request(
                crypto.FILETYPE_PEM, req).decode('utf-8')
            wresult = self.writeFile(csrfile, dumpedCsr)
            if wresult['error']:
                res = {"error": True, "message": wresult['message']}
                return(res)

            res = {
                "error": False,
                "message": "INFO: CSR and private key generated in: " +
                csrpathdir}
            return(res)

    def sign_csr(
            self,
            csr,
            valid_before=0,
            KeyPurpose=False,
            KeyUsage=False,
            days_valid=None,
            encryption=False):
        '''
        Create a X509 signed certificate.

        :param csr: Certificate Signing Request file path.
        :type csr: String.

        :param encryption: Certificate encryption (SHA1/SHA256/SHA512).
        :type encryption: String.

        :param valid_before: Allow to generate a certificate which will be
                             valid (from now) in number of days in the future.
        :type valid_before: Int.

        :param days_valid: Define the periode, in days, during which the certfiicate will be valid. If valid_before is specified the validity will start at valid_before time .
        :type days_valid: Int.

        :param KeyPurpose: Define the certificate purpose. Could be for server (serverAuth) or client authentication(clientAuth), if not specified, the certificate will support both.
        :type KeyPurpose: String.

        :param KeyUsage: Define the certificate usage. Could be [digitalSignature, nonRepudiation, contentCommitment, keyEncipherment, dataEncipherment, keyAgreement, keyCertSign, cRLSign, encipherOnly, decipherOnly
], if not specified, the certificate will bear keyEncipherment and dataEncipherment.
        :type KeyUsage: String.

        :returns: Informational result dict {'error': Boolean, 'message': String}
        :rtype: Dict.
        '''

        if not KeyPurpose:  # define key usage
            typecrt = "SRV"
            KeyPurpose = "serverAuth, clientAuth"
        elif KeyPurpose == "clientAuth":
            typecrt = "CLT"
        elif KeyPurpose == "serverAuth":
            typecrt = "SRV"
        else:
            res = {
                "error": True,
                "message": "ERROR: Wrong Key Usage type " +
                KeyPurpose +
                ", it must be serverAuth or clientAuth !"}
            return(res)
        CRTdir = self.__signeDir

        certbname = ospath.basename(csr)
        certname = ospath.splitext(certbname)[0]
        filespath = CRTdir + '/' + certname + '/' + certname
        resultdir = self.create_dir(CRTdir + '/' + certname, 0o750)
        if self.__verbose:
            if resultdir['message']:
                print(resultdir['message'])
        cert = filespath + '.crt'
        csr_bk_path = filespath + '.csr'

        if ospath.isfile(cert):
            res = {
                "error": False,
                "message": "WARN: Certificate " +
                certname +
                " has already been signed !"}
            return(res)

        if not days_valid:
            days_valid = self.__VALID_DAYS

        currentDate = datetime.utcnow().strftime('%Y/%m/%d %H:%M:%S')
        tocreate = False

        caKeyObj = self.load_pkey(
            self.__intermediateCAkeyfile,
            self.__intermediatePass)
        if not caKeyObj['error']:
            caKeyObj = caKeyObj['message']
        else:
            res = {"error": True, "message": caKeyObj['message']}
            return(res)

        caCertObj = self.load_crt(self.__intermediateCAcrtfile)
        if not caCertObj['error']:
            caCertObj = caCertObj['message']
        else:
            res = {"error": True, "message": caCertObj['message']}
            return(res)

        try:
            reqObj = crypto.load_certificate_request(
                crypto.FILETYPE_PEM, open(csr).read())
        except SSL.SysCallError as e:
            res = {"error": True, "message": e.strerror + " " + e.filename}
            #print(e.args, e.errno, e.filename, e.strerror)
            return(res)
        except SSL.Error as f:
            res = {"error": True, "message": f.strerror + " " + f.filename}
            return(res)
        except SSL.WantReadError as r:
            res = {"error": True, "message": r.strerror + " " + r.filename}
            return(res)
        except SSL.WantWriteError as w:
            res = {"error": True, "message": w.strerror + " " + w.filename}
            return(res)
        except SSL.WantX509LookupError as x:
            res = {"error": True, "message": x.strerror + " " + x.filename}
            return(res)
        except Exception as ex:
            res = {"error": True, "message": ex.strerror + " " + ex.filename}
            return(res)
        except:
            res = {"error": True, "message": "Unexpected error"}
            return(res)

        # archive csr
        dumpedCsr = crypto.dump_certificate_request(
            crypto.FILETYPE_PEM, reqObj).decode('utf-8')
        wresult = self.writeFile(csr_bk_path, dumpedCsr)
        if wresult['error']:
            res = {"error": True, "message": wresult['message']}
            return(res)

        SERIAL_NUMBER = self.getSN()
        if SERIAL_NUMBER['error']:
            res = {"error": True, "message": SERIAL_NUMBER['message']}
            return(res)
        else:
            SERIAL_NUMBER = SERIAL_NUMBER['message']

        if not isinstance(SERIAL_NUMBER, int):
            if research(
                "Serial database.+not found",
                    SERIAL_NUMBER) is not None:
                if rematch(".*intermediate.*", cert):
                    print(SERIAL_NUMBER)
                else:
                    SERIAL_NUMBER = 1
                    tocreate = True
            else:
                res = {
                    "error": True,
                    "message": SERIAL_NUMBER +
                    " during generation of " +
                    cert}
                return(res)

        csr_subject = reqObj.get_subject()

        certObj = crypto.X509()
        certObj.set_version(3 - 1)  # version 3, starts at 0
        certObj.set_subject(csr_subject)
        certObj.set_serial_number(SERIAL_NUMBER)
        certObj.set_pubkey(reqObj.get_pubkey())
        certObj.set_issuer(caCertObj.get_subject())
        certObj.gmtime_adj_notBefore(valid_before * 24 * 3600)
        certObj.gmtime_adj_notAfter(days_valid * 24 * 3600)

        csr_components = dict(csr_subject.get_components())
        csr_components[b'CN']

        certObj.add_extensions([
            crypto.X509Extension(b"basicConstraints", False, b"CA:FALSE")
        ])

        if KeyPurpose == "serverAuth, clientAuth":
            certObj.add_extensions(
                [
                    crypto.X509Extension(
                        b"extendedKeyUsage",
                        True,
                        b"serverAuth, clientAuth"
                    )
                ]
            )
        else:
            certObj.add_extensions(
                [
                    crypto.X509Extension(
                        b"extendedKeyUsage",
                        True,
                        KeyPurpose.encode('utf-8')
                    )
                ]
            )

        if KeyUsage:
            certObj.add_extensions(
                [
                    crypto.X509Extension(
                        b"keyUsage",
                        True,
                        KeyUsage.encode('utf-8')
                    )
                ]
            )
        else:
            certObj.add_extensions(
                [
                    crypto.X509Extension(
                        b"keyUsage",
                        True,
                        #b"dataEncipherment, digitalSignature, nonRepudiation"),
                        b"keyEncipherment, dataEncipherment"
                    )
                ]
            )

        san = False
        # look for san x509 extension
        x509exts = reqObj.get_extensions()
        for ext in x509exts:
            if ext.get_short_name() == b'subjectAltName':
                san = True
                #csrSubjAltN_crit = ext.get_critical()
                #SAN_data = ext.get_data()
                san_ext = ext

        # if san found, add it to the certificate
        if san:
            certObj.add_extensions([san_ext])

        if encryption:
            certObj.sign(caKeyObj, encryption)
        else:
            certObj.sign(caKeyObj, self.__SIGN_ALGO)

        dumpedCert = crypto.dump_certificate(
            crypto.FILETYPE_PEM, certObj).decode('utf-8')
        wresult = self.writeFile(cert, dumpedCert)
        if wresult['error']:
            res = {"error": True, "message": wresult['message']}
            return(res)
        else:
            if self.__HASH_ENC == 'sha1':
                shasum = hashlib.sha1(dumpedCert.encode('utf-8')).hexdigest()
            elif self.__HASH_ENC == '224':
                shasum = hashlib.sha224(dumpedCert.encode('utf-8')).hexdigest()
            elif self.__HASH_ENC == '256':
                shasum = hashlib.sha256(dumpedCert.encode('utf-8')).hexdigest()
            elif self.__HASH_ENC == '384':
                shasum = hashlib.sha384(dumpedCert.encode('utf-8')).hexdigest()
            elif self.__HASH_ENC == '512':
                shasum = hashlib.sha512(dumpedCert.encode('utf-8')).hexdigest()

            if tocreate:
                success = self.writeJsonCert(
                    sha=shasum,
                    serial=SERIAL_NUMBER,
                    date=currentDate,
                    duration=self.__VALID_DAYS,
                    state='activ',
                    certpath=cert,
                    createMode=True,
                    typeCert=typecrt)
                if success['error']:
                    res = {"error": True, "message": success['message']}
                    return(res)
            else:
                success = self.writeJsonCert(
                    sha=shasum,
                    serial=SERIAL_NUMBER,
                    date=currentDate,
                    duration=self.__VALID_DAYS,
                    state='activ',
                    certpath=cert,
                    typeCert=typecrt)
                if success['error']:
                    res = {"error": True, "message": success['message']}
                    return(res)

        res = {"error": False, "message": "INFO: CSR signed."}
        return(res)

    def check_cer_vs_key(self, cert, key, keypass=False):
        '''
        Verify that the certificate belongs to private key.

        :param cert: Certificate file path.
        :type cert: String.

        :param key: Private key file path.
        :type key: String.

        :param keypass: Private key passphrase if needed.
        :type keypass: String.

        :returns: Informational result dict {'error': Boolean, 'message': String}
        :rtype: Dict.
        '''

        if not ospath.isfile(cert):
            res = {"error": True, "message": "ERROR: Unable to find " + cert}
            return(res)
        elif not ospath.isfile(key):
            res = {"error": True, "message": "ERROR: Unable to find " + key}
            return(res)

        keyObj = self.load_pkey(key, keypass)
        if not keyObj['error']:
            keyObj = keyObj['message']
        else:
            res = {"error": True, "message": keyObj['message']}
            return(res)

        certObj = self.load_crt(cert)
        if not certObj['error']:
            certObj = certObj['message']
        else:
            res = {"error": True, "message": certObj['message']}
            return(res)

        ctx = SSL.Context(SSL.TLSv1_METHOD)
        ctx.use_privatekey(keyObj)
        ctx.use_certificate(certObj)

        try:
            ctx.check_privatekey()
        except SSL.Error:
            res = {
                "error": True,
                "message": "ERROR: Incorrect key " +
                key +
                " for certificate " +
                cert}
            return(res)
        else:
            res = {
                "error": False,
                "message": "INFO: Key " +
                key +
                " matches certificate " +
                cert}
            return(res)

    def load_crl(self, crlfile):
        '''
        Load crl file content to openssl x509 object.

        :param crlfile: CRL file path.
        :type crlfile: String.

        :returns: Informational result dict {'error': Boolean, 'message': if error String else x509 object}
        :rtype: Dict.
        '''

        if not ospath.isfile(crlfile):
            x509obj = crypto.CRL()
            if self.__verbose:
                print("INFO: New CRL " + crlfile + " created.")
            res = {"error": False, "message": x509obj}
            return(res)
        else:
            try:
                x509obj = crypto.load_crl(
                    crypto.FILETYPE_PEM, open(crlfile).read())
            except SSL.SysCallError as e:
                res = {"error": True, "message": e.strerror + " " + e.filename}
                #print(e.args, e.errno, e.filename, e.strerror)
            except SSL.Error as f:
                res = {"error": True, "message": f.strerror + " " + f.filename}
            except SSL.WantReadError as r:
                res = {"error": True, "message": r.strerror + " " + r.filename}
            except SSL.WantWriteError as w:
                res = {"error": True, "message": w.strerror + " " + w.filename}
            except SSL.WantX509LookupError as x:
                res = {"error": True, "message": x.strerror + " " + x.filename}
            except Exception as ex:
                res = {
                    "error": True,
                    "message": ex.strerror +
                    " " +
                    ex.filename}
            except:
                res = {"error": True, "message": "Unexpected error"}
            else:
                res = {"error": False, "message": x509obj}
            finally:
                return(res)

    def load_pkey(self, key, keypass=False):
        '''
        Load private key file content to openssl x509 object.

        :param key: Private key file path.
        :type key: String.

        :param keypass: Private key passphrase if needed.
        :type keypass: String.

        :returns: Informational result dict {'error': Boolean, 'message': if error String else x509 object}
        :rtype: Dict.
        '''

        if not keypass:
            try:
                x509obj = crypto.load_privatekey(
                    crypto.FILETYPE_PEM, open(key).read())
            except SSL.SysCallError as e:
                res = {"error": True, "message": e.strerror + " " + e.filename}
                #print(e.args, e.errno, e.filename, e.strerror)
            except SSL.Error as f:
                res = {"error": True, "message": f.strerror + " " + f.filename}
            except SSL.WantReadError as r:
                res = {"error": True, "message": r.strerror + " " + r.filename}
            except SSL.WantWriteError as w:
                res = {"error": True, "message": w.strerror + " " + w.filename}
            except SSL.WantX509LookupError as x:
                res = {"error": True, "message": x.strerror + " " + x.filename}
            except Exception as ex:
                res = {
                    "error": True,
                    "message": ex.strerror +
                    " " +
                    ex.filename}
            except:
                res = {"error": True, "message": "Unexpected error"}
            else:
                res = {"error": False, "message": x509obj}
            finally:
                return(res)
        else:
            if isinstance(keypass, str):
                keypass = keypass.encode('utf-8')

            try:
                keyfile = open(key, "rb")
            except IOError:
                res = {
                    "error": True,
                    "message": 'ERROR: Unable to open file ' +
                    key}
                return(res)

            try:
                x509obj = crypto.load_privatekey(
                    crypto.FILETYPE_PEM, keyfile.read(), keypass)
            except SSL.SysCallError as e:
                res = {"error": True, "message": e.strerror + " " + e.filename}
                #print(e.args, e.errno, e.filename, e.strerror)
            except SSL.Error as f:
                res = {"error": True, "message": f.strerror + " " + f.filename}
            except SSL.WantReadError as r:
                res = {"error": True, "message": r.strerror + " " + r.filename}
            except SSL.WantWriteError as w:
                res = {"error": True, "message": w.strerror + " " + w.filename}
            except SSL.WantX509LookupError as x:
                res = {"error": True, "message": x.strerror + " " + x.filename}
            except Exception as ex:
                print(ex)
                res = {"error": True,
                       "message": "ERROR: Unable to load private key {}".format(str(key))
                       }
            except:
                res = {"error": True, "message": "Unexpected error"}
            else:
                res = {"error": False, "message": x509obj}
            finally:
                return(res)

    def load_crt(self, crt):
        '''
        Load certificate file content to openssl x509 object.

        :param crt: Certificate file path.
        :type crt: String.

        :returns: Informational result dict {'error': Boolean, 'message': if error String else x509 object}
        :rtype: Dict.
        '''

        try:
            x509obj = crypto.load_certificate(
                crypto.FILETYPE_PEM, open(crt).read())
        except SSL.SysCallError as e:
            res = {"error": True, "message": e.strerror + " " + e.filename}
            #print(ex.args, ex.errno, ex.filename, ex.strerror)
        except SSL.Error as f:
            res = {"error": True, "message": f.strerror + " " + f.filename}
        except SSL.WantReadError as r:
            res = {"error": True, "message": r.strerror + " " + r.filename}
        except SSL.WantWriteError as w:
            res = {"error": True, "message": w.strerror + " " + w.filename}
        except SSL.WantX509LookupError as x:
            res = {"error": True, "message": x.strerror + " " + x.filename}
        except Exception as ex:
            res = {"error": True, "message": ex.strerror + " " + ex.filename}
        except:
            res = {"error": True, "message": "Unexpected error"}
        else:
            res = {"error": False, "message": x509obj}
        finally:
            return(res)

    def renew_crl_date(self, next_crl_days=183):
        '''
        Extend crl expiry date and/or renwew crl

        :param next_crl_days: Number of days to add for CRL expiry.
        :type next_crl_days: Int.

        :returns: Informational result dict {'error': Boolean, 'message': String}
        :rtype: Dict.
        '''

        crlObj = self.load_crl(self.__crlpath)
        if not crlObj['error']:
            crlObj = crlObj['message']
        else:
            res = {"error": True, "message": crlObj['message']}
            return(res)

        caKeyObj = self.load_pkey(
            self.__intermediateCAkeyfile,
            self.__intermediatePass)
        if not caKeyObj['error']:
            caKeyObj = caKeyObj['message']
        else:
            res = {"error": True, "message": caKeyObj['message']}
            return(res)

        caCertObj = self.load_crt(self.__intermediateCAcrtfile)
        if not caCertObj['error']:
            caCertObj = caCertObj['message']
        else:
            res = {"error": True, "message": caCertObj['message']}
            return(res)

        try:
            encodedCrl = crlObj.export(
                caCertObj,
                caKeyObj,
                days=next_crl_days,
                digest=self.__CRL_ALGO.encode('utf-8')).decode('utf-8')
            wresult = self.writeFile(self.__crlpath, encodedCrl)
            if wresult['error']:
                res = {"error": True, "message": wresult['message']}
                return(res)
        except:
            res = {
                "error": True,
                "message": "ERROR: Unable to edit crl: " +
                self.__crlpath}
            return(res)

        res = {"error": False, "message": "INFO: CRL date updated successfuly."}
        return(res)

    def update_revokeDB(self, serial, name, date, reason):
        '''
        Update revoked field in pki database.

        :param serial: Certificate serial number.
        :type serial: int.

        :param name: Certificate Common Name.
        :type name: str.

        :param date: Certificate revocation date.
        :type date: str.

        :param reason: Certificate revocation reason.
        :type reason: str.

        :returns: Informational result dict {'error': Boolean, 'message': String}
        :rtype: Dict.
        '''

        infos = {'cn': name, 'date': date, 'reason': reason}

        jsondict = self.json2dict(self.__DBfile)
        if not jsondict['error']:
            jsondict = jsondict['message']
        else:
            res = {
                "error": True,
                "message": "ERROR: Unable to read pki database " +
                self.__DBfile +
                "."}
            return(res)

        if 'revoked' not in jsondict:
            jsondict['revoked'] = {}

        jsondict['revoked'][serial] = infos
        json_out = jsonDump(jsondict, sort_keys=False)
        wresult = self.writeFile(self.__DBfile, json_out)
        if not wresult['error']:
            res = {"error": False, "message": wresult['message']}
            return(res)
        else:
            res = {"error": True, "message": wresult['message']}
            return(res)

    def revoke_cert(
            self,
            certname,
            next_crl_days=183,
            reason='unspecified',
            date=False,
            renewal=False):
        '''
        Revoking certificat in the PKI by it's name: removing files,
        regenerating crl and updating certificat status in pki database.

        :param certname: Certificaten name in PKI.
        :type certname: String.

        :param next_crl_days: Number of days to add for CRL expiry due to the CRL update.
        :type next_crl_days: Int.

        :param reason: Certificate revocation reason to set in the CRL. Must be in
            [unspecified, keyCompromise, CACompromise, affiliationChanged,
             superseded, cessationOfOperation, certificateHold].
        :type reason: Bytes.

        :param date: Date to reach for considering the certificate revoked (Format: "%d/%m/%Y"). If not specified, the revocation comes immediately.
        :type date: String.

        :param renewal: Specify if the revocation is called for a certificate renewal process.
        :type renewal: bool

        :returns: Informational result dict {'error': Boolean, 'message': String}
        :rtype: Dict.
        '''

        typeCert = self.reqType(certname)
        if not typeCert['error']:
            typeCert = typeCert['message']
        else:
            res = {
                "error": True,
                "message": "ERROR: Unable to find certificate type for " +
                certname +
                " --> " +
                typeCert['error']}
            return(res)

        if typeCert == 'SRV':
            CRTdir = self.__srvCRTdir
        elif typeCert == 'CLT':
            CRTdir = self.__cltCRTdir
        else:
            CRTdir = self.__srvCRTdir

        filespath = CRTdir + '/' + certname + '/' + certname
        revokedcert = filespath + '.crt'

        if ospath.isfile(revokedcert):
            # check if this cert is revoked
            validity, valreason = self.chk_validity(certname)
            if not research("has been revoked", valreason):
                reasons_lst = [
                    b"unspecified",
                    b"keyCompromise",
                    b"CACompromise",
                    b"affiliationChanged",
                    b"superseded",
                    b"cessationOfOperation",
                    b"certificateHold",
                    # b"removeFromCRL",
                ]
                if reason.encode('utf-8') not in reasons_lst:
                    res = {
                        "error": True,
                        "message": "ERROR: Bad reason '" +
                        reason +
                        "'. Please use normalized reason: [unspecified, keyCompromise, CACompromise, affiliationChanged, superseded, cessationOfOperation, certificateHold]"}
                    return(res)

                crlObj = self.load_crl(self.__crlpath)
                if not crlObj['error']:
                    crlObj = crlObj['message']
                else:
                    res = {"error": True, "message": crlObj['message']}
                    return(res)

                revokedObj = crypto.Revoked()

                caKeyObj = self.load_pkey(
                    self.__intermediateCAkeyfile,
                    self.__intermediatePass)
                if not caKeyObj['error']:
                    caKeyObj = caKeyObj['message']
                else:
                    res = {"error": True, "message": caKeyObj['message']}
                    return(res)

                caCertObj = self.load_crt(self.__intermediateCAcrtfile)
                if not caCertObj['error']:
                    caCertObj = caCertObj['message']
                else:
                    res = {"error": True, "message": caCertObj['message']}
                    return(res)

                certObj = self.load_crt(revokedcert)
                if not certObj['error']:
                    certObj = certObj['message']
                else:
                    res = {"error": True, "message": certObj['message']}
                    return(res)

                db_sn = certObj.get_serial_number()
                # to put in the crl in hexa
                serial_number = "%x" % db_sn
                # to put in str in  pkidb
                db_sn = str(db_sn)

                now = datetime.utcnow()
                if not date:
                    revokeDate_str = now.strftime('%Y%m%d%H%M%SZ')
                else:
                    date = str(date) + " 23:59:59"
                    try:
                        revokeDate_str = datetime.strptime(
                            date, "%d/%m/%Y %H:%M:%S").strftime('%Y%m%d%H%M%SZ')
                    except ValueError as err:
                        #res = {"error": True, "message": "ERROR:" + str(err)}
                        res = {
                            "error": True,
                            "message": "ERROR: Invalid date format. Must be in dd/mm/yyyy."}
                        return(res)

                revokedObj.set_serial(serial_number.encode('utf-8'))
                revokedObj.set_reason(reason.encode('utf-8'))
                revokedObj.set_rev_date(
                    revokeDate_str.encode('utf-8'))   # revoked as of now

                crlObj.add_revoked(revokedObj)
                try:
                    encodedCrl = crlObj.export(
                        caCertObj,
                        caKeyObj,
                        days=next_crl_days,
                        digest=self.__CRL_ALGO.encode('utf-8')).decode('utf-8')
                except:
                    res = {
                        "error": True,
                        "message": "ERROR: Unable to export new crl: " +
                        self.__crlpath}
                    return(res)
                try:
                    wresult = self.writeFile(self.__crlpath, encodedCrl)
                    if wresult['error']:
                        res = {"error": True, "message": wresult['message']}
                        return(res)
                except:
                    res = {
                        "error": True,
                        "message": "ERROR: Unable to write crl: " +
                        self.__crlpath}
                    return(res)

                if self.__verbose:
                    print("INFO: CRL updated successfuly.")

                # mise a jour de la db pki
                pkidb = self.json2dict(self.__DBfile)
                if not pkidb['error']:
                    pkidb = pkidb['message']
                else:
                    res = {
                        "error": True,
                        "message": "ERROR: Unable to read Serial database " +
                        self.__DBfile +
                        "."}
                    return(res)

                rcertbname = ospath.basename(revokedcert)
                origrcertname = ospath.splitext(rcertbname)[0]
                rcertname = self.cleanStr(origrcertname)
                pkidb[rcertname]['state'] = 'revoked'
                pkidb[rcertname]['reason'] = reason
                newjson = jsonDump(pkidb, sort_keys=False)
                wresult = self.writeFile(self.__DBfile, newjson)
                if wresult['error']:
                    res = {"error": True, "message": wresult['message']}
                    return(res)
                if self.__verbose:
                    print("INFO: Pki db file updated.")

                if not renewal:
                    # suppression du directory du certif revoked
                    rcertdir = ospath.dirname(revokedcert)
                    if ospath.exists(rcertdir):
                        for root, dirs, files in oswalk(
                                rcertdir, topdown=False):
                            for name in files:
                                remove(ospath.join(root, name))
                            for name in dirs:
                                rmdir(ospath.join(root, name))
                        rmdir(rcertdir)
                        if self.__verbose:
                            print(
                                "INFO: All files from the revoked certificate " +
                                origrcertname +
                                " are deleted.")

                updateDB = self.update_revokeDB(
                    db_sn, certname, revokeDate_str, reason)
                if updateDB['error']:
                    res = {
                        "error": True,
                        "message": updateDB['message']}
                    return(res)

                res = {
                    "error": False,
                    "message": "INFO: Certificate " +
                    origrcertname +
                    " revoked."}
                return(res)
            else:
                res = {
                    "error": False,
                    "message": "WARN: Certificate " +
                    origrcertname +
                    " already revoked"}
                return(res)
        else:
            validity, valreason = self.chk_validity(certname)
            if research("has been revoked", valreason):
                res = {
                    "error": False,
                    "message": "WARN: Certificate " +
                    certname +
                    " already revoked"}
                return(res)
            else:
                res = {
                    "error": True,
                    "message": "ERROR: Certificate " +
                    certname +
                    " doesn't exists"}
                return(res)

    def create_cert(
            self,
            country='',
            state='',
            city='',
            org='',
            ou='',
            cn='',
            email='',
            ca=False,
            valid_before=0,
            days_valid=False,
            subjectAltName=None,
            KeyPurpose=False,
            KeyUsage=False,
            encryption=False,
            ocspURI=False,
            CRLdp=False,
            toRenew=False):
        '''
        Create a X509 signed certificate.

        :param country: Certificate country information.
        :type country: String.

        :param state: Certificate state information.
        :type state: String.

        :param city: Certificate city information.
        :type city: String.

        :param org: Certificate organization information.
        :type org: String.

        :param ou: Certificate organization unit information.
        :type ou: String.

        :param email: Certificate administrator e-mail information.
        :type email: String.

        :param subjectAltName: Certificate Subject Alt-names extension. Must be in this format [ 'type:value' ] and types are 'email', 'URI', 'IP', 'DNS'.
        :type subjectAltName: List of str.

        :param cn: Certificate Common Name.
        :type cn: String.

        :param encryption: Certificate encryption (SHA1/SHA256/SHA512).
        :type encryption: String.

        :param ca: Indicate if the key will be use to generate a CA type certificate.
        :type ca: Boolean.

        :param valid_before: Allow to generate a certificate which will be
                             valid (from now) in number of days in the future.
        :type valid_before: Int.

        :param days_valid: Define the periode, in days, during which the certfiicate will be valid. If valid_before is specified the validity will start at valid_before time .
        :type days_valid: Int.

        :param KeyPurpose: Define the certificate usage purpose. Could be for server (serverAuth) or client authentication(clientAuth), if not specified, the certificate will support both.
        :type KeyPurpose: String.

        :param KeyUsage: Define the certificate usage. Could be [digitalSignature, nonRepudiation, contentCommitment, keyEncipherment, dataEncipherment, keyAgreement, keyCertSign, cRLSign, encipherOnly, decipherOnly
], if not specified, the certificate will bear keyEncipherment and dataEncipherment.
        :type KeyUsage: String.

        :param ocspURI: Certificate authorityInfoAccess(OCSP) extension. Must be in this format [ 'val;type:value' ] where val can be (caIssuers|OCSP) and types are 'URI', 'IP' or 'DNS'.
        :type ocspURI: List of str.

        :param CRLdp: Certificate crlDistributionPoints extension. Must be in this format [ 'type:value' ] and types are 'URI', 'IP' or 'DNS'.
        :type CRLdp: List of str.

        :param toRenew: Allow to specify that we want to renew the certificate without revoking but replacing the current one.
        :type toRenew: Boolean.

        :returns: Informational result dict {'error': Boolean, 'message': String}
        :rtype: Dict.
        '''

        if country == '':
            country = self.__C
        if state == '':
            state = self.__ST
        if city == '':
            city = self.__L
        if org == '':
            org = self.__O
        if ou == '':
            ou = self.__OU
        if email == '':
            email = self.__adminEmail

        currentDate = datetime.utcnow().strftime('%Y/%m/%d %H:%M:%S')
        tocreate = False

        if ca and ca != 'intermediate':
            keypath = self.__rootCAkeyfile
            certfile = self.__rootCAcrtfile
            if ospath.isfile(certfile) and not toRenew:
                res = {
                    "error": False,
                    "message": "WARN: Certificate " +
                    certfile +
                    " has already been generated. Doing nothing !"}
                return(res)

            opsslObjKey = self.load_pkey(keypath, self.__caPass)
            if not opsslObjKey['error']:
                opsslObjKey = opsslObjKey['message']
            else:
                res = {"error": True, "message": opsslObjKey['message']}
                return(res)
        elif ca == 'intermediate':
            keypath = self.__intermediateCAkeyfile
            certfile = self.__intermediateCAcrtfile
            if ospath.isfile(certfile) and not toRenew:
                res = {
                    "error": False,
                    "message": "WARN: Certificate " +
                    certfile +
                    " has already been generated. Doing nothing !"}
                return(res)
            opsslObjKey = self.load_pkey(keypath, self.__intermediatePass)
            if not opsslObjKey['error']:
                opsslObjKey = opsslObjKey['message']
            else:
                res = {"error": True, "message": opsslObjKey['message']}
                return(res)
        else:
            if not cn or cn == '':
                if subjectAltName:
                    passname = subjectAltName[0]
                    if not passname or passname == '':
                        res = {"error": True,
                               "message": 'ERROR: Unable to define owner name'}
                        return(res)
                    filename = self.cleanStr(passname)
                    # removing alt-name field prefix after cleaning
                    filename = resub('DNS_|IP_|URI_|email_', '', filename)
            else:
                passname = cn
                filename = cn

            # define key usage
            if KeyPurpose == "both" :
                typecrt = "SRV"
                KeyPurpose = "serverAuth, clientAuth"
                keydir = self.__srvCRTdir + "/" + filename
            elif KeyPurpose == "clientAuth":
                typecrt = "CLT"
                keydir = self.__cltCRTdir + "/" + filename
            else:
                typecrt = "SRV"
                keydir = self.__srvCRTdir + "/" + filename

            keypath = keydir + '/' + filename + '.key'
            certfile = keydir + '/' + filename + '.crt'

            if ospath.isfile(certfile) and not toRenew:
                res = {
                    "error": False,
                    "message": "WARN: Certificate " +
                    certfile +
                    " has already been generated. Doing nothing !"}
                return(res)

            # loading passDB to get passphrase
            passphrase = self.reqPass(passname)
            if passphrase['error']:
                res = {
                    'error': True,
                    'message': 'ERROR: Unable to retrieve passphrase, ' + passphrase['message'] + '. Exiting...'}
                return(res)
            else:
                privkeypass = passphrase['message']

            # flushing dictionnary
            if isinstance(passphrase['message'], dict):
                passphrase['message'].clear()
            else:
                passphrase['message'] = ''

            if not privkeypass or privkeypass == 'None':
                opsslObjKey = self.load_pkey(keypath)
                if not opsslObjKey['error']:
                    opsslObjKey = opsslObjKey['message']
                else:
                    res = {"error": True, "message": opsslObjKey['message']}
                    return(res)
            else:
                if isinstance(privkeypass, str):
                    privkeypass = privkeypass.encode('utf-8')

                opsslObjKey = self.load_pkey(keypath, privkeypass)
                if not opsslObjKey['error']:
                    opsslObjKey = opsslObjKey['message']
                else:
                    res = {"error": True, "message": opsslObjKey['message']}
                    return(res)

        SERIAL_NUMBER = self.getSN()
        if SERIAL_NUMBER['error']:
            res = {"error": True, "message": SERIAL_NUMBER['message']}
            return(res)
        else:
            SERIAL_NUMBER = SERIAL_NUMBER['message']

        if not isinstance(SERIAL_NUMBER, int):
            if research(
                "Serial database.+not found",
                    SERIAL_NUMBER) is not None:
                if not ca or rematch(
                    ".*intermediate.*",
                        certfile) or ca == 'intermediate':
                    if self.__verbose:
                        print(SERIAL_NUMBER)
                    message = "ERROR: Unable to get a certificate Serial Number, Removing assiociated key: " + keypath
                    try:
                        remove(keypath)
                    except:
                        message = "ERROR: Unable to remove " + keypath
                    res = {"error": True, "message": message}
                    return(res)
                else:
                    SERIAL_NUMBER = 1
                    tocreate = True
            else:
                res = {
                    "error": True,
                    "message": SERIAL_NUMBER +
                    " during generation of " +
                    certfile}
                return(res)

        cert = crypto.X509()

        cert.set_version(3 - 1)  # version 3, starts at 0
        cert.get_subject().C = country
        cert.get_subject().ST = state
        cert.get_subject().L = city
        cert.get_subject().O = org
        cert.get_subject().OU = ou
        if cn and not ca:
            cert.get_subject().CN = cn
        elif ca and ca != 'intermediate':
            cert.get_subject().CN = self.__localCN + '_CA_root'
        elif ca and ca == 'intermediate':
            cert.get_subject().CN = self.__localCN + '_CA_intermediate'
        cert.get_subject().emailAddress = email
        cert.set_serial_number(SERIAL_NUMBER)
        cert.set_pubkey(opsslObjKey)

        cert.gmtime_adj_notBefore(valid_before * 24 * 3600)
        if not days_valid:
            cert.gmtime_adj_notAfter(self.__VALID_DAYS * 24 * 3600)
        else:
            cert.gmtime_adj_notAfter(days_valid * 24 * 3600)

        if ca and ca != 'intermediate':
            issuerCertObj = cert
            issuerKeyObj = opsslObjKey
        elif ca == 'intermediate':
            issuerCertObj = self.load_crt(self.__rootCAcrtfile)
            if not issuerCertObj['error']:
                issuerCertObj = issuerCertObj['message']
            else:
                res = {"error": True, "message": issuerCertObj['message']}
                return(res)

            issuerKeyObj = self.load_pkey(self.__rootCAkeyfile, self.__caPass)
            if not issuerKeyObj['error']:
                issuerKeyObj = issuerKeyObj['message']
            else:
                res = {"error": True, "message": issuerKeyObj['message']}
                return(res)
        else:
            issuerCertObj = self.load_crt(self.__intermediateCAcrtfile)
            if not issuerCertObj['error']:
                issuerCertObj = issuerCertObj['message']
            else:
                res = {"error": True, "message": issuerCertObj['message']}
                return(res)

            issuerKeyObj = self.load_pkey(
                self.__intermediateCAkeyfile,
                self.__intermediatePass)
            if not issuerKeyObj['error']:
                issuerKeyObj = issuerKeyObj['message']
            else:
                res = {"error": True, "message": issuerKeyObj['message']}
                return(res)

        cert.set_issuer(issuerCertObj.get_subject())

        if ca:
            typecrt = "CA"
            if ca == 'intermediate':
                cert.add_extensions([
                                    crypto.X509Extension(
                                        b"basicConstraints", True, b"CA:TRUE, pathlen:0"),
                                    crypto.X509Extension(
                                        b"subjectKeyIdentifier", False, b"hash", subject=cert),
                                    crypto.X509Extension(
                                        b"keyUsage", True, b"digitalSignature, cRLSign, keyCertSign")
                                    ])
                # You must add this extension separatelty to allow pyOpenssl to
                # find subjectKeyIdentifier when setting authorityKeyIdentifier
                cert.add_extensions([crypto.X509Extension(
                    b"authorityKeyIdentifier", False, b"keyid:always,issuer", issuer=issuerCertObj)])
            else:
                cert.add_extensions([
                                    crypto.X509Extension(
                                        b"basicConstraints", True, b"CA:TRUE"),
                                    crypto.X509Extension(
                                        b"subjectKeyIdentifier", False, b"hash", subject=cert),
                                    crypto.X509Extension(
                                        b"keyUsage", True, b"digitalSignature, cRLSign, keyCertSign")
                                    ])
                # You must add this extension separatelty to allow pyOpenssl to
                # find subjectKeyIdentifier when setting authorityKeyIdentifier
                cert.add_extensions([crypto.X509Extension(
                    b"authorityKeyIdentifier", False, b"keyid:always,issuer", issuer=issuerCertObj)])

            # OCSP support addon
            cert.add_extensions([crypto.X509Extension(
                b"extendedKeyUsage",
                False,
                b"OCSPSigning")])
        else:
            cert.add_extensions([crypto.X509Extension(
                b"basicConstraints", False, b"CA:FALSE")])

            if KeyUsage:
                cert.add_extensions(
                    [
                        crypto.X509Extension(
                            b"keyUsage",
                            True,
                            KeyUsage.encode('utf-8')
                        )
                    ]
                )
            else:
                cert.add_extensions(
                    [
                        crypto.X509Extension(
                            b"keyUsage",
                            True,
                            #b"dataEncipherment, digitalSignature, nonRepudiation"),
                            b"keyEncipherment, dataEncipherment"
                        )
                    ]
                )

            if not KeyPurpose or KeyPurpose == "False":
                typecrt = "SRV"
            else:
                if KeyPurpose == "clientAuth":
                    typecrt = "CLT"
                elif KeyPurpose in ["serverAuth", "both"]:
                    typecrt = "SRV"
                cert.add_extensions(
                    [
                        crypto.X509Extension(
                            b"extendedKeyUsage",
                            True,
                            KeyPurpose.encode('utf-8')
                        )
                    ]
                )
        # OCSP support addon
        if ocspURI:
            try:
                uris = b", ".join(u.encode('utf-8')
                                          for u in ocspURI)
            except:
                res = {
                    "error": True,
                    "message": 'ERROR: Error parsing ocsp'}
                return(res)
            cert.add_extensions([crypto.X509Extension(
                b"authorityInfoAccess", False, uris)])

        # CRL distribution points addon
        if CRLdp:
            try:
                crlu = b", ".join(c.encode('utf-8')
                                          for c in CRLdp)
            except:
                res = {
                    "error": True,
                    "message": 'ERROR: Error parsing CRL distribution point URIs'}
                return(res)
            cert.add_extensions([crypto.X509Extension(
                b"crlDistributionPoints", False, crlu)])

        if subjectAltName:
            critical = True if not cn else False
            try:
                altnames = b",     ".join(s.encode('utf-8')
                                          for s in subjectAltName)
            except:
                res = {
                    "error": True,
                    "message": 'ERROR: Error parsing alt-names'}
                return(res)
            cert.add_extensions([crypto.X509Extension(
                b"subjectAltName", critical, altnames)])

        if not encryption:
            cert.sign(issuerKeyObj, self.__SIGN_ALGO)
        else:
            cert.sign(issuerKeyObj, encryption)

        dumpedCert = crypto.dump_certificate(
            crypto.FILETYPE_PEM, cert).decode('utf-8')
        wresult = self.writeFile(certfile, dumpedCert)
        if wresult['error']:
            res = {"error": True, "message": wresult['message']}
            return(res)
        else:
            if self.__HASH_ENC == 'sha1':
                shasum = hashlib.sha1(dumpedCert.encode('utf-8')).hexdigest()
            elif self.__HASH_ENC == '224':
                shasum = hashlib.sha224(dumpedCert.encode('utf-8')).hexdigest()
            elif self.__HASH_ENC == '256':
                shasum = hashlib.sha256(dumpedCert.encode('utf-8')).hexdigest()
            elif self.__HASH_ENC == '384':
                shasum = hashlib.sha384(dumpedCert.encode('utf-8')).hexdigest()
            elif self.__HASH_ENC == '512':
                shasum = hashlib.sha512(dumpedCert.encode('utf-8')).hexdigest()

            if tocreate:
                if not days_valid:
                    success = self.writeJsonCert(
                        sha=shasum,
                        serial=SERIAL_NUMBER,
                        date=currentDate,
                        duration=self.__VALID_DAYS,
                        state='activ',
                        certpath=certfile,
                        createMode=True,
                        typeCert=typecrt)
                else:
                    success = self.writeJsonCert(
                        sha=shasum,
                        serial=SERIAL_NUMBER,
                        date=currentDate,
                        duration=days_valid,
                        state='activ',
                        certpath=certfile,
                        createMode=True,
                        typeCert=typecrt)
                if success['error']:
                    res = {"error": True, "message": success['message']}
                    return(res)
            else:
                if not days_valid:
                    success = self.writeJsonCert(
                        sha=shasum,
                        serial=SERIAL_NUMBER,
                        date=currentDate,
                        duration=self.__VALID_DAYS,
                        state='activ',
                        certpath=certfile,
                        typeCert=typecrt)
                else:
                    success = self.writeJsonCert(
                        sha=shasum,
                        serial=SERIAL_NUMBER,
                        date=currentDate,
                        duration=days_valid,
                        state='activ',
                        certpath=certfile,
                        typeCert=typecrt)
                if success['error']:
                    return(False, success['message'])
                    res = {"error": True, "message": success['message']}
                    return(res)

        res = {"error": False, "message": "INFO: Certificate created."}
        return(res)

    def chk_conformity(self, cert):
        '''
        Check if the certificate has been generated by the currently installed  PKI. Looking in the pki database file)

        :param cert: Certificate file path to check.
        :type cert: String.

        :returns: Informational result dict {'error': Boolean, 'message': String}
        :rtype: Dict.
        '''

        rcertbname = ospath.basename(cert)
        rcertname = ospath.splitext(rcertbname)[0]
        rcertname = self.cleanStr(rcertname)
        pkidb = self.json2dict(self.__DBfile)
        if not pkidb['error']:
            pkidb = pkidb['message']
        else:
            res = {
                "error": True,
                "message": "ERROR: Unable to read Serial database " +
                self.__DBfile +
                "."}
            return(res)

        x509CertObj = self.load_crt(cert)
        if not x509CertObj['error']:
            x509CertObj = x509CertObj['message']
        else:
            res = {"error": True, "message": x509CertObj['message']}
            return(res)

        dumpedCert = crypto.dump_certificate(
            crypto.FILETYPE_PEM, x509CertObj).decode('utf-8')
        shaEncert = pkidb[rcertname]['shaenc']

        if shaEncert == 'sha1':
            shasumF = hashlib.sha1(dumpedCert.encode('utf-8')).hexdigest()
        elif shaEncert == '224':
            shasumF = hashlib.sha224(dumpedCert.encode('utf-8')).hexdigest()
        elif shaEncert == '256':
            shasumF = hashlib.sha256(dumpedCert.encode('utf-8')).hexdigest()
        elif shaEncert == '384':
            shasumF = hashlib.sha384(dumpedCert.encode('utf-8')).hexdigest()
        elif shaEncert == '512':
            shasumF = hashlib.sha512(dumpedCert.encode('utf-8')).hexdigest()

        if shasumF == pkidb[rcertname]['shasum']:
            res = {"error": False, "message": "INFO: The certificate " +
                   rcertbname + " is conform and has been generated by" +
                   " this pki"}
            return(res)
        else:
            res = {
                "error": False,
                "message": "WARN: The certificate " +
                rcertbname +
                " has not been generated by this pki"}
            return(res)

    def chk_validity(self, certname):
        '''
        Check certificate status, this will tell us if the certificate is expired or revoked.

        :param cert: Certificate file path to check.
        :type cert: String.

        :returns: Informational result dict {'error': Boolean, 'message': String}
        :rtype: Dict.
        '''

        typeCert = self.reqType(certname)
        if not typeCert['error']:
            typeCert = typeCert['message']
        else:
            res = {
                "error": True,
                "message": "ERROR: Unable to find certificate type for " +
                certname +
                " --> " +
                typeCert['message']}
            return(res)

        if typeCert == 'SRV':
            CRTdir = self.__srvCRTdir
        elif typeCert == 'CLT':
            CRTdir = self.__cltCRTdir
        else:
            CRTdir = self.__srvCRTdir

        filespath = CRTdir + '/' + certname + '/' + certname
        cert = filespath + '.crt'
        # if we do not find cert, trying to find it in signed dir
        if not ospath.isfile(cert):
            cert = self.__signeDir + '/' + certname + '/' + certname + '.crt'
        oriname = certname
        certname = self.cleanStr(certname)

        pkidb = self.json2dict(self.__DBfile)
        if not pkidb['error']:
            pkidb = pkidb['message']
        else:
            res = {
                "error": True,
                "message": "ERROR: Unable to read Serial database " +
                self.__DBfile +
                "."}
            return(res)

        x509CertObj = self.load_crt(cert)
        if not x509CertObj['error']:
            x509CertObj = x509CertObj['message']
        else:
            res = {"error": True, "message": x509CertObj['message']}
            return(res)

        if pkidb[certname]['state'] == 'revoked':
            res = {
                "error": False,
                "message": "WARN: This certificate has been revoked with the reason: " +
                pkidb[certname]['reason']}
            return(res)
        else:
            if x509CertObj.has_expired():
                res = {
                    "error": False,
                    "message": "WARN: The certificate " +
                    oriname +
                    " is not revoked but has expired"}
                return(res)
            else:
                res = {
                    "error": False,
                    "message": "INFO: The certificate " +
                    oriname +
                    " is valid from " +
                    self.gt_to_dt(
                        x509CertObj.get_notBefore()) +
                    " to " +
                    self.gt_to_dt(
                        x509CertObj.get_notAfter())}
                return(res)

    def get_srvCRTdir(self):
        return(self.__srvCRTdir)

    def get_cltCRTdir(self):
        return(self.__cltCRTdir)

    def get_crtsDir(self):
        return(self.__crtsDir)

    def get_csrDir(self):
        return(self.__csrDir)

    def get_crl_path(self):
        return(self.__crlpath)

    def get_initPkey(self):
        if self.__initPkey:
            return(self.__initPkey)
        else:
            return("INFO: Authentication already done..")

    def get_namelist(self):
        '''
        Return a list of all certificate names present in the database file.

        :returns: Informational result dict {'error': Boolean, 'message': String}
        :rtype: Dict.
        '''

        result = self.json2dict(self.__DBfile)
        names = []
        if not result['error']:
            for key, value in result['message'].items():
                if key != 'revoked':
                    if value['state'] != 'revoked':
                        names.append(value['cn'])
            return(names)
        else:
            return(result['error'])

    def read_pkidb(self):
        '''
        Return the certificate database file content

        :returns: Informational result dict {'error': Boolean, 'message': if error String else List of string}
        :rtype: Dict.
        '''

        result = self.json2dict(self.__DBfile)
        if not result['error']:
            return(result['message'])
        else:
            return(result['error'])

    def remove_lockf(self, message):
        '''
        Remove pki lock file.

        :param message: Message to print when removing lock file.
                        This message will be only printed if verbose mode is enabled.
        :type message: String.

        :returns: Informational result dict {'error': Boolean, 'message': String}
        :rtype: Dict.
        '''

        if self.__lockfile and self.__lockfile != "":
            if self.__Ilocked and self.__locked:
                if ospath.exists(self.__lockfile):
                    try:
                        remove(self.__lockfile)
                    except OSError as e:
                        if e.errno != errno.ENOENT:  # errno.ENOENT = no such file or directory
                            raise  # re-raise exception if a different error occured
                            print("WARNING: Unable to unlock the PKI...")
                    else:
                        # retourne le nom de la classe
                        #class_name = self.__class__.__name__
                        self.__alreadyUnlocked = True
                        if self.__verbose:
                            print(message)

    def set_verbosity(self, val):
        self.__verbose = val

    def set_pkeysize(self, val):
        self.__KEY_SIZE = val

    def set_crtenc(self, val):
        self.__SIGN_ALGO = val

    def set_keycipher(self, val):
        self.__KEY_CIPHER = val

    def set_crlenc(self, val):
        self.__CRL_ALGO = val

    srvCRTdir = property(
        get_srvCRTdir,
        None,
        None,
        "Get the directory path for server certificates")
    cltCRTdir = property(
        get_cltCRTdir,
        None,
        None,
        "Get the directory path for client certificates")
    crtsDir = property(
        get_crtsDir,
        None,
        None,
        "Get the directory path for the pki certificates")
    csrDir = property(
        get_csrDir,
        None,
        None,
        "Get the directory path for the pki request")
    crl_path = property(
        get_crl_path,
        None,
        None,
        "Get the CRL path of the PKI")
    initPkey = property(
        get_initPkey,
        None,
        None,
        "Retrieve authentication private key only at first init")
    pkidbDict = property(read_pkidb, None, None, "Get pki db in a dict")
    nameList = property(
        get_namelist,
        None,
        None,
        "Retrieve list of certificates names")
    pkeysize = property(None, set_pkeysize, None, "Define private key size")
    crtenc = property(
        None,
        set_crtenc,
        None,
        "Define certificate encryption algorithm")
    keycipher = property(
        None,
        set_keycipher,
        None,
        "Define private key passphrase cipher encyption")
    crlenc = property(
        None,
        set_crlenc,
        None,
        "Define crl encryption algorithm")

    def __del__(self):
        '''
        This destructor will be called when using: del 'class_object' in python2
        Automatically called in python3, the same way we are using __init__, we are using __del__
        '''

        endinit = False
        alreadyUnlocked = False
        lockfile = False
        Ilocked = False
        locked = False
        verbose = False

        # if not self.__init:
        if hasattr(self, '_PyKI__endinit'):
            endinit = True
        if hasattr(self, '_PyKI__alreadyUnlocked'):
            alreadyUnlocked = True
        if hasattr(self, '_PyKI__lockfile'):
            lockfile = True
        if hasattr(self, '_PyKI__Ilocked'):
            Ilocked = True
        if hasattr(self, '_PyKI__locked'):
            locked = True
        if hasattr(self, '_PyKI__verbose'):
            verbose = True

        if endinit and alreadyUnlocked:
            if self.__endinit and not self.__alreadyUnlocked:
                if lockfile:
                    if self.__lockfile and self.__lockfile != "" and self.__lockfile is not None:
                        if Ilocked and locked:
                            try:
                                if ospath.exists(self.__lockfile):
                                    if self.__Ilocked and self.__locked:
                                        try:
                                            remove(self.__lockfile)
                                        except:
                                            print(
                                                "WARNING: Unable to unlock the PKI...")
                                        else:
                                            # retourne le nom de la classe
                                            #class_name = self.__class__.__name__
                                            if verbose:
                                                if self.__verbose:
                                                    print(
                                                        "INFO: PKI unlocked.")
                                elif not self.__Ilocked and self.__locked:
                                    pass
                                else:
                                    print(
                                        "WARNING: Unable to unlock the PKI, lock file not found.")
                            except:
                                # to avoid premature exits with os.path.exists
                                if self.__Ilocked and self.__locked:
                                    try:
                                        remove(self.__lockfile)
                                    except:
                                        print(
                                            "WARNING: Unable to unlock the PKI...")
                                    else:
                                        # retourne le nom de la classe
                                        #class_name = self.__class__.__name__
                                        if verbose:
                                            if self.__verbose:
                                                print("INFO: PKI unlocked.")
                    else:
                        pass

if __name__ == '__main__':
    pass
