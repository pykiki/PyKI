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
from getpass import getpass
import argparse
from PyKI import PyKI

# Part for integrating init directory as a library
from sys import path as syspath, argv
from os import path as ospath
curScriptDir = ospath.dirname(ospath.abspath(__file__))
initPath = curScriptDir + "/PyKInit/"
syspath.append(initPath)
from PyKInit import pkinit

def argCommandline(argv):
    """ gestion des arguments ligne de commande """

    result={}

    parser = argparse.ArgumentParser(description='Script to show how to use argparse module')
    parser.add_argument("-n", "--cn", action="store", dest="cn", help=u"Certificate common name", required=True)
    parser.add_argument("-l", "--list-user-hno", action='store_true', dest="listuserhno", default=False, help=u"Show pubkey's HNO user", required=False)
    parser.add_argument("-v", "--verbose", action='store_true', dest='verboseMode', default=False, help=u"Add verbosity")

    args = parser.parse_args()

    if args.listuserhno is True:
        result['list-user-hno'] = True
    if args.verboseMode:
        result['verbose'] = args.verboseMode
    if args.cn:
        result['cn'] = args.cn

    nbargs = len(result)
    if nbargs < 1:
        parser.print_help()
        exit(1)

    return(result)

def codegenerator(pwlen = 25, alphabet = False):
    if not alphabet:
        #alphabet = string.printable
        alphabet = string.digits + string.ascii_letters + string.punctuation

    pw_length = pwlen
    mypw = ""

    for i in range(pw_length):
        next_index = random.randrange(len(alphabet))
        mypw = mypw + alphabet[next_index]
    return mypw

def genCert(name, pki, passphrase, usage, altnames = False,
            size = False, certenc = False, days = False, renew=False,
            country=False, state=False, city=False, org=False,
            ou=False, email=False
           ):
    '''
    tools Generatin key and certificate
    '''

    print("INFO: Generating server private key for "+name+"...")
    key = pki.create_key(passphrase=passphrase, keysize = size, name = name, usage = usage)
    if key['error'] :
        print(key['message']+", aborting...")
        return(False)
    else:
        print("INFO: Key "+name+" done.")

    print("INFO: Generating certificate whith alt-names...")
    cert = pki.create_cert(
                            country=country, state=state, city=city,
                            org=org, ou=ou,
                            email=email,
                            KeyUsage=usage,
                            subjectAltName=altnames,
                            cn=name,
                            encryption=certenc,
                            days_valid=days,
                            toRenew=renew
                          )
    if cert['error'] :
        print(cert['message']+", aborting...")
        res=False
    else:
        print(cert['message'])
        res=True

    return(res)

if __name__ == '__main__':
    mainVerbosity = False
    passwd = None
    subjectAltName = None
    renewing=False

    args = argCommandline(argv)
    print(args)
    exit(1)

    pki=pkinit()
    if not pki:
        print("ERROR: Errors found during init")
        exit(1)

    # Set pki verbosity after init
    pki.set_verbosity(mainVerbosity)

    # ---- section a passer par param ---- #
    c= 'US'
    st= 'District Of Columbia'
    l= 'Washington'
    o= 'Ritano Corp'
    ou= 'IT ritano'
    email = 'alain@ritano.fr'

    #purpose = 'server'
    #cn = "PyKIflask"
    # Options are 'email', 'URI', 'IP', 'DNS'
    #subjectAltName = ['DNS:MBP.local', 'DNS:mbp.local.net', 'IP:172.17.22.35', 'IP:127.0.0.1', 'DNS:localhost']
    #subjectAltName = ['DNS:'+cn, 'DNS:localhost', 'URI:172.17.22.35']

    # to specify that we want to renew the certificate
    renewing=True
    purpose = 'client'
    cn = 'client_vpnKimsufi'
    #passwd = 'azerty'
    # ---- fin section a passer par param ---- #

    if cn not in pki.nameList:
        renewing=False

    if not passwd and not renewing:
        passwd = codegenerator(pwlen = 26)

    if purpose == "server":
        duration = 730
        genCert(name = cn, pki = pki, passphrase = passwd, altnames = subjectAltName, size = 8192, usage = 'serverAuth' , days = duration, renew=renewing,
                country=c , state=st , city=l , org=o , ou=ou , email=email
               )
    else:
        duration = 365
        genCert(name=cn, pki=pki, passphrase=passwd, size=4096, usage='clientAuth', days=duration, renew=renewing,
                country=c , state=st , city=l , org=o , ou=ou , email=email
               )
    exit(0)
