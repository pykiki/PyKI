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

import random
import string
import argparse
from datetime import datetime, timedelta

# Part for integrating init directory as a library
from sys import path as syspath, argv
from os import path as ospath
curScriptDir = ospath.dirname(ospath.abspath(__file__))
initPath = curScriptDir + "/PyKInit/"
syspath.append(initPath)
from PyKInit import pkinit


def argCommandline(argv):
    """
    Manage cli script args
    """

    parser = argparse.ArgumentParser(description='Generate PKI certificates')
    parser.add_argument(
        "-n",
        "--cn",
        action="store",
        dest="cn",
        type=str,
        help=u"Certificate common name",
        metavar='Common Name',
        required=True)
    parser.add_argument(
        "-r",
        "--renew",
        action='store_true',
        dest="renewing",
        help=u"Indicates that we want to renew the certificate and not create a new one with a new private key",
        required=False)
    parser.add_argument(
        "-c",
        "--country",
        action='store',
        dest="c",
        type=str,
        default='',
        help=u"Country Name (2 letter code) eg. US",
        metavar='XX',
        required=False)
    parser.add_argument(
        "-st",
        "--state",
        action='store',
        dest="st",
        type=str,
        default='',
        help=u"State or Province Name (full name)",
        metavar='state',
        required=False)
    parser.add_argument(
        "-l",
        "--city",
        action='store',
        dest="l",
        type=str,
        default='',
        help=u"Locality Name (eg, city)",
        metavar='city',
        required=False)
    parser.add_argument(
        "-o",
        "--organization",
        action='store',
        type=str,
        dest="o",
        default='',
        help=u"Organization Name (eg, company)",
        metavar='Organization',
        required=False)
    parser.add_argument(
        "-ou",
        "--org-unit",
        action='store',
        dest="ou",
        type=str,
        default='',
        help=u"Organizational Unit Name (eg, section)",
        metavar='org unit',
        required=False)
    parser.add_argument(
        "-e",
        "--email",
        action='store',
        dest="email",
        type=str,
        default='',
        help=u"Email Address",
        metavar='nobody@domain.com',
        required=False)
    parser.add_argument(
        "-a",
        "--altnames",
        action='store',
        dest="subjectAltName",
        nargs='*',
        type=str,
        metavar='type:value',
        default=False,
        help=u"X509 extension Subject Alternative-names (eg, IP:1.2.3.4 DNS:www.toto.net URI: www.toto.net)",
        required=False)
    parser.add_argument(
        "-p",
        "--purpose",
        action='store',
        dest="purpose",
        type=str,
        default='server',
        metavar='client|server',
        choices=[
            'server',
            'client'],
        help=u"Select which type of use is required for the certificate",
        required=True)
    parser.add_argument(
        "-s",
        "--passphrase",
        action='store',
        dest="passwd",
        type=str,
        default=False,
        help=u"Private key passphrase",
        metavar='mypassphrase',
        required=False)
    parser.add_argument(
        "-v",
        "--verbose",
        action='store_true',
        dest='mainVerbosity',
        help=u"Add output verbosity",
        required=False)
    parser.add_argument(
        "-t",
        "--key-size",
        action='store',
        dest="size",
        type=int,
        default=False,
        help=u"Private key size int value",
        metavar='XXXX',
        choices=[
            1024,
            2048,
            4096,
            8192],
        required=False)
    parser.add_argument(
        "-d",
        "--duration",
        action='store',
        dest="duration",
        type=int,
        default=360,
        help=u"Number of days for certificate validity period",
        metavar='X',
        required=False)
    parser.add_argument(
        "-b",
        "--end-date",
        action='store',
        dest="endays",
        type=int,
        default=False,
        metavar='X',
        help=u"Define a number of days before the current certificate will be revoked.",
        required=False)

    args = parser.parse_args()

    # print help if no arguments given
    if len(argv) <= 1:
        parser.print_help()
        exit(1)

    result = vars(args)

    return(result)


def codegenerator(pwlen=25, alphabet=False):
    if not alphabet:
        #alphabet = string.printable
        alphabet = string.digits + string.ascii_letters + string.punctuation

    pw_length = pwlen
    mypw = ""

    for i in range(pw_length):
        next_index = random.randrange(len(alphabet))
        mypw = mypw + alphabet[next_index]
    return(mypw)


def genCert(name, pki, passphrase, usage, altnames=False,
            size=False, certenc=False, days=False, renew=False,
            country=False, state=False, city=False, org=False,
            ou=False, email=False, endays=False
            ):
    '''
    tools Generatin key and certificate
    '''

    if renew:
        if name not in pki.nameList:
            print('ERROR: Certificate ' + name + " doesn't exist, unable to renew it.")
            return(1)

        if endays:
            currentDate = datetime.utcnow()
            #try:
            #    createDateTime = datetime.strptime(endays, "%d/%m/%Y")
            #except ValueError as err:
            #    print("ERROR:" + str(err))
            #    return(1)

            ## get timedelta object
            #timeDelta = createDateTime - currentDate
            ## get timedelta in days
            #deltadays = timeDelta.days + 1
            deltadate = currentDate + timedelta(days=endays)
            deltadate = deltadate.strftime("%d/%m/%Y")

            crl = pki.revoke_cert(certname=name, reason='superseded', date=deltadate, renewal=True)
        else:
            crl = pki.revoke_cert(certname=name, reason='superseded', renewal=True)

        print(crl['message'])
        if crl['error']:
            return(1)
        else:
            print("INFO: You current certificate for " + name + " will be revoked in "+ str(endays) + " days.")

        print("INFO: Generating certificate whith alt-names...")
        cert = pki.create_cert(
            country=country, state=state, city=city,
            org=org, ou=ou,
            email=email,
            KeyUsage=usage,
            subjectAltName=altnames,
            cn=name,
            encryption=certenc,
            #valid_before=deltadays,
            days_valid=days,
            toRenew=renew
        )
        if cert['error']:
            print(cert['message'] + ", aborting...")
            res = False
        else:
            print(cert['message'])
            print("INFO: Please remember to install your new certificate for " + name + " before the current one expires.")
            res = True
    else:
        print("INFO: Generating server private key for " + name + "...")
        key = pki.create_key(
            passphrase=passphrase,
            keysize=size,
            name=name,
            usage=usage)
        if key['error']:
            print(key['message'] + ", aborting...")
            return(False)
        else:
            print("INFO: Key " + name + " done.")

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
        if cert['error']:
            print(cert['message'] + ", aborting...")
            res = False
        else:
            print(cert['message'])
            res = True

    return(res)

if __name__ == '__main__':
    # get cli args
    args = argCommandline(argv)

    # init pki
    pki = pkinit()
    if not pki:
        print("ERROR: Errors found during init")
        exit(1)

    # Set pki verbosity after init
    pki.set_verbosity(args['mainVerbosity'])

    if args['subjectAltName'] and not 'DNS:' + \
            args['cn'] in args['subjectAltName']:
        args['subjectAltName'].insert(0, 'DNS:' + args['cn'])

    if args['cn'] not in pki.nameList:
        args['renewing'] = False

    if not args['passwd'] and not args['renewing']:
        args['passwd'] = codegenerator(pwlen=26)

    if args['purpose'] == "server":
        args['purpose'] = 'serverAuth'
    else:
        args['purpose'] = 'clientAuth'

    if args['endays'] and not args['renewing']:
        args['endays'] = False

    genCert(
        name=args['cn'],
        pki=pki,
        passphrase=args['passwd'],
        altnames=args['subjectAltName'],
        size=args['size'],
        usage=args['purpose'],
        days=args['duration'],
        renew=args['renewing'],
        country=args['c'],
        state=args['st'],
        city=args['l'],
        org=args['o'],
        ou=args['ou'],
        email=args['email'],
        endays=args['endays'])
    exit(0)
