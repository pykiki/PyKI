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
import argparse
from PyKI import PyKI

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
    parser = argparse.ArgumentParser(description='Get PKI database informations in Human Readable format.')
    parser.add_argument("-v", "--verbose", action='store_true', dest='mainVerbosity', help=u"Add output verbosity", required=False)
    args = parser.parse_args()

    result=vars(args)
    return(result)

if __name__ == '__main__':
    args=argCommandline(argv)

    pki=pkinit()
    if not pki:
        print("ERROR: Errors found during init")
        exit(1)
    pki.set_verbosity(args['mainVerbosity'])

    pkidb = pki.pkidbDict

    # for sorting names befor printing datas
    certsname = []
    for certname in pkidb:
        certsname.append(certname)
    # sort list insensitively
    certsname.sort(key=lambda x: x.lower())

    # process name list to print datas
    for name in certsname:
        status = pkidb[name]['state']
        serial = pkidb[name]['serial']
        validity_time = pkidb[name]['duration']
        cert_shasum = pkidb[name]['shasum']
        cert_usage = pkidb[name]['type']
        if cert_usage == 'CLT':
            cert_usage = 'client authentication'
        elif cert_usage == "SRV":
            cert_usage = 'server authentication'
        hash_encrytion = pkidb[name]['shaenc']
        creation_date = pkidb[name]['created']

        print(
              'Certificate name: ' +name+ '\n',
              '\tCertificate state: ' +status+ '\n',
              '\tCertificate serial number: ', serial, '\n',
              '\tCertificate creation date: ' +creation_date+ '\n',
              '\tDays of validity after creation: ', validity_time, '\n',
              '\tCertificate usage type: ' +cert_usage+ '\n',
              '\tCertificate shasum: ' +cert_shasum+ '\n',
              '\tCertificate shasum encryption: ' +hash_encrytion
        )

    exit(0)