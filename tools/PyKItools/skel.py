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
    parser = argparse.ArgumentParser(description='')
    parser.add_argument("-n", "--cn", action="store", dest="cn", type=str, help=u"Certificate common name", metavar='Common Name', required=True)
    parser.add_argument("-a", "--altnames", action='store', dest="subjectAltName", nargs='*', type=str, metavar='type:value', default=False, help=u"X509 extension Subject Alternative-names (eg, IP:1.2.3.4 DNS:www.toto.net URI: www.toto.net)", required=False)
    parser.add_argument("-p", "--purpose", action='store', dest="purpose", type=str, default='server', metavar='client|server', choices=['server','client'], help=u"Select which type of use is required for the certificate", required=True)
    parser.add_argument("-v", "--verbose", action='store_true', dest='mainVerbosity', help=u"Add output verbosity", required=False)

    args = parser.parse_args()

    # print help if no arguments given
    if len(argv) <= 1:
        parser.print_help()
        exit(1)

    result=vars(args)
    return(result)

if __name__ == '__main__':
    args=argCommandline(argv)

    pki=pkinit()
    if not pki:
        print("ERROR: Errors found during init")
        exit(1)
    pki.set_verbosity(args['mainVerbosity'])

    if args['cn'] not in pki.nameList:
        print('ERROR: Certificate '+args['cn']+" doesn't exist.")
        exit(1)

    exit(0)