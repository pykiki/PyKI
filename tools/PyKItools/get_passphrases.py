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
    parser = argparse.ArgumentParser(
        description='Retrieve passphrase for a specific certificate name. If not specified, this will return all passphrases')
    parser.add_argument(
        "-a",
        "--all",
        action="store_true",
        dest="all",
        help=u"Show all passphrases",
        required=False)
    parser.add_argument(
        "-n",
        "--cn",
        action="store",
        dest="cn",
        type=str,
        help=u"Certificate common name",
        metavar='Common Name',
        required=False,
        default=False)
    parser.add_argument(
        "-v",
        "--verbose",
        action='store_true',
        dest='mainVerbosity',
        help=u"Add output verbosity",
        required=False)

    args = parser.parse_args()
    if len(argv) <= 1:
        parser.print_help()
        exit(1)

    result = vars(args)
    return(result)

if __name__ == '__main__':
    args = argCommandline(argv)

    pki = pkinit()
    if not pki:
        print("ERROR: Errors found during init")
        exit(1)
    pki.set_verbosity(args['mainVerbosity'])

    if args['cn'] and args['cn'] not in pki.nameList:
        print('ERROR: Certificate ' + args['cn'] + " doesn't exist.")
        exit(1)

    passphrases = pki.loadpassDB()
    if not passphrases['error']:
        if args['all']:
            print("\nList of passphrases stored:")
            for passphrase in passphrases['message']:
                print('Certificate Name: ' +
                      str(passphrase) +
                      ' / passphrase: ' +
                      str(passphrases['message'][passphrase]))
        else:
            # we are calling pki func cleanStr() to match name in database
            database_certname = passphrases[
                'message'][pki.cleanStr(args['cn'])]
            print("Passphrase for " + args['cn'] + ": " + database_certname)
    passphrases.clear()

    exit(0)
