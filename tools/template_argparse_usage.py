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
from sys import argv

# CLI options
def argCommandline(argv):
    """ gestion des arguments ligne de commande """

    result={}

    parser = argparse.ArgumentParser(description='Script to show how to use argparse module')
    parser.add_argument("-a", "--add-user", action="store", dest="user", help=u"Add a user")
    parser.add_argument("-l", "--list-user-hno", action='store_true', dest="listuserhno", default=False, help=u"Show pubkey's HNO user", required=False)
    parser.add_argument("-v", "--verbose", action='store_true', dest='verboseMode', default=False, help=u"Add verbosity")

    args = parser.parse_args()

    if args.listuserhno is True:
        result['list-user-hno'] = True
    if args.verboseMode:
        result['verbose'] = args.verboseMode
    if args.user:
        result['user'] = args.user

    nbargs = len(result)
    if nbargs < 1:
        parser.print_help()
        exit(1)

    return(result)

args = argCommandline(argv)
print(args)
