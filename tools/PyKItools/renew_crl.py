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
import os
from PyKI import PyKInit


def argCommandline(argv):
    """
    Manage cli script args
    """
    parser = argparse.ArgumentParser(
        description='Extend and renew CRL period.')
    parser.add_argument(
        "-d",
        "--days",
        action='store',
        dest="days",
        type=int,
        default=360,
        help=u"Number of days for renew CRL validity period",
        metavar='X',
        required=False)
    parser.add_argument(
        "-v",
        "--verbose",
        action='store_true',
        dest='mainVerbosity',
        help=u"Add output verbosity",
        required=False)
    args = parser.parse_args()
    result = vars(args)
    return(result)

if __name__ == '__main__':
    args = argCommandline(argv)

    curScriptDir = os.path.dirname(os.path.abspath(__file__))
    configFilePath = curScriptDir + '/config/config.ini'

    pyki = PyKInit.PyKIsetup(configFilePath)
    pki = pyki.pki
    if not pki:
        print("ERROR: Errors found during init")
        exit(1)
    pki.set_verbosity(args['mainVerbosity'])

    # Renew crl validity
    if args['mainVerbosity']:
        print("INFO: Updating crl expiry to " +
              str(args['days']) +
              "j from now (same as if we would renew it before it expires)")
    renew = pki.renew_crl_date(next_crl_days=args['days'])
    print(renew['message'])

    pki.remove_lockf("INFO: PKI unlocked.")
    del(pki)
    exit(0)
