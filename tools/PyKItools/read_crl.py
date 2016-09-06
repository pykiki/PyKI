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
from datetime import datetime

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

    pki = pkinit()
    if not pki:
        print("ERROR: Errors found during init")
        exit(1)
    pki.set_verbosity(args['mainVerbosity'])

    crlObj = pki.load_crl(pki.crl_path)
    if not crlObj['error']:
        crlObj = crlObj['message']
    revoked = crlObj.get_revoked()

    revokedb = pki.pkidbDict['revoked']

    print("INFO: Reading PKI CRL content:")
    for robj in revoked:
        # to remove leading 0 safely
        revokedSerial = int(robj.get_serial().decode('utf-8'))
        # to be able to use it as a dict item name
        revokedSerial = str(revokedSerial)
        cn = revokedb[revokedSerial]['cn']
        reason = robj.get_reason().decode('utf-8')
        #unspecified|keyCompromise|CACompromise|affiliationChanged|superseded|cessationOfOperation|certificateHold

        date = robj.get_rev_date().decode('utf-8')
        #print(datetime.strptime(date, '%Y%m%d%H:%M:%S'))
        print("Certificate " + cn + " revoked for " + reason + " at " + date + "." )
    exit(0)
