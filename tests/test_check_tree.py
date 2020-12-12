#!/usr/bin/env python3
# -*- coding: UTF-8 -*-

from os import path as ospath, walk as oswalk

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

if __name__ == '__main__':
    '''
    # ajouter un check en debut de script, si le pki path contien des choses, vérifier que la structure a bien etee creee par ce script sinon on créé tout !
    '''
    pkipath = "/Users/albookpro/Downloads/pyTLSpki/building/tests/toto6/"

    if not ospath.exists(pkipath):
        res = {'error': True, 'message': "ERROR: Pki Path doesn't exists"}
        print(res)
        exit(1)

    # pkipath must be an absolute path, without the final "/" for the realpath
    # check
    if pkipath[-1] == '/':
        pkipath = pkipath[:len(pkipath) - 1]

    if ospath.realpath(pkipath) != pkipath:
        print('ERROR: pki is a symlink, refusing to init pki')

    if not ospath.isdir(pkipath):
        res = {
            'error': True,
            'message': "ERROR: Pki init failed, your pki path is already used"}
        print(res)
        exit(1)
    else:
        dirnames = []
        filenames = []
        for path, dirs, files in oswalk(pkipath):
            for d in dirs:
                dirnames.append(d)
            for f in files:
                filenames.append(f)

        if 'public_key.pem' not in filenames:
            initiated = False
            print("First init has to be done")

        dirlen = len(dirnames)
        if dirlen < 6 and dirlen > 0 and initiated:
            print("Unproper PKI filesystem missing directories")
        elif dirlen != 6 and dirlen > 0 and not initiated:
            print(
                "Your PKI filesystem seems to contains partial old structure. You should backup and init again")

        if 'intermediate_cacert.pem' in filenames or 'cacert.pem' in filenames:
            if 'pkicert.db' not in filenames or 'public_key.pem' not in filenames or 'pkipass.db' not in filenames:
                print("Unproper PKI filesystem, missing files")
