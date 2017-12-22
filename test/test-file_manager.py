#!/usr/bin/env python3
# -*- coding: UTF-8 -*-

from json import load as jsonLoad
from json import dumps as jsonDump

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


def writeEncFile(wFile, wContent):
    try:
        file = open(wFile, "wt")
    except IOError:
        res = {
            "error": True,
            "message": "ERROR: Unable to open file " +
            str(wFile)}
        return(res)
    finally:
        try:
            file.write(wContent)
        except IOError:
            res = {
                "error": True,
                "message": 'ERROR: Unable to write to file ' +
                wFile}
            return(res)
        finally:
            file.close()
            res = {
                "error": False,
                "message": 'INFO: File ' +
                wFile +
                ' written'}
            return(res)

#toto = jsonLoad(open('pkicert.db', "r"))
# for k in toto :
#   print(k)

# json to dictionnary


def encJson2dict(fname):
    try:
        db = open(fname, "r")
        try:
            json = jsonLoad(db)
        except ValueError as e:
            json = 'ERROR: Json format error ' + str(fname) + ' --> ' + str(e)
            res = {"error": True, "message": json}
        else:
            res = {"error": False, "message": json}
    except IOError:
        json = 'ERROR: Unable to open file ' + fname
        res = {"error": True, "message": json}
    finally:
        db.close()
        return(res)

if __name__ == '__main__':
    passDBfile = "./toto.enc"
    name = 'test'
    passph = 1234
    verbose = True
    create = True

    if create:
        passdb = {}
    else:
        # mise a jour de la db pki
        passdb = encJson2dict(passDBfile)
        if not passdb['error']:
            passdb = passdb['message']
        else:
            res = {
                "error": True,
                "message": "ERROR: Unable to read Serial database " +
                passDBfile +
                "."}
            print(res)
            exit(1)

    # ecriture dans la db
    passdb[name] = passph
    newjson = jsonDump(passdb, sort_keys=False)
    wresult = writeEncFile(passDBfile, newjson)
    if wresult['error']:
        res = {"error": True, "message": wresult['message']}
        print(res)
        exit(1)
    if verbose:
        print("INFO: Passphrases db file updated.")
