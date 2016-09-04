#!/usr/bin/env python3
# -*- coding: UTF-8 -*-

from json import dumps as jsonDump
from json import load as jsonLoad
from datetime import datetime

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


def writeFile(wFile, wContent, mode='text'):
    try:
        if mode == 'text':
            file = open(wFile, "wt")
        elif mode == 'bytes':
            file = open(wFile, "wb")
        else:
            res = {
                "error": True,
                "message": "ERROR: Please choose mode text or bytes to open your file " +
                str(wFile)}
            return(res)
    except IOError:
        res = {
            "error": True,
            "message": "ERROR: Unable to open file " +
            str(wFile)}
        return(res)
    else:
        try:
            file.write(wContent)
        except IOError:
            res = {
                "error": True,
                "message": 'ERROR: Unable to write to file ' +
                wFile}
            return(res)
        else:
            res = {
                "error": False,
                "message": 'INFO: File ' +
                wFile +
                ' written'}
            return(res)
        finally:
            file.close()


def json2dict(fname):
    try:
        db = open(fname, "r")
        try:
            # load json from reading stream
            json = jsonLoad(db)
        except ValueError as e:
            json = 'ERROR: Json format error ' + str(fname) + ' --> ' + str(e)
            res = {"error": True, "message": json}
        else:
            res = {"error": False, "message": json}
    except IOError:
        json = 'ERROR: Unable to open file ' + fname
        res = {"error": True, "message": json}
    else:
        db.close()
    finally:
        return(res)

if __name__ == '__main__':
    '''
    function de mise a jour de la pki db file
        check des date
            passer les etats a expiré si date depassée
    '''
    DBfile = '/opt/PyKI/pkicert.db'
    verbose = True

    pkidb = json2dict(DBfile)
    if not pkidb['error']:
        pkidb = pkidb['message']
    else:
        res = {
            "error": True,
            "message": "ERROR: Unable to read Serial database " +
            DBfile +
            "."}
        print(res)
        exit(0)
        # return(res)

    modified = False
    critical = False
    for certname in pkidb:
        if pkidb[certname]['state'] == "activ":
            createdate = pkidb[certname]['created']
            duration = pkidb[certname]['duration']
            #print(certname, createdate, duration)
            #currentDate = datetime.utcnow().strftime('%Y/%m/%d %H:%M:%S')
            currentDate = datetime.utcnow()
            # parse str date to datetime.datetime object
            #createDateTime = datetime.strptime(createdate, '%Y/%m/%d %H:%M:%S')
            createDateTime = datetime.strptime(
                "2009/07/23 14:32:30", '%Y/%m/%d %H:%M:%S')
            # get timedelta object
            #print(currentDate - timedelta(days=366))
            timeDelta = currentDate - createDateTime
            # get timedelta in days
            deltadays = timeDelta.days - 1
            # in hours
            #print(round(timeDelta.seconds / (60*60),1))
            # in minutes
            #print(int(timeDelta.seconds / 60))
            # in seconds
            # print(timeDelta.seconds)
            # in microseconds
            # print(timeDelta.microseconds)
            # if deltadays > duration :
            #    print("expired since "+ str(round(deltadays, 1) - duration) +" days")
            # elif deltadays == duration:
            #    if timeDelta.seconds > 60:
            #        print("expired today since "+str(int(timeDelta.seconds/60))+" minutes")
            #    else:
            #        print("expired today since "+str(timeDelta.seconds)+" seconds")
            if deltadays >= duration:
                pkidb[certname]['state'] = "expired"
                modified = True

                if certname == 'cacert':
                    critical = True
                    res = {
                        "error": True,
                        "message": "ERROR: CA certificate is expired."}
                elif certname == 'intermediate_cacert':
                    critical = True
                    res = {
                        "error": True,
                        "message": "ERROR: Intermediate CA certificate is expired."}
    if critical:
        # return(res)
        print(res)
        exit(1)

    if modified:
        newjson = jsonDump(pkidb, sort_keys=False)
        wresult = writeFile(DBfile, newjson)
        if wresult['error']:
            res = {"error": True, "message": wresult['message']}
            # return(res)
            print(res)
            exit(1)
        if verbose:
            print("INFO: Pki db file updated.")
