#!/usr/bin/env python3
# -*- encoding: UTF-8 -*-

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

from OpenSSL import crypto, SSL
from OpenSSL._util import lib as cryptolib

# func needed to translate date time to human readable format
from datetime import datetime
import pytz
def gt_to_dt(gt):
    """ Convert GeneralizedTime string to python datetime object

        >>> gt_to_dt("20150131143554.230")
        datetime.datetime(2015, 1, 31, 14, 35, 54, 230)
        >>> gt_to_dt("20150131143554.230Z")
        datetime.datetime(2015, 1, 31, 14, 35, 54, 230, tzinfo=<UTC>)
        >>> gt_to_dt("20150131143554.230+0300")
        datetime.datetime(2015, 1, 31, 11, 35, 54, 230, tzinfo=<UTC>)
    """
    # check UTC and offset from local time
    utc = False
    if b"Z" in gt.upper():
        utc = True
        gt = gt[:-1]
    if gt[-5] in ['+', '-']:
        # offsets are given from local time to UTC, so substract the offset to get UTC time
        hour_offset, min_offset = -int(gt[-5] + gt[-4:-2]), -int(gt[-5] + gt[-2:])
        utc = True
        gt = gt[:-5]
    else:
        hour_offset, min_offset = 0, 0

    # microseconds are optionnals
    if b"." in gt:
        microsecond = int(gt[gt.index('.') + 1:])
        gt = gt[:gt.index('.')]
    else:
        microsecond = 0

    # seconds and minutes are optionnals too
    if len(gt) == 14:
        year, month, day, hours, minutes, sec = int(gt[:4]), int(gt[4:6]), int(gt[6:8]), int(gt[8:10]), int(gt[10:12]), int(gt[12:])
        hours += hour_offset
        minutes += min_offset
    elif len(gt) == 12:
        year, month, day, hours, minutes, sec = int(gt[:4]), int(gt[4:6]), int(gt[6:8]), int(gt[8:10]), int(gt[10:]), 0
        hours += hour_offset
        minutes += min_offset
    elif len(gt) == 10:
        year, month, day, hours, minutes, sec = int(gt[:4]), int(gt[4:6]), int(gt[6:8]), int(gt[8:]), 0, 0
        hours += hour_offset
        minutes += min_offset
    else:
        # can't be a generalized time
        raise ValueError('This is not a generalized time string')

    # construct aware or naive datetime and format it with strftime
    if utc:
        #dt = datetime(year, month, day, hours, minutes, sec, microsecond, tzinfo=pytz.UTC).strftime('%Y-%m-%d %H:%M:%S')
        dt = datetime(year, month, day, hours, minutes, sec, microsecond, tzinfo=pytz.UTC).strftime('%d/%m/%Y %H:%M')
    else:
        dt = datetime(year, month, day, hours, minutes, sec, microsecond).strftime('%d/%m/%Y %H:%M')
    # done !
    return(dt)

# Certificate file path
filePath = "/opt/pyPKI/CERTS/clients/test_newcsr/test_newcsr.crt"

# loading certificate into X509 object
try:
    latest_cert = crypto.load_certificate( crypto.FILETYPE_PEM, open(filePath).read() )
except FileNotFoundError as e:
    print(e.strerror+": "+filePath)
    exit(1)
except:
    print("ERROR: Unhandled error...")
    exit(1)

#################################
# Get issuer infos: C, ST, etc. #
#################################

print("")

issuer = latest_cert.get_issuer()
certIssuerInfos = issuer.get_components()
unhandled = []
for i in certIssuerInfos:
    if( i[0] == b'CN' ):
        CN = i[1]
    elif( i[0] == b'C' ):
        C = i[1]
    elif( i[0] == b'ST' ):
        ST = i[1]
    elif( i[0] == b'L' ):
        L = i[1]
    elif( i[0] == b'O' ):
        O = i[1]
    elif( i[0] == b'OU' ):
        OU = i[1]
    elif( i[0] == b'emailAddress' ):
        email = i[1]
    else:
        unhandled.append(i)

if len(unhandled) > 0:
    print("INFOS: Unhandled items found:")
    for h in unhandled:
        print( '\t' + str(h[0]) )
        # print value of item
        #print( h[1] )

# Now print the issuer Common Name of the certificate
if CN :
    print("Issuer Common Name: "+CN.decode('utf-8'))
else:
    print("Issuer Common Name not found\n")

if C:
    print("Issuer Country Name: "+C.decode('utf-8'))

if ST:
    print("Issuer State or Province: "+ST.decode('utf-8'))

if L:
    print("Issuer Locality Name: "+L.decode('utf-8'))

if O:
    print("Issuer Organization Name: "+O.decode('utf-8'))

if OU:
    print("Issuer Organizational Unit Name: "+OU.decode('utf-8'))

if email :
    print("Issuer Owner email is: "+email.decode('utf-8'))

########################################
# Get certificate subject informations #
########################################

cert_subjectname_hash = latest_cert.subject_name_hash()
print("\nSubject name hash:",cert_subjectname_hash)

subject = latest_cert.get_subject()
certSubjectInfos = subject.get_components()
unhandled = []
for i in certSubjectInfos:
    if( i[0] == b'CN' ):
        CN = i[1]
    elif( i[0] == b'C' ):
        C = i[1]
    elif( i[0] == b'ST' ):
        ST = i[1]
    elif( i[0] == b'L' ):
        L = i[1]
    elif( i[0] == b'O' ):
        O = i[1]
    elif( i[0] == b'OU' ):
        OU = i[1]
    elif( i[0] == b'emailAddress' ):
        email = i[1]
    else:
        unhandled.append(i)

if len(unhandled) > 0:
    print("INFOS: Unhandled items found:")
    for h in unhandled:
        print( '\t' + str(h[0]) )
        # print value of item
        #print( h[1] )

# Now print the subject Common Name of the certificate
if CN :
    print("Subject Common Name: "+CN.decode('utf-8'))
else:
    print("Subject Common Name not found\n")

if C:
    print("Subject Country Name: "+C.decode('utf-8'))

if ST:
    print("Subject State or Province: "+ST.decode('utf-8'))

if L:
    print("Subject Locality Name: "+L.decode('utf-8'))

if O:
    print("Subject Organization Name: "+O.decode('utf-8'))

if OU:
    print("Subject Organizational Unit Name: "+OU.decode('utf-8'))

if email :
    print("Subject Owner email is: "+email.decode('utf-8'))

####################################
# Check if certificate has expired #
####################################

print("")
expired = latest_cert.has_expired()
if not expired:
    print('Status: Not expired')
else:
    print('Status: Expired')

############################
# Get certificate validity #
############################

fromdate = latest_cert.get_notBefore()
todate = latest_cert.get_notAfter()
print( "Valid from "+gt_to_dt(fromdate)+" to "+gt_to_dt(todate) )

###############################
# Get some other informations #
###############################

cert_sn = latest_cert.get_serial_number()
cert_algo_sign = latest_cert.get_signature_algorithm().decode('utf-8')
cert_ver = latest_cert.get_version()
print(
      "\nCertificate Serial Number:",cert_sn,
      "\nCertificate algorithm signature: "+cert_algo_sign,
      "\nCertificate Version number:",cert_ver
     )

################################
# Format a public key as a PEM #
################################
 
bio = crypto._new_mem_buf()
cryptolib.PEM_write_bio_PUBKEY(bio, latest_cert.get_pubkey()._pkey)
pubkey = crypto._bio_to_string(bio)

pubkey_size = latest_cert.get_pubkey().bits()

print("\nPublic key size:",pubkey_size)
print("Public key:\n\n" + pubkey.decode('utf-8') )

#########################################################
# Get all extensions of the certificate in list of dict #
#########################################################

print("Certificate extensions list:\n")

extensions = {}
extnbr = latest_cert.get_extension_count()
for count in range(extnbr):
    ext_name = latest_cert.get_extension(count).get_short_name().decode('utf-8')
    ext_critical = latest_cert.get_extension(count).get_critical()
    ext_data = latest_cert.get_extension(count).__str__()
    extensions[ext_name] = {'critical':ext_critical, 'data':ext_data}

# Now extensions contains all extensions infoso we can consult it like that
#print(extensions)

# print info of extensions which you are looking for
if 'extendedKeyUsage' in extensions:
    print('\tExtended key usage: '+extensions['extendedKeyUsage']['data'])

if 'basicConstraints' in extensions:
    print('\tBasic constraints: '+extensions['basicConstraints']['data'])

if 'subjectAltName' in extensions:
    print('\tSubject alt-names:')
    for altname in extensions['subjectAltName']['data'].split(', '):
        print("\t\t"+altname.split(':')[1])
print("")

#### ??? ###
#latest_cert.digest()

