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

csr = "/opt/pyPKI/CERTS/clients/test_newcsr/test_newcsr.csr"

reqObj = crypto.load_certificate_request(crypto.FILETYPE_PEM, open(csr).read())

formatted_res = ''

########################################
# Get certificate subject informations #
########################################

subject = reqObj.get_subject()
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
    formatted_res += "INFOS: Unhandled items found:\n"
    for h in unhandled:
        formatted_res += '\t'+h[0].decode('utf-8')+'\n'
        # print value of item
        #print( h[1] )

# Now print the subject Common Name of the certificate
if CN :
    formatted_res += "Subject Common Name: "+CN.decode('utf-8')+'\n'
else:
    formatted_res += "Subject Common Name not found\n"

if C:
    formatted_res += "Subject Country Name: "+C.decode('utf-8')+'\n'

if ST:
    formatted_res += "Subject State or Province: "+ST.decode('utf-8')+'\n'

if L:
    formatted_res += "Subject Locality Name: "+L.decode('utf-8')+'\n'

if O:
    formatted_res += "Subject Organization Name: "+O.decode('utf-8')+'\n'

if OU:
    formatted_res += "Subject Organizational Unit Name: "+OU.decode('utf-8')+'\n'

if email :
    formatted_res += "Subject Owner email is: "+email.decode('utf-8')+'\n'

####################
# Get cert version #
####################

cert_ver = reqObj.get_version()
formatted_res += "\nCertificate Version number: "+str(cert_ver)+'\n'

################################
# Format a public key as a PEM #
################################

bio = crypto._new_mem_buf()
cryptolib.PEM_write_bio_PUBKEY(bio, reqObj.get_pubkey()._pkey)
pubkey = crypto._bio_to_string(bio)

pubkey_size = reqObj.get_pubkey().bits()

formatted_res += "\nPublic key size: "+str(pubkey_size)+'\n'
formatted_res += "Public key:\n\n" + pubkey.decode('utf-8') +'\n'

#########################################################
# Get all extensions of the certificate in list of dict #
#########################################################

formatted_res += "\nCertificate extensions list:\n"

extensions = {}
X509exts = reqObj.get_extensions()
for ext in X509exts:
    ext_name = ext.get_short_name().decode('utf-8')
    ext_data = ext.__str__()
    ext_critical = ext.get_critical()
    extensions[ext_name] = {'critical':ext_critical, 'data':ext_data}

# Now extensions contains all extensions infoso we can consult it like that
#print(extensions)
formatted_res += '\n'

# print info of extensions which you are looking for
if 'extendedKeyUsage' in extensions:
    formatted_res += '\tExtended key usage: '+extensions['extendedKeyUsage']['data']+'\n'

if 'basicConstraints' in extensions:
    formatted_res += '\tBasic constraints: '+extensions['basicConstraints']['data']+'\n'

if 'subjectAltName' in extensions:
    formatted_res += 'Subject alt-names:\n'
    for altname in extensions['subjectAltName']['data'].split(', '):
        formatted_res += "\t"+altname.split(':')[1]+'\n'
formatted_res += "\n"

print(formatted_res)
