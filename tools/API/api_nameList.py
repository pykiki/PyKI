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

    Contact: alain.maibach@gmail.com / 34 rue appienne 13480 - FRANCE.
'''

from os import path as ospath
from PyKI import PyKI
from flask import Flask
from flask import make_response

curScriptDir = ospath.dirname(ospath.abspath(__file__))

app = Flask(__name__)
#app.config['SERVER_NAME'] = "xu4.local.net"
app.config['DEBUG'] = False
lhost = "localhost"
lport = 80


@app.route('/')
def index():
    '''
        Index page for listing all possibilities
    '''

    htmlpage = '''
    <html>
        <HEAD>
            <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/css/bootstrap.min.css" integrity="sha384-BVYiiSIFeK1dGmJRAkycuHAHRg32OmUcww7on3RYdg4Va+PmSTsz/K68vbdEjh4u" crossorigin="anonymous">
        </HEAD>
        <BODY>
            <div class='container'>
                <h1>
                    Welcome to flask tests, here are links to test func calls:
                </h1>
                <p>
                    <a href='https://"+lhost+":"+str(lport)+"/listCert'> List of certificate in the pki database </a>
                </p>
                <p>
                    <a href='https://"+lhost+":"+str(lport)+"/help'> PKI documentation</a>
                </p>
            </div>

        </BODY>
    </html>
    '''
    # allow us to modify headers
    resp = make_response(htmlpage)
    resp.headers['Server'] = 'PyKI amaibach API'
    return(resp)


@app.route('/help')
def help():
    '''
        Documentation page
    '''

    info = open(curScriptDir + "/help.html", 'rt')
    helpContent = info.read()
    info.close()

    # allow us to modify headers
    resp = make_response(helpContent)
    resp.headers['Server'] = 'PyKI amaibach API'

    return(resp)


@app.route('/listCert')
def getNamesList():
    res = ""
    mainVerbosity = False
    # passphrase of the private key requested for pki authentication
    privateKeyPassphrase = 'ma22972'

    # pki authentication private key path
    pkeyPath = "./pki_auth_cert.pem"
    pkey = open(pkeyPath, 'rt')
    pkeyStr = pkey.read()
    pkey.close()

    # Init with privkey loaded from file
    pki = PyKI(authKeypass=privateKeyPassphrase, privkeyStr=pkeyStr)

    # Set pki verbosity after init
    pki.set_verbosity(mainVerbosity)

    res += "List of PKI certificate names:<br/>"
    for name in pki.nameList:
        res += "<pre>" + str(name) + "</pre>"

    # allow us to modify headers
    resp = make_response(res)
    resp.headers['Server'] = 'PyKI amaibach API'

    return(resp)

if __name__ == '__main__':
    # Listen in http #
    #app.run(host=lhost, port=lport)

    # Listen in Quick https #
    #context = ('/opt/PyKI_data/CERTS/servers/PyKIflask/PyKIflask.crt', '/opt/PyKI_data/CERTS/servers/PyKIflask/PyKIflask_unprotected.key')
    #app.run(host=lhost, port=lport, ssl_context=context, threaded=True, debug=True)

    # Listen in https with defined params #

    # Create an ssl context, with TLSv1.2 to use with flask
    #   Docu https://docs.python.org/3/library/ssl.html

    import ssl
    context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)

    # Define SSL options for context #
    if ssl.HAS_ECDH:
        context.set_ecdh_curve('prime256v1')
        context.options |= ssl.OP_SINGLE_ECDH_USE

    # Disable old protocols
    context.options |= ssl.OP_NO_SSLv2
    context.options |= ssl.OP_NO_SSLv3

    # Disable compression because of CRIME attack
    context.options |= ssl.OP_NO_COMPRESSION

    # Prefer server's cipher list over the client's
    context.options |= ssl.OP_CIPHER_SERVER_PREFERENCE

    # Define ciphers suite
    context.set_ciphers(
        'ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-SHA384:ECDHE-RSA-AES256-SHA:DHE-RSA-AES256-SHA:!LOW:!MD5:!aNULL:!eNULL:!3DES:!EXP:!PSK:!SRP:!DSS')

    # disable TLS session tickets
    context.options |= 0x00004000

    # Certificate authentication optional, can be set as CERT_NONE, CERT_OPTIONAL or CERT_REQUIRED
    #context.verify_mode = ssl.CERT_OPTIONAL
    context.verify_mode = ssl.CERT_NONE

    if ssl.HAS_SNI:
        # Is the peer cert name must be checked
        context.check_hostname = False

    # Set Ca certificates chain file
    context.load_verify_locations(
        cafile='/opt/PyKI_data/CERTS/chain_cacert.pem')
    # Set certificate and private key (with password optionnally)
    context.load_cert_chain(
        certfile='/opt/PyKI_data/CERTS/servers/PyKIflask/PyKIflask.crt',
        keyfile='/opt/PyKI_data/CERTS/servers/PyKIflask/PyKIflask.key',
        password="$okuZHeP-Dr~`?r[i[>9HmBp[Y")

    # End definitions #

    # Start flask listener with ssh
    app.run(host=lhost, port=lport, ssl_context=context)
