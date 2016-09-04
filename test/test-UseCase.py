#!/usr/bin/env python3
# -*- coding: UTF-8 -*-

#from time import sleep
from socket import gethostname
from os import path as ospath, sys

curScriptDir = ospath.dirname(ospath.abspath(__file__))
PyKImodPath = curScriptDir + "/../"
sys.path.append(PyKImodPath)
from PyKI import PyKI

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

if __name__ == '__main__':
    mainVerbosity = True

    ###################
    # instanciate pki #
    ###################

    # passphrase of the private key requested for pki authentication
    #privateKeyPassphrase = getpass('PKI Auth key password: ')
    privateKeyPassphrase = 'a'
    # pki authentication private key path
    pkeyPath = "./pki_auth_cert.pem"

    # Init pki with specific infos
    #pki = PyKI(C = "US", ST = "NewYork", L = "Washington", O = "test", OU = "IT ops", adminEmail = 'al.maib@gmail.com')

    # Init pki with verbosity
    #pki = PyKI(verbose = mainVerbosity)

    # Basic pki init
    #pki = PyKI(authKeypass=privateKeyPassphrase)

    # first init, creating private key
    if not ospath.exists(pkeyPath):
        print(
            "\n!!!!! INFO: The private key will be saved in " +
            pkeyPath +
            " !!!!!\n")
        pki = PyKI(
            issuerName='PyKI_auto-tester',
            verbose=True,
            KEY_SIZE=1024,
            SIGN_ALGO='SHA1',
            authKeypass=privateKeyPassphrase,
            authKeylen=1024,
        )
        # get private key for authentication after first init
        authprivkey = pki.initPkey

        # writing key to file
        try:
            wfile = open(pkeyPath, "wt")
        except IOError:
            print('ERROR: unable to open file ' + pkeyPath)
            exit(1)
        else:
            try:
                wfile.write(authprivkey)
            except IOError:
                print('ERROR: Unable to write to file ' + pkeyPath)
                exit(1)
            else:
                if mainVerbosity:
                    print('INFO: File ' + pkeyPath + ' written')
        finally:
            wfile.close()

    # flushing privekey for example purpose only
    authprivkey = None

    # second init with privkey loaded from file
    pkey = open(pkeyPath, 'rt')
    pkeyStr = pkey.read()
    pkey.close()
    # With predefined security params for certificate ca and intermediate gen'
    pki = PyKI(
        issuerName='PyKI_auto-tester',
        verbose=mainVerbosity,
        KEY_SIZE=1024,
        SIGN_ALGO='SHA1',
        authKeypass=privateKeyPassphrase,
        privkeyStr=pkeyStr)

    # sleep(1)

    # instead of using init security value, set new values #

    # set global default keysize
    pki.set_pkeysize(1024)
    # set global default certificate encryption
    pki.set_crtenc("SHA1")
    # set global default key cipher encrytpion
    pki.set_keycipher("DES3")
    # define global default crl encryption
    pki.set_crlenc("sha256")

    # Set pki verbosity after init
    pki.set_verbosity(mainVerbosity)

    ########################
    # server key/cert pair #
    ########################

    commoname = gethostname()
    serverPassphrase = "azerty"

    if mainVerbosity:
        print("INFO: Generating server private key for " + commoname + "...")
    # force serverkey to have a size of 1024, and not to be protected by
    # passphrase
    serverkey = pki.create_key(keysize=1024, name=commoname)
    if serverkey['error']:
        print("ERROR: Unable to generate server key " +
              commoname + " properly, aborting...")
        exit(1)
    elif mainVerbosity:
        print("INFO: Key " + commoname + " done.")

    if mainVerbosity:
        print("INFO: Generating server certificate for " + commoname + "...")
    # define certificate encrytion using param encryption
    servercert = pki.create_cert(
        country='BE', state='Antwerp', city='Mechelen',
        org='In Serf we trust, Inc.', ou='Test Suite Server',
        email='serfserver@example.com',
        KeyUsage="serverAuth",
        cn=commoname,
        subjectAltName=['DNS:' + commoname],
        # Options are 'email', 'URI', 'IP', 'DNS'
        # Example : subjectAltName = ['DNS:' + USERCN, 'DNS:*.local.net',
        # 'IP:10.0.0.1']
        encryption="SHA1"
    )
    if servercert['error']:
        print(
            "ERROR: Unable to generate server certificate " +
            commoname +
            " --> " +
            servercert['message'] +
            ", aborting...")
        exit(1)
    elif mainVerbosity:
        print("INFO: Certificate " + commoname + " done.")

    #''' Gen cert examples '''#
    commoname = 'localhost'
    if mainVerbosity:
        print("INFO: Generating server private key for " + commoname + "...")
    # force serverkey to have a size of 1024, and not to be protected by
    # passphrase
    serverkey = pki.create_key(keysize=1024, name=commoname)
    if serverkey['error']:
        print(
            "ERROR: Unable to generate server key " +
            commoname +
            " --> " +
            serverkey['message'] +
            ", aborting...")
        exit(1)
    elif mainVerbosity:
        print("INFO: Key " + commoname + " done.")

    if mainVerbosity:
        print(
            "INFO: Generating server certificate which has expired a year ago " +
            commoname)
    expiredcert = pki.create_cert(
        country='BE', state='Antwerp', city='Mechelen',
        org='In Serf we trust, Inc.', ou='Test Suite Server',
        email='serfserver@example.com',
        cn=commoname,
        KeyUsage="serverAuth",
    )
    if expiredcert['error']:
        print(
            "ERROR: Unable to generate server certificate " +
            commoname +
            " --> " +
            expiredcert['message'] +
            " aborting...")
        exit(1)
    elif mainVerbosity:
        print("INFO: Certificate " + commoname + " done.")

    commoname = 'localhost_futur'
    if mainVerbosity:
        print("INFO: Generating server private key for " + commoname + "...")
    # force serverkey to have a size of 1024, and not to be protected by
    # passphrase
    serverkey = pki.create_key(keysize=1024, name=commoname)
    if serverkey['error']:
        print(
            "ERROR: Unable to generate server key " +
            commoname +
            " --> " +
            serverkey['message'] +
            " aborting...")
        exit(1)
    elif mainVerbosity:
        print("INFO: Key " + commoname + " done.")

    if mainVerbosity:
        print(
            "INFO: Generating server certificate which will be valid in 10 years for 13 years " +
            commoname)
    expiredcert = pki.create_cert(
        country='BE', state='Antwerp', city='Mechelen',
        org='In Serf we trust, Inc.', ou='Test Suite Server',
        email='serfserver@example.com',
        cn=commoname,
        KeyUsage="serverAuth",
        valid_before=10 * 365,
        days_valid=13 * 365)
    if expiredcert['error']:
        print("ERROR: Unable to generate server certificate " +
              commoname + " --> " + expiredcert['message'] + " aborting")
        exit(1)
    elif mainVerbosity:
        print("INFO: Certificate " + commoname + " done.")

    commoname = 'localhost_nocn'
    if mainVerbosity:
        print("INFO: Generating server private key for " + commoname)
    # force serverkey to have a size of 1024, and not to be protected by
    # passphrase
    serverkey = pki.create_key(keysize=1024, name=commoname)
    if serverkey['error']:
        print(
            "ERROR: Unable to generate server key " +
            commoname +
            " --> " +
            serverkey['message'] +
            " aborting...")
        exit(1)
    elif mainVerbosity:
        print("INFO: Key " + commoname + " done.")

    if mainVerbosity:
        print(
            "INFO: Generating server certificate which will be valid for 13 years with no CommonName " +
            commoname)
    san_nocncert = pki.create_cert(
        country='BE', state='Antwerp', city='Mechelen',
        org='In Serf we trust, Inc.', ou='Test Suite Server',
        email='serfserver@example.com',
        days_valid=13 * 365,
        cn=None,
        subjectAltName=['DNS:' + commoname],
        KeyUsage="serverAuth",
    )
    if san_nocncert['error']:
        print(
            "ERROR: Unable to generate server certificate " +
            commoname +
            " --> " +
            san_nocncert['message'] +
            ", aborting...")
        exit(1)
    elif mainVerbosity:
        print("INFO: Certificate " + commoname + " done.")

    ###################################
    # client key pair and certificate #
    ###################################

    commoname = "SerfClient"
    cltkeyPass = "azerty"

    clientkey = pki.create_key(
        passphrase=cltkeyPass,
        name=commoname,
        usage='clientAuth')
    if clientkey['error']:
        print(
            "ERROR: Unable to generate client key " +
            cltKeyfile +
            " --> " +
            clientkey['message'] +
            " aborting...")
        exit(1)
    elif mainVerbosity:
        print("INFO: Key " + commoname + " done.")

    if mainVerbosity:
        print("INFO: Generating client certificate with alt-names " + commoname)
    clientcert = pki.create_cert(
        country='BE', state='Antwerp', city='Mechelen',
        org='In Serf we trust, Inc.', ou='Test Suite Server',
        email='serfclient@example.com',
        KeyUsage="clientAuth",
        cn=commoname,
        # Options are 'email', 'URI', 'IP', 'DNS'
        subjectAltName=['DNS:' + commoname, 'IP:10.0.0.1'],
        # Example : subjectAltName = ['DNS:' + USERCN, 'DNS:*.local.net',
        # 'IP:10.0.0.1']
    )
    if clientcert['error']:
        print("ERROR: Unable to generate client certificate " +
              commoname + " --> " + clientcert['message'] + " aborting...")
        exit(1)
    elif mainVerbosity:
        print("INFO: Certificate " + commoname + " done.")

    #############################################
    # client/server purpose key and certificate #
    #############################################

    commoname = "ClientSrv4all"
    keyPass = "azerty"

    key = pki.create_key(passphrase=keyPass, name=commoname)
    if key['error']:
        print(
            "ERROR: Unable to generate client key " +
            commoname +
            " --> " +
            key['message'] +
            " aborting...")
        exit(1)
    elif mainVerbosity:
        print("INFO: Key " + commoname + " done.")

    if mainVerbosity:
        print("INFO: Generating certificate whith alt-names for " + commoname)
    cert = pki.create_cert(
        country='BE', state='Antwerp', city='Mechelen',
        org='In Serf we trust, Inc.', ou='Test Suite Server',
        email='serfclient@example.com',
        cn=commoname,
        # Options are 'email', 'URI', 'IP', 'DNS'
        subjectAltName=['DNS:' + commoname, 'IP:10.0.0.1'],
        # Example : subjectAltName = ['DNS:' + USERCN, 'DNS:*.local.net',
        # 'IP:10.0.0.1']
    )
    if cert['error']:
        print("ERROR: Unable to generate client certificate: " +
              commoname + " --> " + cert['message'] + " aborting...")
        exit(1)
    elif mainVerbosity:
        print("INFO: Certificate " + commoname + " done.")

    ######################################
    # Revoke certificates and manage crl #
    ######################################

    # reason cessationOfOperation
    commoname = 'SerfClient'
    if mainVerbosity:
        print("INFO: Revoking certificate " + commoname + "...")
    crl = pki.revoke_cert(
        certname=commoname,
        next_crl_days=183,
        reason="cessationOfOperation")
    if crl['error']:
        print(crl['message'])
    elif mainVerbosity:
        print(crl['message'])

    # reason keyCompromise
    commoname = 'ClientSrv4all'
    if mainVerbosity:
        print("INFO: Revoking certificate " + commoname + "...")
    crl = pki.revoke_cert(
        certname=commoname,
        next_crl_days=183,
        reason="keyCompromise")
    if crl['error']:
        print(crl['message'])
    elif mainVerbosity:
        print(crl['message'])

    # Renew crl validity
    if mainVerbosity:
        print("INFO: Updating crl expiry to 360j from now (same as if we would renew it before it expires)")
    renew = pki.renew_crl_date(next_crl_days=360)
    if renew['error']:
        print(renew['message'])
    elif mainVerbosity:
        print(renew['message'])

    ##############
    # Manage CSR #
    ##############

    # CSR gen
    commoname = "test_newcsr"
    csrPassphrase = "azerty"

    if mainVerbosity:
        print("INFO: Generate a client csr with it's private key")
    # create csr with a private key size of 8192
    csr = pki.create_csr(
        passphrase=csrPassphrase,
        country='BE', state='Antwerp', city='Mechelen',
        org='In Serf we trust, Inc.', ou='Test Suite Server',
        email='serfclient@example.com',
        cn=commoname,
        encryption='SHA1',
        keysize=1024,
        # Options are 'email', 'URI', 'IP', 'DNS'
        subjectAltName=['DNS:' + commoname, 'IP:10.0.0.1']
    )
    if csr['error']:
        print(csr['message'])
    elif mainVerbosity:
        print(csr['message'])

    # CSR signin'
    commoname = "test_newcsr"
    csrfile = '/opt/PyKI_data/CERTS/requests/' + \
        commoname + '/' + commoname + '.csr'
    if mainVerbosity:
        print("INFO: Signing Certificate Request " +
              csrfile + " for 90 days of validity...")
    signRes = pki.sign_csr(
        csr=csrfile,
        KeyUsage="clientAuth",
        days_valid=90,
        encryption="SHA1")
    if signRes['error']:
        print("ERROR: Unable to generate certificate for csr " +
              csrfile + " --> " + signRes['message'] + " aborting...")
        exit(1)
    elif mainVerbosity:
        print("INFO: Certificate " + commoname + " done.")

    #####################
    # Check cert vs key #
    #####################

    # check that the key generated match the cert signed
    certFromCsr = '/opt/PyKI_data/CERTS/signed/test_newcsr/test_newcsr.crt'
    csrkey = '/opt/PyKI_data/CERTS/requests/test_newcsr/test_newcsr.key'
    reschk = pki.check_cer_vs_key(
        cert=certFromCsr,
        key=csrkey,
        keypass=csrPassphrase)
    if reschk['error']:
        print(reschk['message'])
    elif mainVerbosity:
        print(reschk['message'])

    #################
    # Manage pkcs12 #
    #################

    commoname = "test_newcsr"
    pkcspass = 'azerty'
    if mainVerbosity:
        print("INFO: Generating pkcs12 for " + commoname)

    clientpkcs12 = pki.create_pkcs12(pkcs12pwd=pkcspass, pkcs12name=commoname)
    if clientpkcs12['error']:
        print(clientpkcs12['message'])
    elif mainVerbosity:
        print(clientpkcs12['message'])

    # extract ca, cert and key from pkcs12 file
    pkcsfile = pki.get_crtsDir() + "/clients/test_newcsr/test_newcsr.p12"
    dstdata = pkcsfile + '_extracted/'
    if mainVerbosity:
        print(
            "INFO: Extract pkcs12 content from file " +
            pkcsfile +
            " to " +
            dstdata +
            "...")
    extractres = pki.extract_pkcs12(
        pkcs12file=pkcsfile,
        pkcs12pwd=pkcspass,
        destdir=dstdata)
    if extractres['error']:
        print(extractres['message'])
    elif mainVerbosity:
        print(extractres['message'])

    ##############################
    # Remove passphrase from key #
    ##############################

    commoname = "test_newcsr"
    csrPassphrase = "azerty"
    if mainVerbosity:
        print("INFO: Removing passphrase from " + commoname)
    unprotectres = pki.unprotect_key(
        keyname=commoname, privKeypass=csrPassphrase)
    if unprotectres['error']:
        print(unprotectres['message'])
    elif mainVerbosity:
        print(unprotectres['message'])

    ##########
    # Checks #
    ##########

    commoname = "test_newcsr"
    certFromCsr = '/opt/PyKI_data/CERTS/signed/test_newcsr/test_newcsr.crt'

    # Check if the certificate is stored in the pki database
    if mainVerbosity:
        print("INFO: Checking pki conformity for cert " + certFromCsr)
    conform = pki.chk_conformity(cert=certFromCsr)
    if conform['error']:
        print(conform['message'])
    else:
        if mainVerbosity:
            print(conform['message'])
        # we know the certificat is stored in pki so,
        # Check if the certificate is still valid (not revoked and not expired)
        if mainVerbosity:
            print("INFO: Checking certificate status for " + commoname)
        valid = pki.chk_validity(commoname)
        if valid['error']:
            print(valid['message'])
        elif mainVerbosity:
            print(valid['message'])

    ##################################
    # Get dict of passphrases stored #
    ##################################

    passphrases = pki.loadpassDB()
    if mainVerbosity and not passphrases['error']:
        print("\nList of passphrases stored:")
        for passphrase in passphrases['message']:
            print(
                'Certificate Name: ' +
                passphrase +
                ' / passphrase: ' +
                passphrases['message'][passphrase])
    passphrases.clear()

    #############################
    # Get info from certificate #
    #############################

    commoname = 'test_newcsr'
    print("\nCertificate informations for " + commoname)
    cert_info = pki.get_certinfo(commoname)
    if cert_info['error']:
        print(cert_info['message'])
    else:
        print("\n" + cert_info['message'])

    #####################################
    # Get info from certificate request #
    #####################################

    commoname = "test_newcsr"
    print("\nCertificate request informations for " + commoname)
    csr_info = pki.get_csrinfo(
        pki.csrDir +
        "/" +
        commoname +
        "/" +
        commoname +
        ".csr")
    if csr_info['error']:
        print(csr_info['message'])
    else:
        print("\n" + csr_info['message'])
