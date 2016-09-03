# PyKI
TLS Public Key Infrastructure manager  

_This is my first project, the goal was to have an easy to deploy and manage **Public Key Infrastructure** ._

Please be easy with my code, I assume that all is not optimized, pythonic and as robust as I would like, but feel free to help to improve it.

*And I apologize for my english too :p*

## Requirements and installation

### Compatibilities
- **_Python 3.X_**

### Prerequisites

* [cffi >= 1.7.0](https://pypi.python.org/pypi/cffi/1.7.0)
* [cryptography >= 1.4](https://pypi.python.org/pypi/cryptography/1.4)
* [idna >= 2.1](https://pypi.python.org/pypi/idna/2.1)
* [pyasn1 >= 0.1.9](https://pypi.python.org/pypi/pyasn1/0.1.9)
* [pyasn1-modules >= 0.0.8](https://pypi.python.org/pypi/pyasn1-modules/0.0.8)
* [pycparser >= 2.14](https://pypi.python.org/pypi/pycparser/2.14)
* [pycrypto >= 2.6.1](https://pypi.python.org/pypi/pycrypto/2.6.1)
* [pyOpenSSL >= 16.0.0](https://pypi.python.org/pypi/pyOpenSSL/16.0.0)
* [pytz >= 2016.6.1](https://pypi.python.org/pypi/pytz/2016.6.1)
* [six >= 1.10.0](https://pypi.python.org/pypi/six/1.10.0)
* [xkcdpass >= 1.8.0](https://pypi.python.org/pypi/xkcdpass/1.8.0)

### Install python modules dependencies
>
```
pip3 install cffi cryptography idna pyasn1 pycparser pyOpenSSL pytz six xkcdpass pycrypto setuptools
```

### PyKI library installation
>_Create a virtual env, activate it and install the library._

>To install it:
>>
```
tar -xvzf PyKI-1.0.tar.gz
cd PyKI-1.0/
python3 setup.py install --record installation.txt
```

>To uninstall it:
>>
```
pip uninstall PyKI
```

>To be able to use it properly, you must create the PKI directory path with user file permissions:
>>
```
sudo mkdir /opt/PyKI_data/
sudo -EH chown $USER /opt/PyKI_data/
```

### PyKI filesystem
>_The PKI filesystem tree will be created as:_
>>
```
# First init when generating pki private key pair authentication #
>>
    /opt/PyKI_data/
    ├── CA
    ├── CERTS
    │   ├── clients
    │   └── servers
    ├── INTERMEDIATE
    └── passphrases
        └── public_key.pem
    6 directories, 1 files
>>
# Second init, when PKI is loaded successfully after authenticating #
>>
    /opt/PyKI_data/
    ├── CA
    │   ├── cacert.pem
    │   └── cakey.pem
    ├── CERTS
    │   ├── chain_cacert.pem
    │   ├── clients
    │   └── servers
    ├── INTERMEDIATE
    │   ├── crl.pem
    │   ├── intermediate_cacert.pem
    │   └── intermediate_cakey.pem
    ├── passphrases
    │   ├── pkipass.db
    │   └── public_key.pem
    └── pkicert.db
>>
    6 directories, 9 files
```

## PKI usage
>_You can see examples for all funcs in "test/test-UseCase.py"._

> Load PyKI module:
>>```
#!/usr/bin/env python3
# -*- encoding: UTF-8 -*-
from PyKI import PyKI

### 1. PKI init'
>
1. _Initiate the PKI global default values_.
- _Construct (if needed) the PKI filesystem tree_.
- _Generate the PKI private key authentication (**First init' only**)_.
- _Authenticate PKI user (against it's private key)_.
- _Generate CA and intermediate certificates (**If they aren't already**)_.
- _Load CA and intermediate certificates_.
- _Check PKI integrity_.
> 
>**Parameters**:
>>* **verbose (boolean)**: Set verbosity.
* **issuerName (string)**: Set the ROOT certificates issuer names. You should use your organization name.
* **authKeypass (string)**: Set the pki private key passphrase in order to protect the pki calling.
* **privkeyStr (string)**: Must contain the pki private key file content.
* **authKeylen (int)**: Set PKI authentication private key size, must be in [1024, 2048, 4096, 8192].
* **C (string)**: Set default certificate Country name.
* **ST (string)**: Set default certificate State name.
* **L (string)**: Set default certificate Locality name.
* **O (string)**: Set default certificate Organization name.
* **OU (string)**: Set default certificate Organiational Unit name.
* **adminEmail (string)**: Set default certificate administrator e-mail @.
* **KEY_SIZE (int)**: Set default private key size, must be in [1024, 2048, 4096, 8192].
* **SIGN_ALGO (string)**: Set default certificate encryption (signature algorithm), must be in [SHA1, SHA256, SHA512].
* **KEY_CIPHER (string)**: Set default rsa private key cipher.

>>>>
- des (encrypt the generated key with DES in cbc mode)
- des3 (encrypt the generated key with DES in ede cbc mode (168 bit key)
- seed (encrypt PEM output with cbc seed)
- aes128, aes192, aes256 (encrypt PEM output with cbc aes)
- camellia128, camellia192, camellia256 (encrypt PEM output with cbc camellia)
>>
* **CRL_ALGO (string)**: Set CRL message digest, must be in ['MD2','MD5','MDC2','RMD160','SHA','SHA1','SHA224','SHA256','SHA384','SHA512'].
> 
>#### First PKI init' (_To do only once._)
>>- Define a passphrase for the private key which will be use to authenticate and will allow you to request the pki later.
>>
>>>```
    privateKeyPassphrase = 'apassphrasetokeep'
```
>>
>>- Define where to save the pki authentication key.
>>
>>>```
    pkeyPath = "./pki_auth_cert.pem"
```
>>
>>- Init the pki with verbosity and some security custom params.
>>
>>>```
	pki = PyKI(issuerName='PyKI_example', verbose = True, authKeypass=privateKeyPassphrase, authKeylen = 1024, KEY_SIZE = 1024, SIGN_ALGO = 'SHA1')
```
>>
>>- Save the pki authentication key.
>>
>>>```
	# Retrieve authentication private key.
	authprivkey = pki.initPkey	
	# writing key to file.
	try:
		wfile = open(pkeyPath, "wt")
	except IOError:
		print('ERROR: unable to open file '+pkeyPath)
		exit(1)
	else:
		try:
			wfile.write(authprivkey)
		except IOError:
			print('ERROR: Unable to write to file '+pkeyPath)
			exit(1)
		else:
			print('INFO: File ' + pkeyPath + ' written')
	finally:
		wfile.close()
		authprivkey = None
```

>#### Usual PKI init' (_To call everytime you need to manage your PKI_)
>>- Get your pki authentication key into string format.
>>
>>>```
    pkey = open(pkeyPath ,'rt')
    pkeyStr = pkey.read()
    pkey.close()
```
>>
>>- Give the authentication key passphrase.
>>
>>>```
	privateKeyPassphrase = 'apassphrasetokeep'
```
>>
>>- Init' the pki.
>> 
>>>```
	# With default values
		pki = PyKI(authKeypass=privateKeyPassphrase, privkeyStr=pkeyStr)
>>>
	# Or with custom params
		pki = PyKI(issuerName='PyKI_example', authKeypass=privateKeyPassphrase, authKeylen = 1024, KEY_SIZE = 1024, SIGN_ALGO = 'SHA1')
```

### 2. Verbosity
> If you need/want to set verbose mode, you can do it these ways:
>> \- Any time after having called PyKI class: _**pki.set\_verbosity(True)**_
>> 
>> \- During PyKI class calling: _**PyKI(verbose = True, ...)**_

### 3. Callable vars
>_You will have to get them like this: **pki.[name]**_ 
>
>>* **srvCRTdir** : Get the directory path for server certificates
* **cltCRTdir** : Get the directory path for client certificates
* **crtsDir**   : Get the directory path for the pki certificates
* **initPkey**  : Retrieve authentication private key (**_Usable only at first init_**)
* **pkidbDict** : Get pki db as Dict
* **nameList**  : Retrieve list of certificates names
>
>_You will have to set them like this: **pki.[name]='value'**_
>
>>* **pkeysize**  : Set private key size
* **crtenc**    : Set certificate encryption algorithm
* **keycipher** : Set private key passphrase cipher encyption
* **crlenc**    : Set crl encryption algorithm

### 4. Generate a private key
> This stage is mandatory because it will generate a private key to be able to generate a certificate later.
>
**Parameters**:
>>* **passphrase (_string_)**: Private key encryption passphrase. Can be leave as None to generate an unprotected key (not recommended).  
* **keysize (_int_)**: Private key encryption length. Must be in [1024,2048,4096,8192].  
* **name (_string_)**: Private key name which must match the certificate common name.  
* **usage (_string_)**: Set the certificate usage type.  
    _Can be: **serverAuth** or **clientAuth** or **None**. Default: **serverAuth**_.  
* **ca (_boolean_)**: Indicate if the key will be use to generate a CA type certificate.  
>
**Return**:
>>Informational result dict: _{'error': Boolean, 'message': String}_
>
**Example**:
>>```
	# Init pki using 'Usual PKI init' (section 1) example and then
	key = pki.create_key(passphrase='azerty', keysize=1024, name="www.ritano.fr", usage="serverAuth")
	if key['error'] :
		print(key['message'])
		print("ERROR: Unable to generate key "+name+" properly, aborting...")
		exit(1)
	else:
		print(key['message'])
		print("INFO: Key "+name+" generated.")
```

### 5. Generate a TLS certificate
> Create a PEM X509 signed certificate.
>
**Parameters**:
>>* **country (_string_)**: Certificate country information.
* **state (_string_)**: Certificate state information.
* **city (_string_)**: Certificate city information.
* **org (_string_)**: Certificate organization information.
* **ou (_string_)**: Certificate organization unit information.
* **email (_string_)**: Certificate administrator e-mail information.
* **subjectAltName (_list of string_)**: Certificate Subject Alt-names extension. Must be in this format ___[ 'type:value' ]___ and types are '**email**', '**URI**', '**IP**', '**DNS**'.
* **cn (_string_)**: Certificate Common Name.
* **encryption (_string_)**: Certificate encryption (SHA1/SHA256/SHA512).
* **ca (_boolean_)**: Indicate if the key will be use to generate a CA type certificate.
* **valid\_before (_int_)**: Allow to generate a certificate which will be valid (from now) in number of days in the futur.
* **days\_valid (_int_)**: Set the periode, in days, during which the certfiicate will be valid. If valid_before is specified the validity will start at valid_before time .
* **KeyUsage (_string_)**: Set the certificate usage purpose. Could be for server (serverAuth) or client authentication(clientAuth), if not specified, the certificate will support both.
>
**Return**:
>>Informational result dict: _{'error': Boolean, 'message': String}_
>
**Example**:
>>```
	# Init pki using 'Usual PKI init' (section 1) example and then
	cert = pki.create_cert(
                       country = 'FR', state = 'PACA', city = 'Antibes',
                       org = 'Maibach.fr', ou = 'IT',
                       email = 'alain@maibach.fr',
                       KeyUsage = 'serverAuth',
                       subjectAltName = ['DNS:www.ritano.fr', 'DNS:wiki.maibach.fr', 'IP:10.0.0.1'],
                       cn = 'www.ritano.fr',
                       encryption = 'sha1',
                       days_valid = '180'
                      )
	if cert['error'] :
		print("ERROR: Unable to generate certificate "+name+" properly --> "+cert['message']+", aborting...")
		return(False)
	else:
		print(cert['message'])
```

### 6. Remove passphrase
> Removing passphrase from certificate.
>
**Parameters**:
>>* **keyname (_string_)**: PKI certificate name associated to the private key.
* **privKeypass (_string_)**: Private key passphrase.
>
**Return**:
>>Informational result dict: _{'error': Boolean, 'message': String}_
>
**Example**:
>>```
	# Init pki using 'Usual PKI init' (section 1) example and then
	pki.unprotect_key(keyname = 'www.ritano.fr', privKeypass = 'azerty')
	if unprotectres['error']:
		print(unprotectres['message'])
		return(False)
	print(unprotectres['message'])
```

### 7. Get certificate informations
> Get all certificate informations and added extensions.
>
**Parameters**:
>>* **certname (_string_)**: certificate name in the PKI.
>
**Return**:
>>Informational result dict _{'error': Boolean, 'message': Formatted string containing all certificate text infos}_
>
**Example**:
>>```
	# Init pki using 'Usual PKI init' (section 1) example and then
	cert_info = pki.get_certinfo('www.ritano.fr')
	if cert_info['error']:
		print(cert_info['message'])
	else:
		print("\n"+cert_info['message'])
```

### 8. Check certificate validity
> Check if the certificate is still valid (not revoked and not expired).
>
**Parameters**:
>>* **cert (_string_)**: Certificate file path to check.
>
**Return**:
>>Informational result dict: _{'error': Boolean, 'message': String}_
>
**Example**:
>>```
	# Init pki using 'Usual PKI init' (section 1) example and then
	name = 'www.ritano.fr'
	valid = pki.chk_validity(name)
	if valid['error']:
		print(valid['message'])
	else:
		print("Success "+valid['message'])
```

### 9. Check certificate conformity
> Check if the certificate has been generated by the current PKI.
>
**Parameters**:
>>* **cert (_string_)**: Certificate file path to check.
>
**Return**:
>>Informational result dict: _{'error': Boolean, 'message': String}_
>
**Example**:
>>```
	# Init pki using 'Usual PKI init' (section 1) example and then
	conform = pki.chk_conformity(cert="/opt/PyKI_data/CERTS/servers/www.ritano.fr/www.ritano.fr.crt")
	if conform['error']:
		print(conform['message'])
	else:
		print("Success "+conform['message'])
```

### 10. Check private key vs. certificate
> Check that your private key match the certificate.
>
**Parameters**:
>>* **cert (_string_)**: Certificate file path.
* **key (_string_)**: Private key file path.
* **keypass (_string_)**: Private key passphrase if needed.
>
**Return**:
>>Informational result dict: _{'error': Boolean, 'message': String}_
>
**Example**:
>>```
	# Init pki using 'Usual PKI init' (section 1) example and then
	passphrase = 'azerty'
	# if you do not specify it, and the key is encrypted, you will be prompted for it
	#passphrase = None
	reschk = pki.check_cer_vs_key(
		cert="/opt/PyKI_data/CERTS/signed/test_gencsr/test_gencsr.crt",
		key="/opt/PyKI_data/CERTS/requests/test_gencsr/test_gencsr.key",
		keypass = passphrase
	)
	if reschk['error']:
		print(reschk['message'])
	elif mainVerbosity:
		print(reschk['message'])
```

### 11. Create a PKCS12 file
> Create a PKCS12 file for the PKI certificate name specified.
>
**Parameters**:
>>* **pkcs12name (_string_)**: PKI existing certificate name.
* **pkcs12pwd (_string_)**: PKCS12 file password.
>
**Return**:
>>Informational result dict: _{'error': Boolean, 'message': String}_
>
**Example**:
>>```
	# Init pki using 'Usual PKI init' (section 1) example and then
	clientpkcs12 = pki.create_pkcs12(pkcs12pwd='azerty', pkcs12name='www.ritano.fr')
    if clientpkcs12['error']:
        print(clientpkcs12['message'])
    else:
        print("Success "+clientpkcs12['message'])
```

### 12. Extract a PKCS12 file
> Try to extract ca, certificate and private key from a PKCS12 file, to a specified destination.
>
**Parameters**:
>>* **pkcs12file (_string_)**: PKCS12 file path to extract.
* **pkcs12pwd (_string_)**: PKCS12 file password.
* **destdir (_string_)**: Extracted files destination directory.
* **inPrivKeypass (_string_)**: private key passphrase if the key is protected.
>
**Return**:
>>Informational result dict: _{'error': Boolean, 'message': String}_
>
**Example**:
>>```
	# Init pki using 'Usual PKI init' (section 1) example and then
	extractres = pki.extract_pkcs12(
	 								pkcs12file='/opt/PyKI_data/CERTS/servers/www.ritano.fr/www.ritano.fr.p12',
	 								pkcs12pwd='azerty',
	 								destdir=pkcsfile+'_extracted/'
	 							   )
	if extractres['error']:
		print(extractres['message'])
	elif mainVerbosity:
		print(extractres['message'])
```

### 13. Revoke a certificate
> Revoke a certificate with a revoking reason, remove all related files and regenerate the PKI crl.
>
**Parameters**:
>>* **certname (_string_)**: Certificaten name in PKI.
* **next\_crl\_days (_int_)**: Number of days to add for CRL expiry due to the CRL update.
* **reason (_bytes_)**: Certificate revocation reason to set in the CRL.  
Must be in [ ***unspecified, keyCompromise, CACompromise, affiliationChanged,superseded, cessationOfOperation, certificateHold*** ] .
>
**Return**:
>>Informational result dict: _{'error': Boolean, 'message': String}_
>
**Example**:
>>```
	# Init pki using 'Usual PKI init' (section 1) example and then
	crl = pki.revoke_cert(certname='www.ritano.fr', reason = "cessationOfOperation")
	if crl['error']:
		print(crl['message'])
	else:
		print("Success "+crl['message'])
```

### 14. Generate CSR
> Generate a private key and it's Certificate Signing Request.
>
**Parameters**:
>>* **passphrase (_string_)**: Private key passphrase.
* **country (_string_)**: Certificate country information.
* **subjectAltName (_list of string_)**: Certificate Subject Alt-names extension. Must be in this format ***[ 'type:value' ]*** and types are '**email**', '**URI**', '**IP**', '**DNS**'.
* **state (_string_)**: Certificate state information.
* **city (_string_)**: Certificate city information.
* **org (_string_)**: Certificate organization information.
* **ou (_string_)**: Certificate organization unit information.
* **cn (_string_)**: Certificate Common Name.
* **email (_string_)**: Certificate administrator e-mail information.
* **encryption (_string_)**: Private key encryption (SHA1/SHA256/SHA512).
* **keysize (_int_)**: Private key size must be in [1024-8192].
>
**Return**:
>>Informational result dict: _{'error': Boolean, 'message': String}_
>
**Example**:
>>```
	# Init pki using 'Usual PKI init' _(section 1)_ example and then
	# create with a private key size of 1024.
	csr = pki.create_csr(
                     	 passphrase = 'azerty',
                     	 country = 'BE', state = 'Antwerp', city = 'Mechelen',
                     	 org = 'In Serf we trust, Inc.', ou = 'Test Suite Server',
                     	 email = 'serfclient@example.com',
                     	 cn = 'test_gencsr',
                     	 encryption = 'SHA1',
                     	 keysize = 1024,
                     	 subjectAltName = ['DNS:test_gencsr', 'IP:10.0.0.1']
                    	)
	if csr['error']:
		print(csr['message'])
	else:
		print('Success '+csr['message'])
```

### 15. Print Certificate Signing Request informations
> Print all Certificate Signing Request informations matching PKI name csr (_work only for csr generated by the pki_).
>
**Parameters**:
>>* **csrname (_string_)**: CSR name in the PKI.
>
**Return**:
>>Informational result dict _{ 'error': Boolean, 'message': Formatted string containing all csr text infos }_
>
**Example**:
>>```
	# Init pki using 'Usual PKI init' (section 1) example and then
	csr_info = pki.get_csrinfo('test_gencsr')
	if csr_info['error']:
		print(csr_info['message'])
	else:
		print("Success\n"+csr_info['message'])
```

### 16. Sign Certificate Signing Request
> Signing a CSR file with a defined validity duration and add it to the PKI.
>
**Parameters**:
>>* **csr (_string_)**: Certificate Signing Request file path.
* **encryption (_string_)**: Certificate encryption (SHA1/SHA256/SHA512).
* **valid\_before (_int_)**: Allow to generate a certificate which will be valid (from current time) in number of days in the future.
* **days\_valid (_int_)**: Set the periode, in days, during which the certfiicate will be valid. If valid\_before is specified the validity will start at valid_before time .
* **KeyUsage (_string_)**: Set the certificate usage purpose. Could be for server (serverAuth) or client authentication(clientAuth), if not specified, the certificate will support both.
>
**Return**:
>>Informational result dict: _{'error': Boolean, 'message': String}_
>
**Example**:
>>```
	# Init pki using 'Usual PKI init' (section 1) example and then
	# Signing Certificate Request for 90 days of validity
	signRes = pki.sign_csr(
		csr="/opt/PyKI_data/CERTS/requests/test_gencsr/test_gencsr.csr",
    	KeyUsage = "clientAuth",
    	days_valid = 90,
    	encryption = "SHA1"
	)
	if signRes['error'] :
		print("ERROR: Unable to generate certificate for csr "+csrpath+" properly --> "+signRes['message']+", aborting...")
	elif mainVerbosity:
		print(signRes['message'])
```

### 17. Extend CRL duration
> Updating CRL expiry to X days from current time (same as if we would renew it before it expires).
>
**Parameters**:
>>* **next\_crl\_days (_int_)**: Number of days to add for CRL expiry.
>
**Return**:
>>Informational result dict: _{'error': Boolean, 'message': String}_
>
**Example**:
>>```
	# Init pki using 'Usual PKI init' (section 1) example and then
	# Updating crl expiry to 360 days
    extend = pki.extend_crl_date(next_crl_days = 360)
    if extend['error']:
        print(extend['message'])
    else:
        print('Success '+extend['message'])
```

### 18. PKI certificates database
> This will allow you to consult PKI certificates database easyly. Mainly to get informations against certificates status.
>
**Parameters**:
>>None
>
**Return**:
>>Informational result dict: _{'error': Boolean, 'message': String}_
>
**Example**:
>>```
	# Init pki using 'Usual PKI init' (section 1) example and then
>>
	# Get pki database info into list
	pkidb = pki.pkidbDict
>>
    # for sorting names before printing datas
    certsname = []
    for certname in pkidb:
        certsname.append(certname)
    # sort list insensitively
    certsname.sort(key=lambda x: x.lower())
>>
    # process name list to print datas
    for name in certsname:
        status = pkidb[name]['state']
        serial = pkidb[name]['serial']
        validity_time = pkidb[name]['duration']
        cert_shasum = pkidb[name]['shasum']
        cert_usage = pkidb[name]['type']
        cert_encrytion = pkidb[name]['shaenc']
        creation_date = pkidb[name]['created']
>>
        print(
              'Certificate name: ' +name+ '\n',
              '\tCertificate state: ' +status+ '\n',
              '\tCertificate serial number: ', serial, '\n',
              '\tCertificate creation date: ' +creation_date+ '\n',
              '\tDays of validity after creation: ', validity_time, '\n',
              '\tCertificate sha sum: ' +cert_shasum+ '\n',
              '\tCertificate usage type: ' +cert_usage+ '\n',
              '\tCertificate encrytpion level: ' +cert_encrytion
        )
```

### 19. List certificates name
> List all certificates names, except for revoked, present in the PKI database.
>
**Parameters**:
>>None
>
**Return**:
>>Informational result dict: _{'error': Boolean, 'message': String}_
>
**Example**:
>>```
	# Init pki using 'Usual PKI init' (section 1) example and then
	print("List of PKI certificate names:")
	for name in pki.nameList:
		print("\t" + str(name))
```

### 20. Retrieve certificates passphrases
> All certificates passphrases are stored securely (encrypted with AES). This module will allow you to get them. These are only readable if the PKI is correctly instanciated _(the init authentication must be successfull)_.
>
**Parameters**:
>>None
>
**Return**:
>>Informational result dict: _{'error': Boolean, 'message': String}_
>
**Example**:
>>```
	# Init pki using 'Usual PKI init' (section 1) example and then
	# Retrieve certificates passphrases into list
	passphrases = pki.loadpassDB()
	if not passphrases['error']:
		print("\nList of passphrases stored:")
		for passphrase in passphrases['message']:
			print( 'Certificate Name: '+passphrase+' / passphrase: '+ passphrases['message'][passphrase] )
	# Cleaning passphrases list to avoid keeping it in memory
	passphrases.clear()
```

## Tips

### Global informations
> All functions return dict with 2 items: {'error': Boolean, 'message': String}.

### Certificates format
> The PKI creates RSA certificates in PEM format.

### Class init'
> We can redefine static params, concerning encryption, in the class init to enforce certificate security.  
For example we can manage the cryptographic algo setup with **self.\_\_KEY\_ALGO = crypto.TYPE\_RSA** .

### PKI lock file
> A lock is filed, during the class calling, into /opt/PyKI/pki.lock to avoid a concurrent usage.  
> While this lock is present, the PKI will be unusable by other.  

> A walkout mode can be set, based on this behavior.

### PKCS warnings
> - Be carefull when creating a PKCS file, the private key in it will be unprotected.  
> - Remember that the PKCS file is password protected.

### Certificates database
> Pkicert.db contains hashes whith an encryption Setd by HASH\_ENC.  
> By default it is hashed in ***'SHA1'***.  
> The PKI certificate names list can be retrieve by reading PyKI class var: 'nameList' (_see Section 19 of PKI usage_).

### PKI Passphrases database
> The store file '**pkipass.db**' contains encrypted passphrases of all private key for all certificates and certificate requests, generated by this pki.  
>
_Not any passwords for private keys are mandatory but strongly recommended ._

### Updating CA or Intermediate certificate
> If the CA root or intermedaire are expired, you'll just have to suppress the related certificate and init again the pki.
The certificate is generated from the existing private key (_which you **MUST** keep safely_).  
>
___Warning___:
>
>- During the pki init, take care of using same infos as previously used (City, Organisation, CN and so...).
> 
_During the init, the CA certificates are checked and generated._

### Testing your installation
> _Everything must run with no errors._
> 
```
#!/usr/bin/env bash
>
# Used to test all PKI funcs
>
./test/test-UseCase.py
>
./test/test-gen_cert.py
./test/test-removePass.py
./test/test-create_pkcs12.py
./test/test-extract_pkcs12.py
./test/test-revoke_cert.py
>
./test/test-gen_csr.py
./test/test-sign_csr.py
./test/test-is_conform.py
./test/test-check_key_vs_cert.py
>
./test/test-get_infocert.py
./test/test-get_inforeq.py
./test/test-get_validity.py
>
./test/test-extend_crl.py
./test/test-get_passphrases.py
./test/test-read_pki_db.py
>
rm -r /opt/PyKI_data/

### Usefull links
>
* [OpenSSL x509 extensions config](https://www.openssl.org/docs/manmaster/apps/x509v3_config.html)
>
* [PKI RFC5280](https://tools.ietf.org/html/rfc5280)
>
* [Key Usage x509 extension infos](https://www.ibm.com/support/knowledgecenter/en/SSKTMJ_8.0.1/com.ibm.help.domino.admin.doc/DOC/H_KEY_USAGE_EXTENSIONS_FOR_INTERNET_CERTIFICATES_1521_OVER.html?cp=SSQ2R2_9.5.0)
