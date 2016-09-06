This tool set will make your life easier.
The goal is to simplify and automate the pki usage.

The first important part of this set is the init module named
'PyKInit'.
This module is ruled by an ini configuraiton file, which will 
contains the pki init related informations.

At first use, it will do anything you need to create your pki and
will help you to store these informations in order to reuse them quickly.

Take a look, in the PyKInit/ directory, at config_example.ini. A similar default config.ini
will be generated at first use and you will be asked to fill it correctly before go on.
The [pki auth] section set all parameters related to pki authentication in order to load it.
the [pki params] section set all parameters related to certificates and private key security default behaviors.

Remember that all parameters generated at PKI init can be overriden during specific operations like generating certificate, creating a pkcs and more..

Now that the init is correctly set up, you will be able to use every tools built in the tools directory.

# Just one last TIPS: The field passphrase can be left empty; if you do so, you will have to give the pki authentication password each time you'll call the class.


To use the PyKInit, you will have to add it to your syspath like that:
```
from sys import path as syspath
from os import path as ospath
curScriptDir = ospath.dirname(ospath.abspath(__file__))
initPath = curScriptDir + "/PyKInit/"
syspath.append(initPath)
from PyKInit import pkinit
```

Now init the pki like this:
```
pki=pkinit()
```

If you want to specify a file path for config.ini, do it as:
```
pki=pkinit('path/to/file/config.ini')
```

You will be returning True if all goes well.

## generate a certificate with specific information:
```
./gen_cert.py -n www.ritano.fr -p server -c AU -st california -l "los angeles" -o "test corpo" -ou IT -e dodoo@gg.fr --altnames IP:192.168.10.1 DNS:ldap.ritano.fr -v
```
* renew a certificate specifying key size and duration but using globales information for C, ST... (set in config.ini)
```
./gen_cert.py -n vpn3-mp.ritano.fr -p client -d 180 --key-size 2048 -r
```
* renew the certificate to modify locality ('l' field in certificate). The current certificate will be revoked immediately (no -b option specified).
```
./gen_cert.py -n vpn3-mp.ritano.fr -p client -r -d 180 --key-size 2048 --city Paris
```
* renewing certificate choosing a date for the renewal to start on. This will revocate the current certificate on 09/09/2016 at 23:59:59 and begin the new cert at 09/09/2016 with your current time (generating certificate time(hour:min:sec))
```
./gen_cert.py --cn vpn3-mp.ritano.fr -p server -r -b "09/09/2016"
```

## generate csr:
```
./gen_csr.py -n www.ritano.fr -c AU -st california -l "los angeles" -o "test corpo" -ou IT -e dodoo@gg.fr --altnames IP:192.168.10.1 DNS:ldap.ritano.fr -v
```

## get csr info
# specifying csr full path
```
./PyKItools/get_inforeq.py -f /opt/PyKI_data/CERTS/requests/www.ritano.fr/www.ritano.fr.csr
```
# using PKI name (in case that you have generated the csr with the PKI)
```
./PyKItools/get_inforeq.py -n www.ritano.fr
```

