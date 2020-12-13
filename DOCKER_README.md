Pyki's docker usage
===================

## Setup the service

> Keep the private key, in the PKI_AUTH section, secret and in a safe place.
>
> You may remove the passphrase from the pyki-configuration
> file to be prompted each time you invoke the PKI and
> increase the security of your data.

```bash
mkdir -p ./pyki_data/certs_stuff/

YOURSTRONGPASSPHRASE="AlgebraOntoScheduleWreckerScroungerGentileAcclaim"

cat > "./pyki_data/pyki-config.ini" << EOF
[DEFAULT]
verbose: ON

[pki auth]
key length: 4096
private key: /opt/PykI/pki_auth_cert.pem
passphrase: $YOURSTRONGPASSPHRASE

[pki params]
c: My country
st: My state
l: My f***** city
o: amaibach
ou: IT
email: ******@***.com
issuer: PyKI_docker
private key size: 4096
certificate encryption: SHA512
private key cipher: des3
crl encryption: sha256
EOF
```


## Start your service

```bash
$ docker-compose build --force-rm --compress
$ docker-compose up --no-build --no-start
$ docker-compose start
```


## Init the PKI

docker exec -it pyki pyki-init


## Execute actions:

- $ docker exec -it pyki "[command](##commands)"

 - Generate a new cert with: `docker exec -it pyki pyki-gen_cert`

     For a web server:
     ```bash
     docker exec -it pyki bash -c 'pyki-gen_cert -n global.local.net -p web -k keyEncipherment,dataEncipherment -a DNS:*.local.net'
     docker exec -it pyki bash -c 'pyki-removePass -n global.local.net'

     docker exec -it pyki bash -c '
     pyki-get_validity -n global.local.net
     '
     ```

     For an OPENVPN server:
     ```bash
     docker exec -it pyki bash -c 'pyki-gen_cert -n global.local.net -p server -k keyEncipherment,dataEncipherment -a DNS:*.local.net'
     docker exec -it pyki bash -c 'pyki-gen_cert -n global.local.net -p client -k keyEncipherment,dataEncipherment -a DNS:*.local.net'
     docker exec -it pyki bash -c 'pyki-gen_cert -n global.local.net -p both -k keyEncipherment,dataEncipherment -a DNS:*.local.net'
     docker exec -it pyki bash -c 'pyki-removePass -n global.local.net'
     ```

 Add the flag -r to renew the certificate.


## Commands:

- pyki-init
- pyki-check_key_vs_cert
- pyki-create_pkcs12
- pyki-extract_pkcs12
- pyki-gen_cert
- pyki-gen_csr
- pyki-get_infocert
- pyki-get_inforeq
- pyki-get_nameList
- pyki-get_passphrases -->
    If you do not use removePass command, you will need these to figure out which passphrae encrypt your certificate.
- pyki-get_validity
- pyki-is_conform
- pyki-read_crl
- pyki-read_pki_db
- pyki-removePass
- pyki-renew_crl
- pyki-revoke_cert
- pyki-sign_csr


## Remove your deployment

```bash
$ docker-compose down
```

## Re-build if necessary

- To force image re-build after having deployed, you can execute this command:

```bash
$ docker-compose build --compress --force-rm --pull --no-cache
```
