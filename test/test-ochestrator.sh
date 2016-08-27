#!/usr/bin/env bash

# Used to test all PKI funcs

./UseCase.py
#
./gen_cert.py
./removePass.py
./create_pkcs12.py
./extract_pkcs12.py
./revoke_cert.py
#
./gen_csr.py
./sign_csr.py
./is_conform.py
./check_key_vs_cert.py
#
./get_infocert.py
./get_inforeq.py
./get_validity.py
#
./extend_crl.py
./get_passphrases.py
./read_pki_db.py
