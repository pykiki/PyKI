#!/usr/bin/env bash

# Used to test all PKI funcs

./test-UseCase.py
#
./test-gen_cert.py
./test-removePass.py
./test-create_pkcs12.py
./test-extract_pkcs12.py
./test-revoke_cert.py
#
./test-gen_csr.py
./test-sign_csr.py
./test-is_conform.py
./test-check_key_vs_cert.py
#
./test-get_infocert.py
./test-get_inforeq.py
./test-get_validity.py
#
./test-extend_crl.py
./test-get_passphrases.py
./test-read_pki_db.py
