#!/bin/bash
export OPENSC_DEBUG=9
./src/tools/pkcs11-tool --module ./src/pkcs11/.libs/opensc-pkcs11.so --sign --id 444945474f205249424549524f20444520534f555a4120323032342d31302d30392032303a32323a3235 -m RSA-PKCS -i data.txt -o data.sig > debug_pkcs11_sign.log 2>&1
