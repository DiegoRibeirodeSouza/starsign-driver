#!/bin/bash
sed -i 's/cert_policy = .*/cert_policy = none;/g' /etc/pam_pkcs11/pam_pkcs11.conf
echo "Cert policy atualizado para none!"
