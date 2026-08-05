#!/bin/bash
cd /home/diego/Documentos/starsign-driver/OpenSC
make install
systemctl restart pcscd
sed -i 's|/home/diego/Documentos/starsign-driver/OpenSC/src/pkcs11/.libs/opensc-pkcs11.so|/usr/local/lib/opensc-pkcs11.so|g' /etc/pam_pkcs11/pam_pkcs11.conf
echo "Configuração do PAM atualizada!"
apt update
