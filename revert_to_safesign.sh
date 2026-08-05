#!/bin/bash
echo "Revertendo configuração do PAM para o driver proprietário (SafeSign)..."
sed -i 's|/usr/local/lib/opensc-pkcs11.so|/usr/lib/libaetpkss.so.3|g' /etc/pam_pkcs11/pam_pkcs11.conf

# Reverte a cert_policy (vamos manter em none apenas para garantir que o sudo funcione com o SafeSign sem problemas caso o cacerts esteja vazio)
# sed -i 's/cert_policy = none;/cert_policy = signature;/g' /etc/pam_pkcs11/pam_pkcs11.conf

echo "Reiniciando serviço pcscd..."
systemctl restart pcscd

echo "Revertendo NSSDB (Chrome/Thorium)..."
sudo -u $SUDO_USER modutil -dbdir sql:/home/$SUDO_USER/.pki/nssdb -delete "OpenSC" -force 2>/dev/null
sudo -u $SUDO_USER modutil -dbdir sql:/home/$SUDO_USER/.pki/nssdb -add "SafeSign" -libfile /usr/lib/libaetpkss.so.3 -force 2>/dev/null

echo "Rollback concluído! O seu sistema voltou a usar o SafeSign (proprietário)."
