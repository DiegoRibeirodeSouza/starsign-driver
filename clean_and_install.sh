#!/bin/bash
echo "Removendo drivers opensc atuais..."
apt-get remove --purge -y opensc opensc-pkcs11
echo "Limpando possiveis instalacoes manuais..."
rm -f /usr/local/lib/opensc*
rm -f /usr/local/lib/pkcs11/opensc*
echo "Instalando versão da madrugada (05/08)..."
dpkg -i /home/diego/Documentos/starsign-driver/opensc_0.26.1-2+open.a3.2_amd64.deb /home/diego/Documentos/starsign-driver/opensc-pkcs11_0.26.1-2+open.a3.2_amd64.deb
echo "Reiniciando pcscd..."
systemctl restart pcscd
echo "Pronto!"
