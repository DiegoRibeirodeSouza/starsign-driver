#!/bin/bash
MODULE="/usr/local/lib/opensc-pkcs11.so"

# Chrome / Thorium usam o NSSDB do usuário local
if [ -d "$HOME/.pki/nssdb" ]; then
    echo "Registrando no banco NSS local (~/.pki/nssdb)..."
    # Tenta deletar caso já exista uma entrada antiga
    modutil -dbdir sql:$HOME/.pki/nssdb -delete "OpenSC" -force 2>/dev/null
    # Adiciona a versão final instalada no sistema
    modutil -dbdir sql:$HOME/.pki/nssdb -add "OpenSC" -libfile $MODULE -force
else
    echo "Banco de dados NSS não encontrado em ~/.pki/nssdb"
fi
