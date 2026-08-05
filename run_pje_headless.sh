#!/bin/bash
export PJE_MODE=full
export PJE_SIGNER_PRIORITY=pkcs11
export PJE_PKCS11_MODULE=/home/diego/Documentos/starsign-driver/OpenSC/src/pkcs11/.libs/opensc-pkcs11.so

echo "=== INICIANDO PJe Headless ==="
# export OPENSC_DEBUG=9
# export OPENSC_DEBUG_FILE=/tmp/opensc-debug.log
if [ -z "$PJE_PKCS11_PIN" ]; then
    read -s -p "Digite o PIN do token A3: " PJE_PKCS11_PIN
    echo ""
    export PJE_PKCS11_PIN
fi

# Apontando para o binário recém-compilado nos Documentos
/home/diego/Documentos/pje_headless/pjeheadless