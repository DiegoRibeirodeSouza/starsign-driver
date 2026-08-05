#!/bin/bash
export PJE_MODE=full
export PJE_SIGNER_PRIORITY=pkcs11
export PJE_PKCS11_MODULE=/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so

echo "=== INICIANDO PJe Headless ==="
if [ -z "$PJE_PKCS11_PIN" ]; then
    read -s -p "Digite o PIN do token A3: " PJE_PKCS11_PIN
    echo ""
    export PJE_PKCS11_PIN
fi

/tmp/pje_headless/bin/pjeheadless
