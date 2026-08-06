#!/bin/bash
export OPENSC_DEBUG=9
export PAM_PKCS11_DEBUG=1
sudo echo "test" > debug_sudo.log 2>&1
