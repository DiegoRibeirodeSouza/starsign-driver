#!/bin/bash
export OPENSC_DEBUG=9
export PAM_PKCS11_DEBUG=1
pkcs11_inspect > debug_sign.log 2>&1
