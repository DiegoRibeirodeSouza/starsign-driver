#!/bin/bash
sed -i 's/data\[2\] = env->key_ref\[0\];/data[2] = 0x01;/' src/libopensc/card-starsign.c
make -C src/libopensc && make -C src/pkcs11
