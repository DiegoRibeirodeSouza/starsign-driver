#!/bin/bash
sed -i 's/unsigned long alg_flags = SC_ALGORITHM_RSA_RAW | SC_ALGORITHM_RSA_PAD_PKCS1/unsigned long alg_flags = SC_ALGORITHM_RSA_PAD_PKCS1/' src/libopensc/card-starsign.c

sed -i '/u8 data\[6\] =/c\
                u8 key_ref = env->key_ref[0];\
                u8 alg_ref = 0x02;\
                u8 data[6] = { 0x84, 0x01, key_ref, 0x80, 0x01, alg_ref };' src/libopensc/card-starsign.c
