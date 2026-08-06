#!/bin/bash
sed -i '/pinfo->id = cinfo->id;/a \
\t\t\t\tstrncpy(objs[i]->label, cert_obj->label, sizeof(objs[i]->label));' src/libopensc/pkcs15-syn.c

sed -i '/puinfo->id = cinfo->id;/a \
\t\t\t\tstrncpy(objs[i]->label, cert_obj->label, sizeof(objs[i]->label));' src/libopensc/pkcs15-syn.c

make -C src/libopensc && make -C src/pkcs11
