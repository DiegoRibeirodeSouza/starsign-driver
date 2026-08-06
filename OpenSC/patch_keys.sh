#!/bin/bash
cat << 'INNER' > patch.awk
/pinfo->id = cinfo->id;/ {
    print "if (pinfo->key_reference == 1) {"
    print "    pinfo->id = cinfo->id;"
    print "    strncpy(objs[i]->label, cert_obj->label, sizeof(objs[i]->label));"
    print "}"
    next
}
/puinfo->id = cinfo->id;/ {
    print "if (puinfo->key_reference == 1) {"
    print "    puinfo->id = cinfo->id;"
    print "    strncpy(objs[i]->label, cert_obj->label, sizeof(objs[i]->label));"
    print "}"
    next
}
{print}
INNER
awk -f patch.awk src/libopensc/pkcs15-syn.c > temp.c
mv temp.c src/libopensc/pkcs15-syn.c
