/pinfo->key_reference == 1/ {
    print "\t\t\t\tif (pinfo->key_reference == 0) {"
    print "\t\t\t\t\tsc_pkcs15_remove_object(p15card, objs[i]);"
    print "\t\t\t\t}"
    print $0
    next
}
{print}
