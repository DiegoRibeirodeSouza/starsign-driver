sed -i '/static int starsign_set_security_env/,/^}/c \
static int starsign_set_security_env(sc_card_t *card, const sc_security_env_t *env, int res)\
{\
        sc_apdu_t apdu;\
        u8 data[6];\
        int r;\
\
        if (env->operation != SC_SEC_OPERATION_SIGN) {\
            return sc_get_iso7816_driver()->ops->set_security_env(card, env, res);\
        }\
\
        data[0] = 0x80;\
        data[1] = 0x01;\
        data[2] = 0x12;\
        data[3] = 0x84;\
        data[4] = 0x01;\
        data[5] = env->key_ref_len > 0 ? env->key_ref[0] : 0x00;\
\
        sc_format_apdu(card, \&apdu, SC_APDU_CASE_3_SHORT, 0x22, 0x41, 0xB6);\
        apdu.data = data;\
        apdu.datalen = 6;\
        apdu.lc = 6;\
\
        r = sc_transmit_apdu(card, \&apdu);\
        if (r) return r;\
        return sc_check_sw(card, apdu.sw1, apdu.sw2);\
}\
' src/libopensc/card-starsign.c
