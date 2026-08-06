sed -i '/unsigned long alg_flags = SC_ALGORITHM_RSA_RAW;/i \        card->caps |= SC_CARD_CAP_APDU_EXT;\
        card->max_send_size = 2048;\
        card->max_recv_size = 2048;' src/libopensc/card-starsign.c
