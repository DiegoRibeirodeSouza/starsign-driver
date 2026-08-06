/*
 * Support for G&D StarSign CUT S cards (A.E.T. Europe SafeSign)
 *
 * This driver performs the proprietary DRM handshake and logical
 * channel selection required by the StarSign CUT S token.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <string.h>
#include <stdlib.h>

#include "internal.h"
#include "asn1.h"
#include "log.h"

static const struct sc_atr_table starsign_atrs[] = {
	{ "3B:F9:96:00:00:81:31:FE:45:53:43:45:37:20:0E:00:20:20:28", NULL, NULL, SC_CARD_TYPE_STARSIGN, 0, NULL },
	{ NULL, NULL, NULL, 0, 0, NULL }
};

static struct sc_card_operations starsign_ops;
static struct sc_card_driver starsign_drv = {
	"G&D StarSign CUT S",
	"starsign",
	&starsign_ops,
	NULL, 0, NULL
};

static const u8 starsign_drm_string[] = "I am A.E.T. Europe B.V. SafeSign or BlueX approved software.";

static int starsign_match_card(sc_card_t *card)
{
	int i;
	i = _sc_match_atr(card, starsign_atrs, &card->type);
	if (i < 0)
		return 0;
	return 1;
}

static int starsign_init(sc_card_t *card)
{
	sc_apdu_t apdu;
	u8 rbuf[SC_MAX_APDU_BUFFER_SIZE];
	int r;

	card->name = "G&D StarSign CUT S";
	card->type = SC_CARD_TYPE_STARSIGN;

	/* 1. First DRM Handshake (ignore result, usually 6D 00) */
	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0xDA, 0x01, 0x00);
	apdu.data = starsign_drm_string;
	apdu.datalen = sizeof(starsign_drm_string) - 1;
	apdu.lc = apdu.datalen;
	r = sc_transmit_apdu(card, &apdu);
	if (r < 0) return r;

	/* 2. Select PKCS#15 AID (ignore result) */
	u8 aid[] = { 0xA0, 0x00, 0x00, 0x00, 0x63, 0x50, 0x4B, 0x43, 0x53, 0x2D, 0x31, 0x35 };
	sc_format_apdu(card, &apdu, SC_APDU_CASE_4_SHORT, 0xA4, 0x04, 0x00);
	apdu.data = aid;
	apdu.datalen = sizeof(aid);
	apdu.lc = sizeof(aid);
	apdu.le = 256;
	apdu.resplen = sizeof(rbuf);
	apdu.resp = rbuf;
	r = sc_transmit_apdu(card, &apdu);
	if (r < 0) return r;

	/* 3. Second DRM Handshake (ignore result) */
	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0xDA, 0x01, 0x00);
	apdu.data = starsign_drm_string;
	apdu.datalen = sizeof(starsign_drm_string) - 1;
	apdu.lc = apdu.datalen;
	r = sc_transmit_apdu(card, &apdu);
	if (r < 0) return r;

	/* 4. Open Logical Channel 1 */
	sc_format_apdu(card, &apdu, SC_APDU_CASE_2_SHORT, 0x70, 0x00, 0x00);
	apdu.resp = rbuf;
	apdu.resplen = sizeof(rbuf);
	apdu.le = 1;

	r = sc_transmit_apdu(card, &apdu);
	if (r < 0) return r;
	
	if (apdu.sw1 == 0x6A && apdu.sw2 == 0x81) {
		/* Channel already open, that's fine */
		r = SC_SUCCESS;
	} else {
		r = sc_check_sw(card, apdu.sw1, apdu.sw2);
		if (r != SC_SUCCESS) return r;
	}

	/* 5. Force CLA=0x01 for all subsequent operations */
	card->cla = 0x01;

	/* 6. Select PKCS#15 AID again on Channel 1 */
	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0xA4, 0x04, 0x00);
	apdu.data = aid;
	apdu.datalen = sizeof(aid);
	apdu.lc = sizeof(aid);
	r = sc_transmit_apdu(card, &apdu);
	if (r < 0) return r;
	r = sc_check_sw(card, apdu.sw1, apdu.sw2);
	if (r != SC_SUCCESS) {
		sc_log(card->ctx, "Card refused AID selection on channel 1 (SW %02X %02X), ignoring as it might be already selected", apdu.sw1, apdu.sw2);
	}

	/* Force RAW RSA (software padding) because G&D StarSign CUT cards 
	   often return 67 00 if sent unpadded hashes during C_Sign.
	   We ONLY set SC_ALGORITHM_RSA_RAW so OpenSC pads the data to 256/512 bytes itself. */
	card->caps |= SC_CARD_CAP_APDU_EXT;
	card->max_send_size = 2048;
	card->max_recv_size = 2048;
	unsigned long alg_flags = SC_ALGORITHM_RSA_RAW;
				  
	_sc_card_add_rsa_alg(card, 1024, alg_flags, 0);
	_sc_card_add_rsa_alg(card, 2048, alg_flags, 0);
	_sc_card_add_rsa_alg(card, 4096, alg_flags, 0);

	return SC_SUCCESS;
}

static int starsign_select_file(sc_card_t *card, const sc_path_t *in_path, sc_file_t **file_out)
{
	int r = SC_SUCCESS;
	size_t i;
	struct sc_apdu apdu;

	if (in_path->type != SC_PATH_TYPE_PATH && in_path->type != SC_PATH_TYPE_FROM_CURRENT && in_path->type != SC_PATH_TYPE_FILE_ID) {
		sc_log(card->ctx, "STARSIGN SELECT FILE DEFERRING type=%d", in_path->type);
		return sc_get_iso7816_driver()->ops->select_file(card, in_path, file_out);
	}

	sc_log(card->ctx, "STARSIGN SELECT FILE EXECUTING type=%d len=%zu", in_path->type, in_path->len);

	if (in_path->len % 2 != 0 || in_path->len == 0)
		return SC_ERROR_INVALID_ARGUMENTS;

	/* First, try to select the full path at once if it's a full path from MF */
	if (in_path->len >= 4 && in_path->value[0] == 0x3F && in_path->value[1] == 0x00) {
		sc_log(card->ctx, "STARSIGN SELECT FILE: Attempting full path selection from MF");
		sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0xA4, 0x08, 0x0C);
		apdu.data = in_path->value;
		apdu.datalen = in_path->len;
		apdu.lc = in_path->len;
		r = sc_transmit_apdu(card, &apdu);
		if (r < 0) return r;
		r = sc_check_sw(card, apdu.sw1, apdu.sw2);
		if (r == SC_SUCCESS) {
			sc_log(card->ctx, "STARSIGN SELECT FILE: Full path selection successful");
			return SC_SUCCESS;
		}
		sc_log(card->ctx, "STARSIGN SELECT FILE: Full path selection failed (%d), falling back to component-by-component", r);
	}

	/* Loop over every 2 bytes of the path */
	for (i = 0; i < in_path->len; i += 2) {
		unsigned short fid = (in_path->value[i] << 8) | in_path->value[i + 1];

		/* DO NOT ignore 3F00! We need to select it to reset the current DF to MF.
		   HOWEVER, G&D StarSign tokens have a bug where some certificates' absolute paths
		   omit the 5015 DF. If we just select 3F00, the subsequent selection of 4302 will fail.
		   The safest fix is: when we see 3F00, we select 3F00 AND THEN select 5015 automatically! */
		if (fid == 0x3F00) {
			sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0xA4, 0x00, 0x0C);
			apdu.data = (const u8 *)"\x3F\x00";
			apdu.datalen = 2; apdu.lc = 2;
			r = sc_transmit_apdu(card, &apdu);
			if (r < 0) return r;
			
			sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0xA4, 0x00, 0x0C);
			apdu.data = (const u8 *)"\x50\x15";
			apdu.datalen = 2; apdu.lc = 2;
			r = sc_transmit_apdu(card, &apdu);
			if (r < 0) return r;
			continue;
		}
		/* Ignore virtual/intermediate DFs that are not selectable directly on G&D StarSign */
		if (fid == 0x3FFF) {
			sc_log(card->ctx, "STARSIGN SELECT FILE: IGNORING virtual DF %04X", fid);
			continue;
		}

		/* Determine if this is the last component of the path */
		int is_last = (i + 2 == in_path->len);
		
		/* P1=0x01 (Select DF) if not the last component, P1=0x02 (Select EF) if it is. 
		   Fallback to 0x00 if neither works. */
		int p1 = is_last ? 0x02 : 0x01;
		
		sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0xA4, p1, 0x0C); /* P2=0x0C means No response/FCI expected */
		apdu.data = &in_path->value[i];
		apdu.datalen = 2;
		apdu.lc = 2;

		r = sc_transmit_apdu(card, &apdu);
		if (r < 0) return r;
		r = sc_check_sw(card, apdu.sw1, apdu.sw2);
		
		/* Fallback loop */
		if (r == SC_ERROR_FILE_NOT_FOUND) {
			sc_log(card->ctx, "STARSIGN SELECT FILE: P1=0x%02X failed, retrying with P1=0x00 for FID %04X", p1, fid);
			sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0xA4, 0x00, 0x0C);
			apdu.data = &in_path->value[i];
			apdu.datalen = 2;
			apdu.lc = 2;

			r = sc_transmit_apdu(card, &apdu);
			if (r < 0) return r;
			r = sc_check_sw(card, apdu.sw1, apdu.sw2);
		}

		if (r < 0) return r;
	}

	if (file_out) {
		sc_file_t *file = sc_file_new();
		if (!file)
			return SC_ERROR_OUT_OF_MEMORY;
		file->id = (in_path->value[in_path->len - 2] << 8) | in_path->value[in_path->len - 1];
		file->type = SC_FILE_TYPE_WORKING_EF;
		file->ef_structure = SC_FILE_EF_TRANSPARENT;
		file->size = 0x8000; /* Dummy size so OpenSC reads until EOF */
		file->magic = SC_FILE_MAGIC;
		*file_out = file;
	}
	return SC_SUCCESS;
}

static int starsign_set_security_env(sc_card_t *card, const sc_security_env_t *env, int res)
{
	sc_apdu_t apdu;
	u8 sbuf[256];
	u8 *p;
	int r;

	sc_log(card->ctx, "STARSIGN: set_security_env called! Operation: %d", env->operation);

	if (card == NULL || env == NULL) {
		return SC_ERROR_INVALID_ARGUMENTS;
	}
	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0x22, 0x41, 0);
	apdu.cla = card->cla; /* PATCH FOR STARSIGN LOGICAL CHANNEL */

	switch (env->operation) {
	case SC_SEC_OPERATION_AUTHENTICATE:
		apdu.p2 = 0xA4;
		break;
	case SC_SEC_OPERATION_DECIPHER:
	case SC_SEC_OPERATION_DERIVE:
		apdu.p2 = 0xB8;
		break;
	case SC_SEC_OPERATION_SIGN:
		apdu.p2 = 0xB6;
		break;
	default:
		return SC_ERROR_INVALID_ARGUMENTS;
	}
	p = sbuf;
	if (env->flags & SC_SEC_ENV_ALG_REF_PRESENT) {
		*p++ = 0x80;	/* algorithm reference */
		*p++ = 0x01;
		*p++ = env->algorithm_ref & 0xFF;
	} else if (env->operation == SC_SEC_OPERATION_SIGN) {
		/* Force PKCS1 algorithm reference if missing (required by StarSign CUT S) */
		*p++ = 0x80;
		*p++ = 0x01;
		*p++ = 0x02; /* SC_ALGORITHM_RSA_PAD_PKCS1 */
	}
	if (env->flags & SC_SEC_ENV_FILE_REF_PRESENT) {
		if (env->file_ref.len > SC_MAX_PATH_SIZE)
			return SC_ERROR_INVALID_ARGUMENTS;
		if (sizeof(sbuf) - (p - sbuf) < env->file_ref.len + 2)
			return SC_ERROR_OFFSET_TOO_LARGE;

		*p++ = 0x81;
		*p++ = (u8) env->file_ref.len;
		memcpy(p, env->file_ref.value, env->file_ref.len);
		p += env->file_ref.len;
	}
	if (env->flags & SC_SEC_ENV_KEY_REF_PRESENT) {
		if (sizeof(sbuf) - (p - sbuf) < env->key_ref_len + 2)
			return SC_ERROR_OFFSET_TOO_LARGE;

		if (env->flags & SC_SEC_ENV_KEY_REF_SYMMETRIC)
			*p++ = 0x83;
		else
			*p++ = 0x84;
		if (env->key_ref_len > SC_MAX_KEYREF_SIZE)
			return SC_ERROR_INVALID_ARGUMENTS;
		*p++ = env->key_ref_len & 0xFF;
		memcpy(p, env->key_ref, env->key_ref_len);
		p += env->key_ref_len;
	}
	r = (int)(p - sbuf);
	apdu.lc = r;
	apdu.datalen = r;
	apdu.data = sbuf;
	apdu.resplen = 0;
	
	r = sc_transmit_apdu(card, &apdu);
	if (r < 0) return r;
	return sc_check_sw(card, apdu.sw1, apdu.sw2);
}

static int starsign_pin_cmd(sc_card_t *card, struct sc_pin_cmd_data *data)
{
	struct sc_apdu local_apdu;
	int r;
	u8 sbuf[SC_MAX_APDU_BUFFER_SIZE];

	if (data->cmd != SC_PIN_CMD_VERIFY)
		return sc_get_iso7816_driver()->ops->pin_cmd(card, data);

	if (data->apdu == NULL) {
		r = iso7816_build_pin_apdu(card, &local_apdu, data, sbuf, sizeof(sbuf));
		if (r < 0) return r;
		data->apdu = &local_apdu;
	}

	/* G&D StarSign requires PIN verification to be performed on the 
	 * specific logical channel (usually 1). The standard iso7816_pin_cmd 
	 * sends it on channel 0, which fails to unlock the keys on channel 1. */
	data->apdu->cla = card->cla;

	/* Transmit the APDU */
	r = sc_transmit_apdu(card, data->apdu);
	sc_mem_clear(sbuf, sizeof(sbuf));

	if (r < 0) return r;
	return sc_check_sw(card, data->apdu->sw1, data->apdu->sw2);
}

struct sc_card_driver * sc_get_starsign_driver(void)
{
	struct sc_card_driver *iso_drv = sc_get_iso7816_driver();
	starsign_ops = *iso_drv->ops;
	starsign_ops.init = starsign_init;
	starsign_ops.match_card = starsign_match_card;
	starsign_ops.select_file = starsign_select_file;
	starsign_ops.set_security_env = starsign_set_security_env;
	starsign_ops.pin_cmd = starsign_pin_cmd;
	return &starsign_drv;
}
