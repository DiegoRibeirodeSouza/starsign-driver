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

/* Tracks the currently selected working directory so select_file() can
 * avoid redundant re-navigation:
 *  - df5031_selected: the PKCS#15 application DF (5031) is active, so an
 *    EF can be addressed as its direct child instead of re-navigating
 *    from the MF.
 *  - mid_fid/mid_fid_valid: the "virtual path" cert/data EFs (encoded as
 *    3F00 3FFF <mid DF> <final EF>, e.g. 3F00 3FFF 4302 05A0) live under a
 *    real DF (4302) one level below 5031. 0x3FFF itself is a placeholder
 *    that the card rejects with SW 6A82 if selected, but the mid DF is
 *    real and must be selected once — re-selecting it a second time while
 *    it is already the current DF ALSO fails with 6A82, so it is cached
 *    and only reselected when it actually changes. */
struct starsign_drv_data {
	int df5031_selected;
	u8 mid_fid[2];
	int mid_fid_valid;
};

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

	card->drv_data = calloc(1, sizeof(struct starsign_drv_data));
	if (!card->drv_data)
		return SC_ERROR_OUT_OF_MEMORY;

	/* 1. First DRM Handshake (ignore result, usually 6D 00) */
	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0xDA, 0x01, 0x00);
	apdu.data = starsign_drm_string;
	apdu.datalen = sizeof(starsign_drm_string) - 1;
	apdu.lc = apdu.datalen;
	r = sc_transmit_apdu(card, &apdu);
	if (r != SC_SUCCESS) return r;

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
	if (r != SC_SUCCESS) return r;

	/* 3. Second DRM Handshake (ignore result) */
	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0xDA, 0x01, 0x00);
	apdu.data = starsign_drm_string;
	apdu.datalen = sizeof(starsign_drm_string) - 1;
	apdu.lc = apdu.datalen;
	r = sc_transmit_apdu(card, &apdu);
	if (r != SC_SUCCESS) return r;

	/* 4. Open Logical Channel 1 */
	sc_format_apdu(card, &apdu, SC_APDU_CASE_2_SHORT, 0x70, 0x00, 0x00);
	apdu.resp = rbuf;
	apdu.resplen = sizeof(rbuf);
	apdu.le = 1;

	r = sc_transmit_apdu(card, &apdu);
	if (r != SC_SUCCESS) return r;
	
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
	if (r != SC_SUCCESS) return r;
	r = sc_check_sw(card, apdu.sw1, apdu.sw2);
	if (r != SC_SUCCESS) {
		if (apdu.sw1 == 0x6A && apdu.sw2 == 0x86) {
			sc_log(card->ctx, "Card refused AID selection on channel 1 (SW %02X %02X), ignoring as it might be already selected", apdu.sw1, apdu.sw2);
		} else {
			return r;
		}
	}

	/* Force RAW RSA (software padding) or allow on-card padding via hashes.
	   G&D StarSign CUT cards expect either a 256-byte payload (for 2048-bit keys) or a 32-byte hash. */
	card->caps |= SC_CARD_CAP_APDU_EXT;
	card->max_send_size = 2048;
	card->max_recv_size = 256;
	
	/* Patch reader limits directly to prevent apdu.c from falling back to Short APDUs */
	if (card->reader) {
		card->reader->max_send_size = 2048;
		/* Keep recv_size at 256 to prevent card from crashing on large reads during PKCS15 init */
		card->reader->max_recv_size = 256;
	}
	/* Do NOT advertise SC_ALGORITHM_RSA_HASH_* here. The card pads a raw
	 * hash it is given with PKCS#1 v1.5 (00 01 FF..FF 00 <hash>) but does
	 * NOT prepend the DigestInfo ASN.1/OID header a standards-compliant
	 * SHA256-RSA-PKCS signature requires — verified by decrypting a live
	 * signature with the token's own public key: the padded block held
	 * the bare SHA-256 digest with no DigestInfo prefix, so verifiers
	 * correctly reject it. Only advertise HASH_NONE so OpenSC's crypto
	 * layer builds the full DigestInfo+PKCS#1 block in software and hands
	 * the card an already-padded blob for a raw RSA operation. */
	unsigned long alg_flags = SC_ALGORITHM_RSA_RAW | SC_ALGORITHM_RSA_PAD_PKCS1 | SC_ALGORITHM_RSA_HASH_NONE;
				  
	_sc_card_add_rsa_alg(card, 1024, alg_flags, 0);
	_sc_card_add_rsa_alg(card, 2048, alg_flags, 0);
	_sc_card_add_rsa_alg(card, 4096, alg_flags, 0);

	return SC_SUCCESS;
}

/* Extract the file size from an FCP response of the form
 * 6F <len> 80 02 <size-hi> <size-lo> ... (tag 0x80 = number of data bytes).
 * Returns 0 if the tag is not present or the buffer is too short. */
static size_t starsign_parse_fcp_size(const u8 *buf, size_t len)
{
	size_t i;

	if (len < 2 || buf[0] != 0x6F)
		return 0;

	for (i = 2; i + 3 < len; ) {
		u8 tag = buf[i];
		u8 taglen = buf[i + 1];
		if (tag == 0x80 && taglen == 2 && i + 3 < len)
			return ((size_t)buf[i + 2] << 8) | buf[i + 3];
		i += 2 + taglen;
	}
	return 0;
}

static int starsign_select_ef_child(sc_card_t *card, const u8 *fid, size_t *file_size)
{
	int r;
	struct sc_apdu apdu;
	u8 rbuf[SC_MAX_APDU_BUFFER_SIZE];

	sc_format_apdu(card, &apdu, SC_APDU_CASE_4_SHORT, 0xA4, 0x02, 0x00);
	apdu.data = fid;
	apdu.datalen = 2;
	apdu.lc = 2;
	apdu.resp = rbuf;
	apdu.resplen = sizeof(rbuf);
	apdu.le = 256;

	r = sc_transmit_apdu(card, &apdu);
	if (r != SC_SUCCESS) return r;
	r = sc_check_sw(card, apdu.sw1, apdu.sw2);
	if (r != SC_SUCCESS) return r;

	if (file_size)
		*file_size = starsign_parse_fcp_size(apdu.resp, apdu.resplen);
	return SC_SUCCESS;
}

static int starsign_select_file(sc_card_t *card, const sc_path_t *in_path, sc_file_t **file_out)
{
	int r = SC_SUCCESS;
	size_t i;
	struct sc_apdu apdu;
	int selected_as_ef = 0;
	struct starsign_drv_data *priv = card->drv_data;
	int has_3fff_placeholder = 0;
	size_t resolved_size = 0;

	if (in_path->type != SC_PATH_TYPE_PATH && in_path->type != SC_PATH_TYPE_FROM_CURRENT && in_path->type != SC_PATH_TYPE_FILE_ID) {
		return sc_get_iso7816_driver()->ops->select_file(card, in_path, file_out);
	}

	if (in_path->len % 2 != 0 || in_path->len == 0)
		return SC_ERROR_INVALID_ARGUMENTS;

	for (i = 0; i + 2 < in_path->len; i += 2) {
		if (in_path->value[i] == 0x3F && in_path->value[i + 1] == 0xFF) {
			has_3fff_placeholder = 1;
			break;
		}
	}

	/* StarSign CUT S encodes some data/certificate paths with a 0x3FFF
	 * placeholder component (e.g. 3F00 3FFF 4302 05A0) that is not a real
	 * selectable file — the card answers SW 6A82 if it is ever selected.
	 * The component right after it (e.g. 4302) IS a real DF one level
	 * below the PKCS#15 application DF and must be selected once; doing
	 * so a second time while it is already the current DF also yields
	 * 6A82, so cache it and only reselect when it actually changes.
	 * The final component is then addressed as its direct child EF. */
	if (has_3fff_placeholder) {
		if (in_path->len < 8)
			return SC_ERROR_INVALID_ARGUMENTS;

		const u8 *mid = &in_path->value[in_path->len - 4];
		const u8 *final = &in_path->value[in_path->len - 2];

		if (!priv || !priv->mid_fid_valid || priv->mid_fid[0] != mid[0] || priv->mid_fid[1] != mid[1]) {
			sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0xA4, 0x00, 0x0C);
			apdu.data = mid;
			apdu.datalen = 2;
			apdu.lc = 2;

			r = sc_transmit_apdu(card, &apdu);
			if (r != SC_SUCCESS) return r;
			r = sc_check_sw(card, apdu.sw1, apdu.sw2);
			if (r != SC_SUCCESS) return r;

			if (priv) {
				priv->mid_fid[0] = mid[0];
				priv->mid_fid[1] = mid[1];
				priv->mid_fid_valid = 1;
			}
		}

		r = starsign_select_ef_child(card, final, &resolved_size);
		if (r != SC_SUCCESS) return r;
		selected_as_ef = 1;
	}
	/* Same trace shows that once DF 5031 has been entered, every other
	 * object under it (TokenInfo, ODF/AODF/PrKDF/CDF/DODF EFs, ...) is also
	 * addressed as a direct child EF — the MF is never reselected. Only the
	 * very first "3F00 5031" transition performs genuine MF->DF navigation. */
	else if (in_path->len == 4 && in_path->value[0] == 0x3F && in_path->value[1] == 0x00 &&
	         priv && priv->df5031_selected &&
	         !(in_path->value[2] == 0x50 && in_path->value[3] == 0x31)) {
		r = starsign_select_ef_child(card, &in_path->value[2], &resolved_size);
		if (r != SC_SUCCESS) return r;
		selected_as_ef = 1;
	}
	else {
		/* Genuine hierarchical navigation from the MF (used for the initial
		 * "3F00 5031" DF transition and any other top-level DF/EF reached
		 * before that context is established).
		 * Use P1=0x00 (Select by File ID) for ALL steps — the StarSign CUT S
		 * rejects P1=0x01 (Select child DF) for special DFs like 3FFF. */
		for (i = 0; i < in_path->len; i += 2) {
			sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0xA4, 0x00, 0x0C);
			apdu.data = &in_path->value[i];
			apdu.datalen = 2;
			apdu.lc = 2;

			r = sc_transmit_apdu(card, &apdu);
			if (r != SC_SUCCESS) return r;
			r = sc_check_sw(card, apdu.sw1, apdu.sw2);
			if (r != SC_SUCCESS) return r;
		}

		if (priv && in_path->len == 4 && in_path->value[2] == 0x50 && in_path->value[3] == 0x31)
			priv->df5031_selected = 1;
		/* Genuine top-level navigation leaves whatever DF the path landed
		 * on; the cached "mid DF" (e.g. 4302) is no longer necessarily
		 * selected, so drop it and let the next 3FFF-placeholder path
		 * reselect it explicitly. */
		if (priv)
			priv->mid_fid_valid = 0;
	}

	if (file_out) {
		sc_file_t *file = sc_file_new();
		if (!file)
			return SC_ERROR_OUT_OF_MEMORY;
		file->id = (in_path->value[in_path->len - 2] << 8) | in_path->value[in_path->len - 1];

		/* Set type based on whether we selected a DF or EF in the last step */
		file->type = (in_path->len > 2 && !selected_as_ef) ? SC_FILE_TYPE_DF : SC_FILE_TYPE_WORKING_EF;
		file->ef_structure = SC_FILE_EF_TRANSPARENT;
		/* Use the real size reported by the card's FCP response when we
		 * have one (needed so sc_pkcs15_read_file's offset+count bounds
		 * check against file->size does not reject legitimately larger
		 * files, e.g. certificates); fall back to a generous default
		 * otherwise, since most callers here just read the whole file. */
		file->size = resolved_size ? resolved_size : 1024;
		file->magic = SC_FILE_MAGIC;
		file->path = *in_path;
		*file_out = file;
	}
	return SC_SUCCESS;
}

static int starsign_set_security_env(sc_card_t *card, const sc_security_env_t *env, int res)
{
	sc_apdu_t apdu;
	int r;

	sc_log(card->ctx, "STARSIGN: set_security_env called! Operation: %d", env->operation);

	if (card == NULL || env == NULL) {
		return SC_ERROR_INVALID_ARGUMENTS;
	}

	/* Force max_send_size to prevent apdu.c from falling back to Short APDU chaining
	   if the PC/SC reader negotiation mistakenly lowered it. Keep max_recv_size at
	   256 (the real RSA-2048 output size): iso7816_fixup_transceive_length() only
	   clamps apdu.le down to max_recv_size, never up, and some PKCS#11 framework
	   callers (e.g. decipher) request an oversized response buffer (512 bytes) that
	   the reader's USB/PC-SC transport cannot actually deliver in one extended APDU
	   (SCardTransmit fails with SCARD_E_INVALID_PARAMETER). Capping max_recv_size at
	   256 forces such oversized Le requests down to the correct, transmittable size. */
	card->max_send_size = 2048;
	card->max_recv_size = 256;
	card->caps |= SC_CARD_CAP_APDU_EXT;

	u8 p2 = 0;
	switch (env->operation) {
	case SC_SEC_OPERATION_AUTHENTICATE:
		p2 = 0xA4;
		break;
	case SC_SEC_OPERATION_DECIPHER:
	case SC_SEC_OPERATION_DERIVE:
		p2 = 0xB8;
		break;
	case SC_SEC_OPERATION_SIGN:
		p2 = 0xB6;
		break;
	default:
		return SC_ERROR_INVALID_ARGUMENTS;
	}

	/* StarSign CUT S hardware specifically requires the exact MSE: SET payload:
	   84 01 01 80 01 02 (Key Reference = 01, Algorithm Reference = 02)
	   Standard OpenSC puts 80 before 84, which the token rejects. */
	
	u8 sbuf[6] = {0x84, 0x01, 0x01, 0x80, 0x01, 0x02};
	
	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0x22, 0x41, p2);
	apdu.cla = card->cla;
	apdu.data = sbuf;
	apdu.datalen = 6;
	apdu.lc = 6;
	apdu.resplen = 0;
	
	sc_log(card->ctx, "STARSIGN: MSE SET constructed payload=84 01 %02X 80 01 %02X", sbuf[2], sbuf[5]);

	r = sc_transmit_apdu(card, &apdu);
	if (r != SC_SUCCESS) return r;
	return sc_check_sw(card, apdu.sw1, apdu.sw2);
}

static int starsign_finish(sc_card_t *card)
{
	if (card->drv_data) {
		free(card->drv_data);
		card->drv_data = NULL;
	}
	return SC_SUCCESS;
}

struct sc_card_driver * sc_get_starsign_driver(void)
{
	struct sc_card_driver *iso_drv = sc_get_iso7816_driver();
	starsign_ops = *iso_drv->ops;
	starsign_ops.init             = starsign_init;
	starsign_ops.finish           = starsign_finish;
	starsign_ops.match_card       = starsign_match_card;
	starsign_ops.select_file      = starsign_select_file;
	starsign_ops.set_security_env = starsign_set_security_env;
	return &starsign_drv;
}
