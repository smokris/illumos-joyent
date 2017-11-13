/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright (c) 2017, Joyent, Inc.
 */
#include <arpa/inet.h>
#include <netinet/in.h>
#include <string.h>
#include <strings.h>
#include <sys/debug.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <net/pfkeyv2.h>
#include "defs.h"
#include "ikev2_sa.h"
#include "ikev2_pkt.h"
#include "ikev2_common.h"
#include "ikev2_enum.h"
#include "ikev2_proto.h"
#include "config.h"
#include "pfkey.h"
#include "pkcs11.h"
#include "pkt.h"
#include "worker.h"

/*
 * XXX: IKEv1 selected the PRF based on the authentication algorithm.
 * IKEv2 allows the PRF to be negotiated separately.  Eventually, we
 * should probably add the ability to specify PRFs in the configuration
 * file.  For now, we just include all the ones we support in decreasing
 * order of preference.
 */
static ikev2_prf_t prf_supported[] = {
	IKEV2_PRF_HMAC_SHA2_512,
	IKEV2_PRF_HMAC_SHA2_384,
	IKEV2_PRF_HMAC_SHA2_256,
	IKEV2_PRF_HMAC_SHA1,
	IKEV2_PRF_HMAC_MD5
};

static void log_acq_match(ikev2_sa_result_t *);

static boolean_t
ikev2_sa_from_ext_acquire(pkt_t *restrict pkt, parsedmsg_t *restrict pmsg,
    uint32_t spi, ikev2_dh_t dh)
{
	sadb_prop_t *prop = (sadb_prop_t *)pmsg->pmsg_exts[SADB_X_EXT_EPROP];
	sadb_x_ecomb_t *ecomb = (sadb_x_ecomb_t *)(prop + 1);
	sadb_x_algdesc_t *alg = (sadb_x_algdesc_t *)(ecomb + 1);
	size_t propnum = 0;
	pkt_sa_state_t pss;
	boolean_t ok;
	VERIFY3P(prop, !=, NULL);

	ok = ikev2_add_sa(pkt, &pss);

	for (size_t i = 0; i < prop->sadb_x_prop_numecombs; i++) {
		ikev2_spi_proto_t proto;

		/* Probably overly cautious */
		if (ecomb->sadb_x_ecomb_numalgs == 0) {
			ecomb = (sadb_x_ecomb_t *)alg;
			continue;
		}

		proto = alg->sadb_x_algdesc_satype;
		ok &= ikev2_add_prop(&pss, propnum++, proto, spi);

		for (size_t j = 0; j < ecomb->sadb_x_ecomb_numalgs;
		    j++, alg++) {
			uint8_t algnum = alg->sadb_x_algdesc_alg;
			uint16_t minbits = alg->sadb_x_algdesc_minbits;
			uint16_t maxbits = alg->sadb_x_algdesc_maxbits;

			if (alg->sadb_x_algdesc_satype != proto) {
				(void) bunyan_warn(log,
				    "Extended proposal contains different "
				    "SA types in the same ecomb",
				    BUNYAN_T_END);
				continue;
			}

			switch (alg->sadb_x_algdesc_algtype) {
			case SADB_X_ALGTYPE_NONE:
				break;
			case SADB_X_ALGTYPE_CRYPT:
				ok &= ikev2_add_xf_encr(&pss,
				    ikev2_pfkey_to_encr(algnum), minbits,
				    maxbits);
				break;
			case SADB_X_ALGTYPE_AUTH:
				ok &= ikev2_add_xform(&pss, IKEV2_XF_AUTH,
				    ikev2_pfkey_to_auth(algnum));
				break;
			case SADB_X_ALGTYPE_COMPRESS:
				(void) bunyan_warn(worker->w_log,
				    "Extended proposal contains a compression "
				    "algorithm specification",
				    BUNYAN_T_UINT32, "alg", (uint32_t)algnum,
				    BUNYAN_T_END);
				continue;
			}
		}

		ecomb = (sadb_x_ecomb_t *)alg;
	}

	return (ok);
}

boolean_t
ikev2_sa_from_acquire(pkt_t *restrict pkt, parsedmsg_t *restrict pmsg,
    uint32_t spi, ikev2_dh_t dh)
{
	sadb_msg_t *samsg = pmsg->pmsg_samsg;
	sadb_prop_t *prop;
	sadb_comb_t *comb, *end;
	size_t propnum = 0;
	ikev2_spi_proto_t spi_type = IKEV2_PROTO_NONE;
	boolean_t ok;
	pkt_sa_state_t pss;

	ASSERT3U(samsg->sadb_msg_type, ==, SADB_ACQUIRE);

	switch (samsg->sadb_msg_satype) {
	case SADB_SATYPE_AH:
		spi_type = IKEV2_PROTO_AH;
		break;
	case SADB_SATYPE_ESP:
		spi_type = IKEV2_PROTO_ESP;
		break;
	case SADB_SATYPE_UNSPEC:
		/* ACQURE as a result of an INVERSE_ACQUIRE */
		return (ikev2_sa_from_ext_acquire(pkt, pmsg, spi, dh));
	default:
		INVALID("sadb_msg_satype");
	}

	prop = (sadb_prop_t *)pmsg->pmsg_exts[SADB_EXT_PROPOSAL];
	VERIFY3U(prop->sadb_prop_exttype, ==, SADB_EXT_PROPOSAL);

	ok = ikev2_add_sa(pkt, &pss);

	end = (sadb_comb_t *)((uint64_t *)prop + prop->sadb_prop_len);
	for (comb = (sadb_comb_t *)(prop + 1); comb < end; comb++) {
		ok &= ikev2_add_prop(&pss, propnum++, spi_type, spi);

		if (comb->sadb_comb_encrypt != SADB_EALG_NONE) {
			ikev2_xf_encr_t encr;
			uint16_t minbits, maxbits;

			encr = ikev2_pfkey_to_encr(comb->sadb_comb_encrypt);
			minbits = comb->sadb_comb_encrypt_minbits;
			maxbits = comb->sadb_comb_encrypt_maxbits;
			ok &= ikev2_add_xf_encr(&pss, encr, minbits, maxbits);
		}

		if (comb->sadb_comb_auth != SADB_AALG_NONE) {
			ikev2_xf_auth_t xf_auth;
			/*
			 * Neither the auth algorithms currently supported
			 * nor the IKE protocol itself supports specifying
			 * a key/bits size for the auth alg.
			 */
			VERIFY3U(comb->sadb_comb_auth_minbits, ==, 0);
			VERIFY3U(comb->sadb_comb_auth_maxbits, ==, 0);

			xf_auth = ikev2_pfkey_to_auth(comb->sadb_comb_auth);
			ok &= ikev2_add_xform(&pss, IKEV2_XF_AUTH, xf_auth);
		}

		if (dh != IKEV2_DH_NONE)
			ok &= ikev2_add_xform(&pss, IKEV2_XF_DH, dh);

		/* We currently don't support ESNs */
		ok &= ikev2_add_xform(&pss, IKEV2_XF_ESN, IKEV2_ESN_NONE);
	}

	return (ok);
}

ikev2_xf_auth_t
ikev2_pfkey_to_auth(int alg)
{
	switch (alg) {
	case SADB_AALG_NONE:
		return (IKEV2_XF_AUTH_NONE);
	case SADB_AALG_SHA256HMAC:
		return (IKEV2_XF_AUTH_HMAC_SHA2_256_128);
	case SADB_AALG_SHA384HMAC:
		return (IKEV2_XF_AUTH_HMAC_SHA2_384_192);
	case SADB_AALG_SHA512HMAC:
		return (IKEV2_XF_AUTH_HMAC_SHA2_512_256);
	case SADB_AALG_MD5HMAC:
		return (IKEV2_XF_AUTH_HMAC_MD5_96);
	case SADB_AALG_SHA1HMAC:
		return (IKEV2_XF_AUTH_HMAC_SHA1_96);
	default:
		INVALID("alg");
		/*NOTREACHED*/
		return (alg);
	}
}

ikev2_xf_encr_t
ikev2_pfkey_to_encr(int alg)
{
	switch (alg) {
	case SADB_EALG_NONE:
	case SADB_EALG_DESCBC:
	case SADB_EALG_3DESCBC:
	case SADB_EALG_BLOWFISH:
	case SADB_EALG_NULL:
	case SADB_EALG_AES:	/* CBC */
	case SADB_EALG_AES_CCM_8:
	case SADB_EALG_AES_CCM_12:
	case SADB_EALG_AES_CCM_16:
	case SADB_EALG_AES_GCM_8:
	case SADB_EALG_AES_GCM_12:
	case SADB_EALG_AES_GCM_16:
		/* These all match up */
		return (alg);
	default:
		INVALID("alg");
		/*NOTREACHED*/
		return (alg);
	}
}

static boolean_t add_rule_xform(pkt_sa_state_t *restrict,
    const config_xf_t *restrict);

boolean_t
ikev2_sa_from_rule(pkt_t *restrict pkt, const config_rule_t *restrict rule,
    uint64_t spi)
{
	boolean_t ok = B_TRUE;
	pkt_sa_state_t pss;

	if (!ikev2_add_sa(pkt, &pss))
		return (B_FALSE);

	for (uint8_t i = 0; rule->rule_xf[i] != NULL; i++) {
		/* RFC 7296 3.3.1 - Proposal numbers start with 1 */
		ok &= ikev2_add_prop(&pss, i + 1, IKEV2_PROTO_IKE, spi);
		ok &= add_rule_xform(&pss, rule->rule_xf[i]);
	}
	return (ok);
}

static boolean_t
add_rule_xform(pkt_sa_state_t *restrict pss, const config_xf_t *restrict xf)
{
	encr_modes_t mode = encr_data[xf->xf_encr].ed_mode;
	boolean_t ok = B_TRUE;

	ok &= ikev2_add_xf_encr(pss, xf->xf_encr, xf->xf_minbits,
	    xf->xf_maxbits);

	/*
	 * For all currently known combined mode ciphers, we can omit an
	 * integrity transform
	 */
	if (!MODE_IS_COMBINED(mode))
		ok &= ikev2_add_xform(pss, IKEV2_XF_AUTH, xf->xf_auth);
	ok &= ikev2_add_xform(pss, IKEV2_XF_DH, xf->xf_dh);

	for (size_t i = 0; ok && i < ARRAY_SIZE(prf_supported); i++)
		ok &= ikev2_add_xform(pss, IKEV2_XF_PRF, prf_supported[i]);

	return (ok);
}

boolean_t
ikev2_sa_add_result(pkt_t *restrict pkt,
    const ikev2_sa_result_t *restrict result, uint64_t spi)
{
	boolean_t ok;
	pkt_sa_state_t pss;

	ok = ikev2_add_sa(pkt, &pss);
	ok &= ikev2_add_prop(&pss, result->sar_propnum, result->sar_proto, spi);

	if (SA_RESULT_HAS(result, IKEV2_XF_ENCR)) {
		ok &= ikev2_add_xform(&pss, IKEV2_XF_ENCR, result->sar_encr);
		if (result->sar_encr_keylen != 0)
			ok &= ikev2_add_xf_attr(&pss, IKEV2_XF_ATTR_KEYLEN,
			    result->sar_encr_keylen);
	}
	if (SA_RESULT_HAS(result, IKEV2_XF_AUTH))
		ok &= ikev2_add_xform(&pss, IKEV2_XF_AUTH, result->sar_auth);
	if (SA_RESULT_HAS(result, IKEV2_XF_DH))
		ok &= ikev2_add_xform(&pss, IKEV2_XF_DH, result->sar_dh);
	if (SA_RESULT_HAS(result, IKEV2_XF_PRF))
		ok &= ikev2_add_xform(&pss, IKEV2_XF_PRF, result->sar_prf);
	if (SA_RESULT_HAS(result, IKEV2_XF_ESN))
		ok &= ikev2_add_xform(&pss, IKEV2_XF_ESN, result->sar_esn);

	return (ok);
}

struct rule_data_s {
	config_rule_t		*rd_rule;
	config_xf_t		*rd_xf;
	ikev2_sa_result_t	*rd_res;
	ikev2_prf_t		rd_prf;
	boolean_t		rd_match;
	boolean_t		rd_skip;
	boolean_t		rd_has_auth;
	boolean_t		rd_keylen_match;
};

static boolean_t match_rule_prop_cb(ikev2_sa_proposal_t *, uint64_t, uint8_t *,
    size_t, void *);
static boolean_t match_rule_xf_cb(ikev2_transform_t *, uint8_t *, size_t,
    void *);
static boolean_t match_rule_attr_cb(ikev2_xf_type_t, uint16_t,
    ikev2_attribute_t *, void *);

boolean_t
ikev2_sa_match_rule(config_rule_t *restrict rule, pkt_t *restrict pkt,
    ikev2_sa_result_t *restrict result, ikev2_auth_type_t *restrict authp)
{
	pkt_payload_t *pay = pkt_get_payload(pkt, IKEV2_PAYLOAD_SA, NULL);

	VERIFY3P(pay, !=, NULL);

	(void) bunyan_debug(log, "Checking rules against proposals",
	    BUNYAN_T_STRING, "rule", rule->rule_label,
	    BUNYAN_T_END);

	*authp = IKEV2_AUTH_NONE;

	for (size_t i = 0; rule->rule_xf[i] != NULL; i++) {
		for (size_t j = 0; j < ARRAY_SIZE(prf_supported); j++) {
			struct rule_data_s data = {
				.rd_rule = rule,
				.rd_xf = rule->rule_xf[i],
				.rd_res = result,
				.rd_prf = prf_supported[j],
				.rd_match = B_FALSE
			};

			(void) memset(result, 0, sizeof (*result));

			(void) bunyan_trace(log,
			    "Checking rule transform against proposals",
			    BUNYAN_T_UINT32, "xfnum", (uint32_t)i,
			    BUNYAN_T_STRING, "xf", rule->rule_xf[i]->xf_str,
			    BUNYAN_T_END);

			VERIFY(ikev2_walk_proposals(pay->pp_ptr, pay->pp_len,
			    match_rule_prop_cb, &data, B_FALSE));

			if (data.rd_match) {
				char estr[IKEV2_ENUM_STRLEN];
				char astr[IKEV2_ENUM_STRLEN];
				char pstr[IKEV2_ENUM_STRLEN];
				char dstr[IKEV2_ENUM_STRLEN];
				char authstr[IKEV2_ENUM_STRLEN];

				*authp = rule->rule_xf[i]->xf_authtype;

				(void) bunyan_debug(log, "Found proposal match",
				    BUNYAN_T_STRING, "xf",
				    rule->rule_xf[i]->xf_str,
				    BUNYAN_T_UINT32, "propnum",
				    (uint32_t)result->sar_propnum,
				    BUNYAN_T_STRING, "authmethod",
				    ikev2_auth_type_str(*authp, authstr,
				    sizeof (authstr)),
				    BUNYAN_T_UINT64, "spi", result->sar_spi,
				    BUNYAN_T_STRING, "encr",
				    ikev2_xf_encr_str(result->sar_encr, estr,
				    sizeof (estr)),
				    BUNYAN_T_UINT32, "keylen",
				    (uint32_t)result->sar_encr_keylen,
				    BUNYAN_T_STRING, "auth",
				    ikev2_xf_auth_str(result->sar_auth, astr,
				    sizeof (astr)),
				    BUNYAN_T_STRING, "prf",
				    ikev2_prf_str(result->sar_prf, pstr,
				    sizeof (pstr)),
				    BUNYAN_T_STRING, "dh",
				    ikev2_dh_str(result->sar_dh, dstr,
				    sizeof (dstr)),
				    BUNYAN_T_END);

				return (B_TRUE);
			}
		}
	}

	(void) bunyan_debug(log, "No matching proposals found", BUNYAN_T_END);
	return (B_FALSE);
}

static boolean_t
match_rule_prop_cb(ikev2_sa_proposal_t *prop, uint64_t spi, uint8_t *buf,
    size_t buflen, void *cookie)
{
	struct rule_data_s *data = cookie;

	(void) bunyan_trace(log, "Checking proposal",
	    BUNYAN_T_UINT32, "propnum", (uint32_t)prop->proto_proposalnr,
	    BUNYAN_T_END);

	if (prop->proto_protoid != IKEV2_PROTO_IKE) {
		char buf[IKEV2_ENUM_STRLEN];

		(void) bunyan_trace(log, "Proposal is not for IKE",
		    BUNYAN_T_STRING, "protocol",
		    ikev2_spi_str(prop->proto_protoid, buf, sizeof (buf)),
		    BUNYAN_T_END);
		return (B_FALSE);
	}

	(void) memset(data->rd_res, 0, sizeof (*data->rd_res));
	data->rd_skip = B_FALSE;
	data->rd_has_auth = B_FALSE;

	VERIFY(ikev2_walk_xfs(buf, buflen, match_rule_xf_cb, cookie));

	if (data->rd_skip)
		return (B_TRUE);

	/* These must all match, otherwise next proposal */
	if (!SA_RESULT_HAS(data->rd_res, IKEV2_XF_ENCR) ||
	    !SA_RESULT_HAS(data->rd_res, IKEV2_XF_PRF) ||
	    !SA_RESULT_HAS(data->rd_res, IKEV2_XF_DH) ||
	    (!MODE_IS_COMBINED(encr_data[data->rd_res->sar_encr].ed_mode) &&
	    !SA_RESULT_HAS(data->rd_res, IKEV2_XF_AUTH)))
		return (B_TRUE);

	/* A match.  Stop walk of remaining proposals */
	data->rd_res->sar_proto = prop->proto_protoid;
	data->rd_res->sar_spi = spi;
	data->rd_res->sar_propnum = prop->proto_proposalnr;
	data->rd_match = B_TRUE;
	return (B_FALSE);
}

static boolean_t
match_rule_xf_cb(ikev2_transform_t *xf, uint8_t *buf, size_t buflen,
    void *cookie)
{
	struct rule_data_s *data = cookie;
	char str[IKEV2_ENUM_STRLEN];
	boolean_t match = B_FALSE;

	(void) bunyan_trace(log, "Checking transform",
		    BUNYAN_T_STRING, "xftype", ikev2_xf_type_str(xf->xf_type,
		    str, sizeof (str)),
		    BUNYAN_T_UINT32, "val", (uint32_t)xf->xf_id,
		    BUNYAN_T_END);

	switch (xf->xf_type) {
	case IKEV2_XF_ENCR:
		if (data->rd_xf->xf_encr != xf->xf_id)
			break;

		/*
		 * If the encr alg matches, it should be something
		 * defined.
		 */
		VERIFY3U(xf->xf_id, <=, IKEV2_ENCR_MAX);
		if (buflen > 0) {
			data->rd_keylen_match = B_FALSE;
			VERIFY(ikev2_walk_xfattrs(buf, buflen,
			    match_rule_attr_cb, xf->xf_type, xf->xf_id,
			    cookie));

			/*
			 * RFC7296 3.3.6 - Unknown attribute means skip
			 * the transform, but not the whole proposal.
			 */
			if (data->rd_skip) {
				data->rd_skip = B_FALSE;
				break;
			}
			if (!data->rd_keylen_match)
				break;
		}

		data->rd_res->sar_encr = xf->xf_id;
		match = B_TRUE;
		break;
	case IKEV2_XF_AUTH:
		data->rd_has_auth = B_TRUE;
		if (data->rd_xf->xf_auth == xf->xf_id) {
			data->rd_res->sar_auth = xf->xf_id;
			match = B_TRUE;
		}
		break;
	case IKEV2_XF_PRF:
		if (xf->xf_id == data->rd_prf) {
			match = B_TRUE;
			data->rd_res->sar_prf = data->rd_prf;
		}
		break;
	case IKEV2_XF_DH:
		if (data->rd_xf->xf_dh == xf->xf_id) {
			match = B_TRUE;
			data->rd_res->sar_dh = xf->xf_id;
		}
		break;
	case IKEV2_XF_ESN:
		/* Not valid in IKE proposals */
		(void) bunyan_info(log,
		    "Encountered ESN transform in IKE transform", BUNYAN_T_END);
		data->rd_skip = B_TRUE;
		break;
	default:
		/*
		 * RFC7296 3.3.6 - An unrecognized transform type means the
		 * proposal should be ignored.
		 */
		(void) bunyan_info(log,
		    "Unknown transform type in proposal",
		    BUNYAN_T_UINT32, "xftype", (uint32_t)xf->xf_type,
		    BUNYAN_T_END);
		data->rd_skip = B_TRUE;
	}

	if (match) {
		(void) bunyan_trace(log, "Partial match",
		    BUNYAN_T_STRING, "type", ikev2_xf_type_str(xf->xf_type, str,
		    sizeof (str)),
		    BUNYAN_T_UINT32, "val", (uint32_t)xf->xf_id,
		    BUNYAN_T_END);
		data->rd_res->sar_match |= (uint32_t)1 << xf->xf_type;
	}

	return (!data->rd_skip);
}

static boolean_t
match_rule_attr_cb(ikev2_xf_type_t xftype, uint16_t xfid,
    ikev2_attribute_t *attr, void *cookie)
{
	struct rule_data_s *data = cookie;

	switch (xftype) {
	case IKEV2_XF_ENCR:
		break;
	case IKEV2_XF_AUTH:
	case IKEV2_XF_DH:
	case IKEV2_XF_PRF:
	case IKEV2_XF_ESN:
		data->rd_skip = B_TRUE;
		return (B_FALSE);
	}

	/* Currently, only the keylength attribute is defined and supported */
	if (IKE_ATTR_GET_TYPE(attr->attr_type) != IKEV2_XF_ATTR_KEYLEN) {
		data->rd_skip = B_TRUE;
		return (B_FALSE);
	}

	if (xfid > IKEV2_ENCR_MAX)
		return (B_FALSE);

	if (!encr_keylen_allowed(xfid))
		return (B_FALSE);

	if (attr->attr_length >= data->rd_xf->xf_minbits &&
	    attr->attr_length <= data->rd_xf->xf_maxbits) {
		data->rd_res->sar_encr_keylen = attr->attr_length;
		data->rd_keylen_match = B_TRUE;
		return (B_FALSE);
	}

	return (B_TRUE);
}

struct acquire_data_s {
	union {
		sadb_comb_t		*adu_comb;
		sadb_x_ecomb_t		*adu_ecomb;
	} adu;
#define	ad_comb adu.adu_comb
#define	ad_ecomb adu.adu_ecomb
	sadb_x_algdesc_t	*ad_algdesc;
	ikev2_sa_result_t	*ad_res;
	ikev2_spi_proto_t	ad_spitype;
	ikev2_dh_t		ad_dh;
	uint32_t		ad_seen;
	boolean_t		ad_skip;
	boolean_t		ad_match;
	boolean_t		ad_keylen_match;
	boolean_t		ad_ext_acquire;
};

static boolean_t ikev2_sa_match_eacquire(parsedmsg_t *restrict,
    ikev2_dh_t, pkt_t *restrict, ikev2_sa_result_t *restrict);
static boolean_t match_acq_prop_cb(ikev2_sa_proposal_t *, uint64_t,
    uint8_t *, size_t, void *);
static boolean_t match_acq_xf_cb(ikev2_transform_t *, uint8_t *, size_t,
    void *);
static boolean_t match_acq_attr_cb(ikev2_xf_type_t, uint16_t,
    ikev2_attribute_t *, void *);

boolean_t
ikev2_sa_match_acquire(parsedmsg_t *restrict pmsg, ikev2_dh_t dh,
    pkt_t *restrict pkt, ikev2_sa_result_t *restrict result)
{
	if (pmsg->pmsg_exts[SADB_X_EXT_EPROP] != NULL)
		return (ikev2_sa_match_eacquire(pmsg, dh, pkt, result));

	pkt_payload_t *pay = pkt_get_payload(pkt, IKEV2_PAYLOAD_SA, NULL);
	sadb_msg_t *samsg = pmsg->pmsg_samsg;
	sadb_prop_t *prop;
	sadb_comb_t *comb;
	ikev2_spi_proto_t spitype = IKEV2_PROTO_NONE;

	VERIFY3P(pay, !=, NULL);

	(void) bunyan_debug(log, "Checking rules against acquire",
	    BUNYAN_T_END);

	prop = (sadb_prop_t *)pmsg->pmsg_exts[SADB_EXT_PROPOSAL];
	comb = (sadb_comb_t *)(prop + 1);
	VERIFY3P(prop, !=, NULL);

	switch (samsg->sadb_msg_satype) {
	case SADB_SATYPE_AH:
		spitype = IKEV2_PROTO_AH;
		break;
	case SADB_SATYPE_ESP:
		spitype = IKEV2_PROTO_ESP;
		break;
	default:
		INVALID(samsg->sadb_msg_satype);
	}

	for (size_t i = 0; i < prop->sadb_x_prop_numecombs; i++, comb++) {
		struct acquire_data_s data = {
			.ad_comb = comb,
			.ad_res = result,
			.ad_spitype = spitype,
			.ad_dh = dh
		};

		(void) memset(result, 0, sizeof (*result));

		VERIFY(ikev2_walk_proposals(pay->pp_ptr, pay->pp_len,
		    match_acq_prop_cb, &data, B_FALSE));

		if (data.ad_match) {
			log_acq_match(result);
			return (B_TRUE);
		}
	}

	(void) bunyan_debug(log, "No matching proposals found", BUNYAN_T_END);
	return (B_FALSE);
}

static boolean_t
match_acq_prop_cb(ikev2_sa_proposal_t *prop, uint64_t spi, uint8_t *buf,
    size_t buflen, void *cookie)
{
	NOTE(ARGUNUSED(spi))
	struct acquire_data_s *data = cookie;
	char str[2][IKEV2_ENUM_STRLEN];

	if (prop->proto_protoid != data->ad_spitype) {
		bunyan_debug(log, "Proposal is not for this SA type",
		    BUNYAN_T_STRING, "exp_satype",
		    ikev2_spi_str(data->ad_spitype, str[1], sizeof (str[1])),
		    BUNYAN_T_STRING, "prop_satype",
		    ikev2_spi_str(prop->proto_protoid, str[2], sizeof (str[2])),
		    BUNYAN_T_UINT32, "prop_satype_val",
		    (uint32_t)prop->proto_protoid, BUNYAN_T_END);
		return (B_FALSE);
	}

	(void) memset(data->ad_res, 0, sizeof (*data->ad_res));
	data->ad_skip = B_FALSE;

	VERIFY(ikev2_walk_xfs(buf, buflen, match_acq_xf_cb, cookie));

	if (data->ad_skip)
		return (B_TRUE);

	/*
	 * Go on to the next proposal if no match.  Check mandatory types
	 * and optional types if we've specified one.
	 * RFC7296 3.3.3 Lists mandatory and optional transform types
	 */
	switch (data->ad_spitype) {
	case IKEV2_PROTO_ESP:
		/* Mandatory: ENCR, ESN  Optional: AUTH, DH */
		if (!SA_RESULT_HAS(data->ad_res, IKEV2_XF_ENCR) ||
		    !SA_RESULT_HAS(data->ad_res, IKEV2_XF_ESN) ||
		    (data->ad_comb->sadb_comb_auth != SADB_AALG_NONE &&
		    !SA_RESULT_HAS(data->ad_res, IKEV2_XF_AUTH)) ||
		    (data->ad_dh != IKEV2_DH_NONE &&
		    !SA_RESULT_HAS(data->ad_res, IKEV2_XF_DH)))
			return (B_TRUE);
		break;
	case IKEV2_PROTO_AH:
		/* Mandatory: AUTH, ESN, Optional: DH */
		if (!SA_RESULT_HAS(data->ad_res, IKEV2_XF_AUTH) ||
		    !SA_RESULT_HAS(data->ad_res, IKEV2_XF_ESN) ||
		    (data->ad_dh != IKEV2_DH_NONE &&
		    !SA_RESULT_HAS(data->ad_res, IKEV2_XF_DH)))
			return (B_TRUE);
		break;
	case IKEV2_PROTO_NONE:
	case IKEV2_PROTO_IKE:
	case IKEV2_PROTO_FC_ESP_HEADER:
	case IKEV2_PROTO_FC_CT_AUTH:
		INVALID("data->ad_spitype");
		break;
	}

	return (B_FALSE);
}
static boolean_t
match_acq_xf_cb(ikev2_transform_t *xf, uint8_t *buf, size_t buflen,
    void *cookie)
{
	struct acquire_data_s *data = cookie;
	boolean_t match = B_FALSE;

	switch (xf->xf_type) {
	case IKEV2_XF_ENCR:
		if (xf->xf_id != data->ad_comb->sadb_comb_encrypt)
			break;

		/*
		 * If the alg matches, it should be something we know.
		 * Note xf_id is unsigned, so no need to check if >= 0
		 */
		VERIFY3U(xf->xf_id, <=, IKEV2_ENCR_MAX);

		if (buflen > 0) {
			data->ad_keylen_match = B_FALSE;
			VERIFY(ikev2_walk_xfattrs(buf, buflen,
			    match_acq_attr_cb, xf->xf_type, xf->xf_id, cookie));

			/*
			 * RFD7296 3.3.6 - Unknown attribute means skip the
			 * transform, but not the whole proposal.
			 */
			if (data->ad_skip) {
				data->ad_skip = B_FALSE;
				break;
			}
			if (!data->ad_keylen_match)
				break;
		}
		data->ad_res->sar_encr = xf->xf_id;
		match = B_TRUE;
		break;
	case IKEV2_XF_PRF:
		(void) bunyan_debug(log,
		    "Encountered PRF transform in AH/ESP transform",
		    BUNYAN_T_END);
		data->ad_skip = B_TRUE;
		break;
	case IKEV2_XF_AUTH:
		if (xf->xf_id != data->ad_comb->sadb_comb_auth)
			break;
		match = B_TRUE;
		data->ad_res->sar_auth = xf->xf_id;
		break;
	case IKEV2_XF_DH:
		if (xf->xf_id != data->ad_dh)
			break;
		match = B_TRUE;
		data->ad_res->sar_dh = xf->xf_id;
		break;
	case IKEV2_XF_ESN:
		/* XXX: At some point, pf_key(7P) will need support for this */
		if (xf->xf_id != IKEV2_ESN_NONE)
			break;
		match = B_TRUE;
		data->ad_res->sar_esn = B_FALSE;
		break;
	}

	if (match)
		data->ad_res->sar_match |= (uint32_t)1 << xf->xf_type;

	return (!data->ad_skip);
}

static boolean_t
match_acq_attr_cb(ikev2_xf_type_t xftype, uint16_t xfid,
    ikev2_attribute_t *attr, void *cookie)
{
	struct acquire_data_s *data = cookie;
	uint16_t minbits = 0, maxbits = 0;

	if (data->ad_ext_acquire) {
		sadb_x_algdesc_t *algdesc = data->ad_algdesc;

		minbits = algdesc->sadb_x_algdesc_minbits;
		maxbits = algdesc->sadb_x_algdesc_maxbits;
	} else {
		minbits = data->ad_comb->sadb_comb_encrypt_minbits;
		maxbits = data->ad_comb->sadb_comb_encrypt_maxbits;
	}

	if (IKE_ATTR_GET_TYPE(attr->attr_type) != IKEV2_XF_ATTR_KEYLEN) {
		data->ad_skip = B_TRUE;
		return (B_FALSE);
	}

	if (xfid > IKEV2_ENCR_MAX)
		return (B_FALSE);

	if (!encr_keylen_allowed(xfid))
		return (B_FALSE);

	if (attr->attr_length >= minbits && attr->attr_length <= maxbits) {
		data->ad_res->sar_encr_keylen = attr->attr_length;
		data->ad_keylen_match = B_TRUE;
		return (B_FALSE);
	}

	return (B_TRUE);
}

static boolean_t match_eacq_prop_cb(ikev2_sa_proposal_t *, uint64_t,
    uint8_t *, size_t, void *);
static boolean_t match_eacq_xf_cb(ikev2_transform_t *, uint8_t *, size_t,
    void *);

static boolean_t
ikev2_sa_match_eacquire(parsedmsg_t *restrict pmsg,
    ikev2_dh_t dh, pkt_t *restrict pkt, ikev2_sa_result_t *restrict res)
{
	pkt_payload_t *pay = pkt_get_payload(pkt, IKEV2_PAYLOAD_SA, NULL);
	sadb_msg_t *samsg = pmsg->pmsg_samsg;
	sadb_prop_t *prop = NULL;
	sadb_x_ecomb_t *ecomb = NULL;
	struct acquire_data_s data = {
		.ad_res = res,
		.ad_dh = dh,
		.ad_ext_acquire = B_TRUE
	};
	uint16_t numcomb = 0;
	uint8_t	numalg = 0;

	(void) bunyan_debug(log, "Checking rules against extended acquire",
	    BUNYAN_T_END);

	prop = (sadb_prop_t *)pmsg->pmsg_exts[SADB_X_EXT_EPROP];
	ecomb = (sadb_x_ecomb_t *)(prop + 1);
	numcomb = prop->sadb_x_prop_numecombs;
	numalg = ecomb->sadb_x_ecomb_numalgs;
	for (size_t i = 0; i < numcomb; i++) {
		sadb_x_algdesc_t *algdesc = (sadb_x_algdesc_t *)(ecomb + 1);

		data.ad_ecomb = ecomb;
		VERIFY(ikev2_walk_proposals(pay->pp_ptr, pay->pp_len,
		    match_eacq_prop_cb, &data, B_FALSE));

		if (data.ad_match) {
			log_acq_match(res);
			return (B_TRUE);
		}

		ecomb = (sadb_x_ecomb_t *)(algdesc + numalg);
	}

	(void) bunyan_debug(log, "No matching proposals found", BUNYAN_T_END);
	return (B_FALSE);
}

static boolean_t
match_eacq_prop_cb(ikev2_sa_proposal_t *prop, uint64_t spi, uint8_t *buf,
    size_t buflen, void *cookie)
{
	struct acquire_data_s *data = cookie;
	sadb_x_ecomb_t *ecomb = data->ad_ecomb;
	sadb_x_algdesc_t *algdesc = (sadb_x_algdesc_t *)(ecomb + 1);

	bzero(data->ad_res, sizeof (*data->ad_res));
	data->ad_spitype = satype_to_ikev2(algdesc->sadb_x_algdesc_satype);
	data->ad_seen = 0;
	if (data->ad_dh != IKEV2_DH_NONE)
		data->ad_seen |= (uint32_t)1 << IKEV2_XF_DH;

	for (size_t i = 0; i < ecomb->sadb_x_ecomb_numalgs; i++, algdesc++) {
		ikev2_xf_type_t xftype = 0;

		if (satype_to_ikev2(algdesc->sadb_x_algdesc_satype) !=
		    prop->proto_protoid)
			continue;

		switch (algdesc->sadb_x_algdesc_algtype) {
		case SADB_X_ALGTYPE_AUTH:
			xftype = IKEV2_XF_AUTH;
			break;
		case SADB_X_ALGTYPE_CRYPT:
			xftype = IKEV2_XF_ENCR;
			break;
		}

		data->ad_algdesc = algdesc;
		if (xftype != 0)
			data->ad_seen |= (uint32_t)1 << xftype;

		data->ad_skip = B_FALSE;
		VERIFY(ikev2_walk_xfs(buf, buflen, match_eacq_xf_cb, cookie));
		if (data->ad_skip)
			return (B_TRUE);
	}

	if (((data->ad_seen & data->ad_res->sar_match) != data->ad_seen) ||
	    !data->ad_keylen_match)
		return (B_TRUE);

	data->ad_match = B_TRUE;
	data->ad_res->sar_spi = spi;
	data->ad_res->sar_proto = data->ad_spitype;
	data->ad_res->sar_propnum = prop->proto_proposalnr;
	return (B_FALSE);
}

static boolean_t
match_eacq_xf_cb(ikev2_transform_t *xf, uint8_t *buf, size_t buflen,
    void *cookie)
{
	struct acquire_data_s *data = cookie;
	sadb_x_algdesc_t *algdesc = data->ad_algdesc;
	char str[IKEV2_ENUM_STRLEN];
	const char *strp = NULL;
	boolean_t match = B_FALSE;
	uint8_t algtype = algdesc->sadb_x_algdesc_algtype;
	uint8_t alg = algdesc->sadb_x_algdesc_alg;

	(void) bunyan_trace(log, "Checking transform",
	    BUNYAN_T_STRING, "xftype", ikev2_xf_type_str(xf->xf_type, str,
	    sizeof (str)),
	    BUNYAN_T_UINT32, "val", (uint32_t)xf->xf_id,
	    BUNYAN_T_END);

	/* XXX: Can there be different satypes in one ecomb? */
	switch (xf->xf_type) {
	case IKEV2_XF_ENCR:
		if (algtype != SADB_X_ALGTYPE_CRYPT)
			return (B_TRUE);
		if (xf->xf_id != ikev2_pfkey_to_encr(alg))
			break;

		if (buflen > 0) {
			data->ad_keylen_match = B_FALSE;
			VERIFY(ikev2_walk_xfattrs(buf, buflen,
			    match_acq_attr_cb, xf->xf_type, xf->xf_id,
			    cookie));

			/*
			 * RFC7296 3.3.6 - Unknown attribute means skip the
			 * transform, but not the whole proposal.
			 */
			if (data->ad_skip) {
				data->ad_skip = B_FALSE;
				break;
			}
			if (!data->ad_keylen_match)
				break;
		}
		data->ad_res->sar_encr = xf->xf_id;
		match = B_TRUE;
		strp = ikev2_xf_encr_str(xf->xf_id, str, sizeof (str));
		break;
	case IKEV2_XF_AUTH:
		if (algtype != SADB_X_ALGTYPE_AUTH)
			return (B_TRUE);
		if (xf->xf_id != ikev2_pfkey_to_auth(alg))
			break;
		match = B_TRUE;
		data->ad_res->sar_auth = xf->xf_id;
		strp = ikev2_xf_auth_str(xf->xf_id, str, sizeof (str));
		break;
	case IKEV2_XF_DH:
		if (xf->xf_id != data->ad_dh)
			break;
		match = B_TRUE;
		data->ad_res->sar_dh = xf->xf_id;
		strp = ikev2_dh_str(xf->xf_id, str, sizeof (str));
		break;
	case IKEV2_XF_ESN:
		if (xf->xf_id != IKEV2_ESN_NONE)
			break;
		match = B_TRUE;
		data->ad_res->sar_esn = B_FALSE;
		break;
	}

	if (match) {
		const char *xfp = NULL;
		char xfbuf[IKEV2_ENUM_STRLEN];

		data->ad_res->sar_match |= (uint32_t)1 << xf->xf_type;

		xfp = ikev2_xf_type_str(xf->xf_type, xfbuf, sizeof (xfbuf));
		(void) bunyan_debug(log, "Partial transform match",
		    BUNYAN_T_STRING, "xftype", xfp,
		    BUNYAN_T_STRING, "xfval", strp,
		    BUNYAN_T_END);
	}

	return (!data->ad_skip);
}

static void
log_acq_match(ikev2_sa_result_t *res)
{
	char estr[IKEV2_ENUM_STRLEN];
	char astr[IKEV2_ENUM_STRLEN];
	char pstr[IKEV2_ENUM_STRLEN];
	char dstr[IKEV2_ENUM_STRLEN];

	(void) bunyan_debug(log, "Found proposal match",
	    BUNYAN_T_UINT32, "propnum", (uint32_t)res->sar_propnum,
	    BUNYAN_T_UINT64, "spi", res->sar_spi,
	    BUNYAN_T_STRING, "encr",
	    ikev2_xf_encr_str(res->sar_encr, estr, sizeof (estr)),
	    BUNYAN_T_UINT32, "keylen", (uint32_t)res->sar_encr_keylen,
	    BUNYAN_T_STRING, "auth",
	    ikev2_xf_auth_str(res->sar_auth, astr, sizeof (astr)),
	    BUNYAN_T_STRING, "dh", ikev2_dh_str(res->sar_dh,
	    dstr, sizeof (dstr)),
	    BUNYAN_T_BOOLEAN, "esn", res->sar_esn,
	    BUNYAN_T_END);
}

char *
ikev2_id_str(pkt_payload_t *restrict id, char *restrict buf, size_t buflen)
{
	ikev2_id_t *idp = (ikev2_id_t *)id->pp_ptr;
	ikev2_id_type_t type = idp->id_type;
	void *data = (idp + 1);
	size_t datalen = id->pp_len - sizeof (*idp);

	switch (type) {
	case IKEV2_ID_IPV4_ADDR:
		(void) inet_ntop(AF_INET, data, buf, buflen);
		break;
	case IKEV2_ID_FQDN:
	case IKEV2_ID_RFC822_ADDR:
		(void) strlcpy(buf, data, buflen);
		break;
	case IKEV2_ID_IPV6_ADDR:
		(void) inet_ntop(AF_INET6, data, buf, buflen);
		break;
	case IKEV2_ID_DER_ASN1_DN:
	case IKEV2_ID_DER_ASN1_GN:
		INVALID("not implemented yet");
		break;
	case IKEV2_ID_KEY_ID:
	default:
		(void) writehex(data, datalen, NULL, buf, buflen);
		break;
	case IKEV2_ID_FC_NAME:
		(void) writehex(data, datalen, ":", buf, buflen);
		break;
	}

	return (buf);
}
