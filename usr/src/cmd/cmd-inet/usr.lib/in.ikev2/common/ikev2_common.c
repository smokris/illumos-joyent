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
#include <sys/types.h>
#include <net/pfkeyv2.h>
#include <sys/debug.h>
#include "defs.h"
#include "ikev2_pkt.h"
#include "ikev2_common.h"
#include "config.h"
#include "pkcs11.h"

boolean_t
ikev2_sa_from_acquire(pkt_t *pkt, parsedmsg_t *pmsg, uint32_t spi,
    ikev2_dh_t dh)
{
	sadb_msg_t *samsg = pmsg->pmsg_samsg;
	sadb_sa_t *sa;
	sadb_prop_t *prop;
	sadb_comb_t *comb;
	boolean_t ok;
	ikev2_spi_proto_t spi_type = IKEV2_PROTO_NONE;

	ASSERT3U(samsg->sadb_msg_type, ==, SADB_ACQUIRE);

	switch (samsg->sadb_msg_satype) {
	case SADB_SATYPE_AH:
		spi_type = IKEV2_PROTO_AH;
		break;
	case SADB_SATYPE_ESP:
		spi_type = IKEV2_PROTO_ESP;
		break;
	default:
		INVALID("sadb_msg_satype");
	}

	prop = (sadb_prop_t *)pmsg->pmsg_exts[SADB_EXT_PROPOSAL];
	ASSERT3U(prop->sadb_prop_exttype, ==, SADB_EXT_PROPOSAL);

	ok = ikev2_add_sa(pkt);

	comb = (sadb_comb_t *)(prop + 1);
	for (size_t i = 0; i < prop->sadb_x_prop_numecombs; i++, comb++) {
		ok &= ikev2_add_prop(pkt, i + 1, spi_type, spi);

		if (comb->sadb_comb_encrypt != SADB_EALG_NONE) {
			ikev2_xf_encr_t encr;
			uint16_t minbits, maxbits;

			encr = ikev2_pfkey_to_encr(comb->sadb_comb_encrypt);
			minbits = comb->sadb_comb_encrypt_minbits;
			maxbits = comb->sadb_comb_encrypt_maxbits;
			ok &= ikev2_add_xf_encr(pkt, encr, minbits, maxbits);
		}

		if (comb->sadb_comb_auth != SADB_AALG_NONE) {
			ikev2_xf_auth_t xf_auth;
			/*
			 * nothing currently supports this either local algs
			 * or the IKE protocol
			 */
			VERIFY3U(comb->sadb_comb_auth_minbits, ==, 0);
			VERIFY3U(comb->sadb_comb_auth_maxbits, ==, 0);

			xf_auth = ikev2_pfkey_to_auth(comb->sadb_comb_auth);
			ok &= ikev2_add_xform(pkt, IKEV2_XF_AUTH, xf_auth);
		}

		if (dh != IKEV2_DH_NONE)
			ok &= ikev2_add_xform(pkt, IKEV2_XF_DH, dh);
	}

	return (ok);
}

ikev2_xf_auth_t
ikev2_pfkey_to_auth(int alg)
{
	switch (alg) {
	case SADB_AALG_NONE:
	case SADB_AALG_SHA256HMAC:
	case SADB_AALG_SHA384HMAC:
	case SADB_AALG_SHA512HMAC:
		/* these values all correspond */
		return (alg);
	case SADB_AALG_MD5HMAC:
		/* this one does not */
		return (IKEV2_XF_AUTH_HMAC_MD5_96);
	case SADB_AALG_SHA1HMAC:
		/* nor does this one */
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
		return (alg);
	default:
		INVALID("alg");
		/*NOTREACHED*/
		return (alg);
	}
}

boolean_t
ikev2_sa_add_result(pkt_t *restrict pkt,
    const ikev2_sa_result_t *restrict result)
{
	boolean_t ok;

	ok = ikev2_add_sa(pkt);
	ok &= ikev2_add_prop(pkt, result->sar_propnum, result->sar_proto,
	    result->sar_spi);

	if (SA_RESULT_HAS(result, IKEV2_XF_ENCR)) {
		ok &= ikev2_add_xform(pkt, IKEV2_XF_ENCR, result->sar_encr);
		if (result->sar_encr_keylen != 0)
			ok &= ikev2_add_xf_attr(pkt, IKEV2_XF_ATTR_KEYLEN,
			    result->sar_encr_keylen);
	}
	if (SA_RESULT_HAS(result, IKEV2_XF_AUTH))
		ok &= ikev2_add_xform(pkt, IKEV2_XF_AUTH, result->sar_auth);
	if (SA_RESULT_HAS(result, IKEV2_XF_DH))
		ok &= ikev2_add_xform(pkt, IKEV2_XF_DH, result->sar_dh);
	if (SA_RESULT_HAS(result, IKEV2_XF_PRF))
		ok &= ikev2_add_xform(pkt, IKEV2_XF_PRF, result->sar_prf);
	if (SA_RESULT_HAS(result, IKEV2_XF_ESN))
		ok &= ikev2_add_xform(pkt, IKEV2_XF_ESN, result->sar_esn);

	return (ok);
}

boolean_t
ikev2_sa_match_rule(config_rule_t *restrict rule, pkt_t *restrict pkt,
    ikev2_sa_result_t *restrict result)
{
	/* TODO */
	return (B_FALSE);
}

boolean_t
ikev2_sa_match_acquire(parsedmsg_t *restrict pmsg, pkt_t *restrict pkt,
    ikev2_sa_result_t *restrict result)
{
	/* TODO */
	return (B_FALSE);
}

#if 0
sa_compare_xf_cb(ikev2_transform_t *xf, uchar_t *buf, size_t buflen,
    void *cookie)
{
	struct validate_data *data = cookie;
	boolean_t match = B_FALSE;

	/* xf_id */
	switch (xf->xf_type) {
	case IKEV2_XF_ENCR:
		if (data->xf->xf_encr == xf->xf_id)
			match = B_TRUE;
		break;
	case IKEV2_XF_PRF:
		switch (xf->xf_id) {
		case IKEV2_PRF_HMAC_SHA2_512:
		case IKEV2_PRF_HMAC_SHA2_384:
		case IKEV2_PRF_HMAC_SHA2_256:
		case IKEV2_PRF_HMAC_SHA1:
		case IKEV2_PRF_HMAC_MD5:
			match = B_TRUE;
			break;
		}
		break;
	case IKEV2_XF_AUTH:
		if (data->xf->xf_auth == xf->xf_id)
			match = B_TRUE;
		break;
	case IKEV2_XF_DH:
		if (data->xf->xf_dh == xf->xf_id)
			match = B_TRUE;
		break;
	case IKEV2_XF_ESN:
		/* XXX: msg */
		return (B_FALSE);
	default:
		bunyan_debug(data->log, "Unknown transform type",
		    BUNYAN_T_UINT32, "xftype", (uint32_t)xf->xf_type,
		    BUNYAN_T_END);
		return (B_FALSE);
	}

	if (match)
		data->match |= (uint32_t)1 << xf->xf_type;

	return (B_TRUE);
}
#endif
