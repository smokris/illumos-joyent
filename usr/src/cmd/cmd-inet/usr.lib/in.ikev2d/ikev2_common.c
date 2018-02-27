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
#include <alloca.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <errno.h>
#include <string.h>
#include <strings.h>
#include <sys/debug.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <net/pfkeyv2.h>

#include "defs.h"
#include "dh.h"
#include "ikev2_sa.h"
#include "ikev2_pkt.h"
#include "ikev2_common.h"
#include "ikev2_enum.h"
#include "ikev2_proto.h"
#include "config.h"
#include "pfkey.h"
#include "pkcs11.h"
#include "pkt.h"
#include "prf.h"
#include "util.h"
#include "worker.h"

/*
 * XXX: IKEv1 selectes the PRF based on the authentication algorithm.
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
	config_xf_t **xf = rule->rule_xf;
	boolean_t ok = B_TRUE;
	pkt_sa_state_t pss;

	if (rule->rule_xf == NULL)
		xf = config->cfg_default_xf;

	if (!ikev2_add_sa(pkt, &pss))
		return (B_FALSE);

	for (uint8_t i = 0; xf[i] != NULL; i++) {
		/* RFC 7296 3.3.1 - Proposal numbers start with 1 */
		ok &= ikev2_add_prop(&pss, i + 1, IKEV2_PROTO_IKE, spi);
		ok &= add_rule_xform(&pss, xf[i]);
	}

	return (ok);
}

static boolean_t
add_rule_xform(pkt_sa_state_t *restrict pss, const config_xf_t *restrict xf)
{
	encr_modes_t mode = encr_data(xf->xf_encr)->ed_mode;
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
ikev2_sa_add_result(pkt_t *restrict pkt, const ikev2_sa_match_t *restrict res,
    uint64_t spi)
{
	boolean_t ok;
	pkt_sa_state_t pss;

	ok = ikev2_add_sa(pkt, &pss);
	ok &= ikev2_add_prop(&pss, res->ism_propnum, res->ism_satype, spi);

	if (SA_MATCH_HAS(res, IKEV2_XF_ENCR)) {
		ok &= ikev2_add_xform(&pss, IKEV2_XF_ENCR, res->ism_encr);
		if (res->ism_encr_keylen != 0)
			ok &= ikev2_add_xf_attr(&pss, IKEV2_XF_ATTR_KEYLEN,
			    res->ism_encr_keylen);
	}
	if (SA_MATCH_HAS(res, IKEV2_XF_AUTH))
		ok &= ikev2_add_xform(&pss, IKEV2_XF_AUTH, res->ism_auth);
	if (SA_MATCH_HAS(res, IKEV2_XF_DH))
		ok &= ikev2_add_xform(&pss, IKEV2_XF_DH, res->ism_dh);
	if (SA_MATCH_HAS(res, IKEV2_XF_PRF))
		ok &= ikev2_add_xform(&pss, IKEV2_XF_PRF, res->ism_prf);
	if (SA_MATCH_HAS(res, IKEV2_XF_ESN))
		ok &= ikev2_add_xform(&pss, IKEV2_XF_ESN, res->ism_esn);

	return (ok);
}

static boolean_t ikev2_sa_match_prop(config_xf_t *restrict,
    ikev2_sa_proposal_t *restrict, ikev2_sa_match_t *restrict, boolean_t);
static boolean_t ikev2_sa_match_encr_attr(config_xf_t *restrict,
    ikev2_transform_t *restrict, ikev2_sa_match_t *restrict);
static boolean_t ikev2_sa_match_attr(ikev2_transform_t *restrict);

/*
 * Try to match a config_xf_t from a config_rule_t to an SA proposal
 * from a remote peer.
 *	rule	The rule containing the config_xf_t's used to match
 *	pkt	The packet with the SA payload to match
 *	m	The match results
 *	rekey	B_TRUE if this is part of an IKE SA rekey operation
 *
 * Returns B_TRUE if a match was found, B_FALSE otherwise.
 */
boolean_t
ikev2_sa_match_rule(config_rule_t *restrict rule, pkt_t *restrict pkt,
	ikev2_sa_match_t *restrict m, boolean_t rekey)
{
	pkt_payload_t *sa_pay = pkt_get_payload(pkt, IKEV2_PAYLOAD_SA, NULL);

	if (sa_pay == NULL) {
		(void) bunyan_warn(log, "Packet is missing SA payload",
		    BUNYAN_T_END);
		return (B_FALSE);
	}

	for (size_t i = 0; rule->rule_xf[i] != NULL; i++) {
		config_xf_t *rxf = rule->rule_xf[i];
		ikev2_sa_proposal_t *prop = ikev2_prop_first(sa_pay);

		FOREACH_PROP(prop, sa_pay) {
			if (ikev2_sa_match_prop(rxf, prop, m, rekey))
				return (B_TRUE);
		}
	}

	(void) bunyan_info(log,
	    "Could not find matching policy to create a new IKE SA",
	    BUNYAN_T_END);

	return (B_FALSE);
}

#define	UNKNOWN_XF(_xf, _val) \
    (void) bunyan_debug(log, "Unknown transform type; rejecting transform", \
	BUNYAN_T_STRING, "xftype", ikev2_xf_type_str((_xf)->xf_type), \
	BUNYAN_T_STRING, "xfval", ikev2_xf_str((_xf)->xf_type, (_val)), \
	BUNYAN_T_END)

/*
 * Compare the config_xf_t and ikev2_sa_proposal_t.  Return B_TRUE if the
 * two match (with matching results written to m).  B_FALSE if the two
 * do not match.
 */
static boolean_t
ikev2_sa_match_prop(config_xf_t *restrict rxf,
    ikev2_sa_proposal_t *restrict prop, ikev2_sa_match_t *restrict m,
    boolean_t rekey)
{
	ikev2_transform_t *xf = NULL;
	char spibuf[19] = { 0 };	/* 0x + 16-digit hex + NUL */
	bzero(m, sizeof (*m));

	if (prop->proto_protoid != IKEV2_PROTO_IKE) {
		(void) bunyan_warn(log,
		    "Invalid protocol (SA type) in SA proposal",
		    BUNYAN_T_UINT32, "proposal_num",
		    (uint32_t)prop->proto_proposalnr,
		    BUNYAN_T_STRING, "protocol",
		    ikev2_spi_str(prop->proto_protoid), BUNYAN_T_END);
		return (B_FALSE);
	}

	m->ism_spi = ikev2_prop_spi(prop);

	/*
	 * During an IKE_SA_INIT exchange, no SPI is included, however during
	 * an IKE rekey, the remote peer MUST include their SPI in the
	 * proposal.
	 */
	if (rekey && m->ism_spi == 0) {
		(void) bunyan_warn(log,
		    "Proposal does not contain a valid SPI value; ignoring",
		    BUNYAN_T_UINT32, "proposal_num",
		    (uint32_t)prop->proto_proposalnr, BUNYAN_T_END);
		return (B_FALSE);
	}

	if (!rekey && m->ism_spi != 0) {
		(void) bunyan_warn(log,
		    "Proposal in IKE_SA_INIT exchange contains an SPI value; "
		    "ignoring",
		    BUNYAN_T_UINT32, "proposal_num",
		    (uint32_t)prop->proto_proposalnr, BUNYAN_T_END);
		return (B_FALSE);
	}

	m->ism_propnum = prop->proto_proposalnr;
	m->ism_satype = prop->proto_protoid;
	m->ism_authmethod = rxf->xf_authtype;

	if (m->ism_spi != 0) {
		(void) snprintf(spibuf, sizeof (spibuf), "0x%016" PRIx64,
		    m->ism_spi);
	} else {
		(void) strlcpy(spibuf, "0x0", sizeof (spibuf));
	}

	(void) bunyan_debug(log, "Evaluating proposal",
	    BUNYAN_T_UINT32, "proposal_num", (uint32_t)m->ism_propnum,
	    BUNYAN_T_STRING, "protocol", ikev2_spi_str(m->ism_satype),
	    BUNYAN_T_STRING, "spi", spibuf,
	    BUNYAN_T_END);

	/*
	 * IKE SA policies MUST contain an encryption mechanism.  We have
	 * errored badly if we've successfully parsed a local policy without
	 * one.
	 */
	VERIFY3U(rxf->xf_encr, !=, IKEV2_ENCR_NONE);
	m->ism_have |= SEEN(IKEV2_XF_ENCR);

	/*
	 * For non-combined mode encryption mechanisms, we must also have
	 * an integrity mechanism selected.
	 */
	if (rxf->xf_auth != IKEV2_XF_AUTH_NONE)
		m->ism_have |= SEEN(IKEV2_XF_AUTH);
	else
		VERIFY(MODE_IS_COMBINED(encr_data(rxf->xf_encr)->ed_mode));

	/*
	 * config_rule_t's don't include any PRFs, instead every config_rule_t
	 * implictly includes all of the PRFs in prf_supported[], so we must
	 * check them separately.
	 */
	m->ism_have |= SEEN(IKEV2_XF_PRF);
	for (size_t i = 0; i < ARRAY_SIZE(prf_supported); i++) {
		FOREACH_XF(xf, prop) {
			if (xf->xf_type != IKEV2_XF_PRF)
				continue;

			m->ism_seen |= SEEN(IKEV2_XF_PRF);

			if (SA_MATCHES(m, IKEV2_XF_PRF))
				break;

			if (BE_IN16(&xf->xf_id) != prf_supported[i])
				continue;

			if (!ikev2_sa_match_attr(xf))
				continue;

			(void) bunyan_debug(log, "Transform match",
			    BUNYAN_T_STRING, "xftype",
			    ikev2_xf_type_str(xf->xf_type),
			    BUNYAN_T_STRING, "xfval", ikev2_prf_str(m->ism_prf),
			    BUNYAN_T_END);

			m->ism_prf = prf_supported[i];
			m->ism_match |= SEEN(IKEV2_XF_PRF);
			break;
		}

		if (SA_MATCHES(m, IKEV2_XF_PRF))
			break;
	}

	/*
	 * Go through the transforms again, looking at the non-PRF transforms.
	 * The general advice in RFC7296 is that a proposal that contains
	 * unknown transform types should be rejected.  A proposal that
	 * contains unknown transform values cause that specific transform
	 * to be rejected (but the remaining transforms in the proposal can
	 * still be evaluated).
	 */
	FOREACH_XF(xf, prop) {
		uint16_t val = BE_IN16(&xf->xf_id);

		(void) bunyan_debug(log, "Evaluating transform",
		    BUNYAN_T_STRING, "xftype", ikev2_xf_type_str(xf->xf_type),
		    BUNYAN_T_STRING, "xfval", ikev2_xf_str(xf->xf_type, val),
		    BUNYAN_T_END);

		switch ((ikev2_xf_type_t)xf->xf_type) {
		case IKEV2_XF_ENCR:
		case IKEV2_XF_PRF:
		case IKEV2_XF_AUTH:
		case IKEV2_XF_DH:
			/* Mark what we've seen (as long as it's none none) */
			if (val != 0)
				m->ism_seen |= SEEN(xf->xf_type);

			/* But use the first match for a given transform type */
			if (SA_MATCHES(m, xf->xf_type))
				continue;

			break;
		case IKEV2_XF_ESN:
			/*
			 * Warn instead of debug as ESN transforms are NEVER
			 * valid for IKE SAs.
			 */
			(void) bunyan_warn(log,
			    "IKE SA proposal contains an invalid transform",
			    BUNYAN_T_UINT32, "proposal_num",
			    (uint32_t)m->ism_propnum,
			    BUNYAN_T_STRING, "xftype",
			    ikev2_xf_type_str(xf->xf_type), BUNYAN_T_END);
			return (B_FALSE);
		default:
			/*
			 * Unknown transform types are ok, but we must reject
			 * the proposal containing them.
			 */
			(void) bunyan_debug(log,
			    "Unknown transform type; rejecting proposal",
			    BUNYAN_T_STRING, "xftype",
			    ikev2_xf_type_str(xf->xf_type), BUNYAN_T_END);
			return (B_FALSE);
		}

		switch ((ikev2_xf_type_t)xf->xf_type) {
		case IKEV2_XF_ENCR:
			/*
			 * We can never match an unknown id with our policy,
			 * however for diagnostic purposes, it seems useful
			 * to note when we encounter them.
			 */
			if (encr_data(val) == NULL) {
				UNKNOWN_XF(xf, val);
				continue;
			}

			if (rxf->xf_encr != val)
				continue;

			if (!ikev2_sa_match_encr_attr(rxf, xf, m))
				continue;

			m->ism_encr = val;
			m->ism_match |= SEEN(IKEV2_XF_ENCR);
			break;
		case IKEV2_XF_AUTH:
			/*
			 * We can never match an unknown id with our policy,
			 * however for diagnostic purposes, it seems useful
			 * to note when we encounter them.
			 */
			if (auth_data(val) == NULL) {
				UNKNOWN_XF(xf, val);
				continue;
			}

			if (rxf->xf_auth != val)
				continue;

			if (!ikev2_sa_match_attr(xf))
				continue;

			m->ism_auth = val;
			m->ism_match |= SEEN(IKEV2_XF_AUTH);
			break;
		case IKEV2_XF_DH:
			if (rxf->xf_dh != val)
				continue;

			if (!ikev2_sa_match_attr(xf))
				continue;

			m->ism_dh = val;
			m->ism_match |= SEEN(IKEV2_XF_DH);
			break;
		case IKEV2_XF_PRF:
		case IKEV2_XF_ESN:
			/* Handled earlier */
			break;
		}

		(void) bunyan_debug(log, "Transform match",
		    BUNYAN_T_STRING, "xftype", ikev2_xf_type_str(xf->xf_type),
		    BUNYAN_T_STRING, "xfval", ikev2_xf_str(xf->xf_type, val),
		    BUNYAN_T_END);
	}

	if (SA_MATCH(m)) {
		const encr_data_t *ed = encr_data(m->ism_encr);

		/*
		 * Keylengths can be mandatory, optional, or prohibited
		 * depending on the specific mechanism.  It is hopefully less
		 * confusing to only print a value when it is either mandatory
		 * or optional (with a non-default value).
		 *
		 * We do not to set m->ism_encr_keylen to the actual sized
		 * used since the ikev2_sa_results_t that contains the results
		 * of the evaluation is used to generate the response SA
		 * payload (and including a keylength when prohibited would
		 * cause the exchange to fail).
		 */
		if (m->ism_encr_keylen > 0) {
			(void) bunyan_key_add(log,
			    BUNYAN_T_UINT32, "encr_keylen",
			    (uint32_t)m->ism_encr_keylen, BUNYAN_T_END);
		}

		/*
		 * Similarly with integrity mechanisms, it is hopefully less
		 * confusing to omit it's value when using combined mode
		 * ciphers (vs. logging 'none' or logging the encryption
		 * mechanism as the integrity mechanism).
		 */
		if (!MODE_IS_COMBINED(ed->ed_mode)) {
			(void) bunyan_key_add(log,
			    BUNYAN_T_STRING, "auth",
			    ikev2_xf_auth_str(m->ism_auth), BUNYAN_T_END);
		}

		if (m->ism_spi != 0) {
			(void) snprintf(spibuf, sizeof (spibuf), "0x" PRIx64,
			    m->ism_spi);
		} else {
			(void) strlcpy(spibuf, "0x0", sizeof (spibuf));
		}

		(void) bunyan_debug(log, "Proposal matched",
		    BUNYAN_T_UINT32, "proposal_num", (uint32_t)m->ism_propnum,
		    BUNYAN_T_STRING, "protocol", ikev2_spi_str(m->ism_satype),
		    BUNYAN_T_STRING, "spi", spibuf,
		    BUNYAN_T_STRING, "encr", ikev2_xf_encr_str(m->ism_encr),
		    BUNYAN_T_STRING, "prf", ikev2_prf_str(m->ism_prf),
		    BUNYAN_T_STRING, "dh", ikev2_dh_str(m->ism_dh),
		    BUNYAN_T_END);

		(void) bunyan_key_remove(log, "auth");
		(void) bunyan_key_remove(log, "encr_keylen");

		return (B_TRUE);
	}

	(void) bunyan_debug(log, "Proposal did not match", BUNYAN_T_END);
	return (B_FALSE);
}

static boolean_t
ikev2_sa_match_encr_attr(config_xf_t *restrict rxf,
    ikev2_transform_t *restrict i2xf, ikev2_sa_match_t *restrict m)
{
	const encr_data_t *ed = NULL;
	ikev2_attribute_t *attr = NULL;
	uint16_t val = BE_IN16(&i2xf->xf_id);

	ed = encr_data(val);

	if (!XF_HAS_ATTRS(i2xf) && encr_keylen_req(ed)) {
		(void) bunyan_warn(log,
		    "Transform is missing required keylength attribute",
		    BUNYAN_T_STRING, "xftype", ikev2_xf_type_str(i2xf->xf_type),
		    BUNYAN_T_STRING, "xfval", ikev2_xf_str(i2xf->xf_type, val),
		    BUNYAN_T_END);
		return (B_FALSE);
	}

	FOREACH_ATTR(attr, i2xf) {
		uint16_t type = BE_IN16(&attr->attr_type);
		uint16_t len = BE_IN16(&attr->attr_length);
		boolean_t tv = B_FALSE;

		if (IKE_ATTR_GET_FORMAT(type) == IKE_ATTR_TV)
			tv = B_TRUE;

		type = IKE_ATTR_GET_TYPE(type);

		if (!tv || type != IKEV2_XF_ATTR_KEYLEN) {
			(void) bunyan_debug(log,
			    "Transform contains unknown attribute; "
			    "ignoring transform",
			    BUNYAN_T_STRING, "xftype",
			    ikev2_xf_type_str(i2xf->xf_type),
			    BUNYAN_T_STRING, "xfval",
			    ikev2_xf_str(i2xf->xf_type, val),
			    BUNYAN_T_UINT32, "attrtype", (uint32_t)type,
			    BUNYAN_T_UINT32,
			    tv ? "attrval" : "attrlen", (uint32_t)len,
			    BUNYAN_T_END);

			return (B_FALSE);
		}

		(void) bunyan_debug(log, "Evaluating keylength",
		    BUNYAN_T_STRING, "xftype", ikev2_xf_type_str(i2xf->xf_type),
		    BUNYAN_T_STRING, "xfval", ikev2_xf_str(i2xf->xf_type, val),
		    BUNYAN_T_UINT32, "keylen", (uint32_t)len,
		    BUNYAN_T_END);

		/*
		 * This is arguably an invalid transform rather than merely
		 * one that does not match, so explicitly log it, and log
		 * as a warning.
		 */
		if (!encr_keylen_allowed(ed)) {
			(void) bunyan_warn(log,
			    "Transform included a keylength when none should "
			    "present; rejecting transform",
			    BUNYAN_T_STRING, "xftype",
			    ikev2_xf_type_str(i2xf->xf_type),
			    BUNYAN_T_STRING, "xfval",
			    ikev2_xf_str(i2xf->xf_type, val),
			    BUNYAN_T_UINT32, "keylen", (uint32_t)len,
			    BUNYAN_T_END);
			return (B_FALSE);
		}

		if (!encr_keylen_ok(ed, len))
			return (B_FALSE);

		if (rxf->xf_minbits > len || rxf->xf_maxbits < len) {
			(void) bunyan_debug(log,
			    "Encryption keylength does not match",
			    BUNYAN_T_UINT32, "keylen", (uint32_t)len,
			    BUNYAN_T_UINT32, "keymin",
			    (uint32_t)rxf->xf_minbits,
			    BUNYAN_T_UINT32, "keymax",
			    (uint32_t)rxf->xf_maxbits,
			    BUNYAN_T_END);
			return (B_FALSE);
		}

		m->ism_encr_keylen = len;
		(void) bunyan_debug(log,
		    "Encryption keylength matches",
		    BUNYAN_T_STRING, "xftype", ikev2_xf_type_str(i2xf->xf_type),
		    BUNYAN_T_STRING, "xfval", ikev2_xf_str(i2xf->xf_type, val),
		    BUNYAN_T_UINT32, "keylen", (uint32_t)len,
		    BUNYAN_T_END);
	}

	return (B_TRUE);
}

/*
 * A generic handler for any transform type that does not have any
 * known/supported attributes.  Returns B_FALSE if any attributes are
 * present, B_TRUE if no attributes are present.
 */
static boolean_t
ikev2_sa_match_attr(ikev2_transform_t *restrict i2xf)
{
	if (!XF_HAS_ATTRS(i2xf))
		return (B_TRUE);

	(void) bunyan_debug(log, "Transform contains unknown attribute(s); "
	    "ignoring transform", BUNYAN_T_END);

	return (B_FALSE);
}

boolean_t
ikev2_sa_check_prop(config_rule_t *restrict rule, pkt_t *restrict resp,
    ikev2_sa_match_t *restrict m, boolean_t rekey)
{
	config_xf_t *rxf = NULL;
	pkt_payload_t *sa_pay = pkt_get_payload(resp, IKEV2_PAYLOAD_SA, NULL);
	ikev2_sa_proposal_t *prop = NULL;

	if (sa_pay == NULL) {
		(void) bunyan_warn(log, "SA payload is missing in response",
		    BUNYAN_T_END);
		return (B_FALSE);
	}

	prop = ikev2_prop_first(sa_pay);

	for (size_t i = 0; rule->rule_xf[i] != NULL; i++) {
		if (i + 1 != prop->proto_proposalnr)
			continue;

		rxf = rule->rule_xf[i];
		break;
	}

	if (rxf == NULL) {
		(void) bunyan_warn(log,
		    "SA payload returned an invalid proposal number",
		    BUNYAN_T_UINT32, "proposal_num",
		    (uint32_t)prop->proto_proposalnr, BUNYAN_T_END);
		return (B_FALSE);
	}

	return (ikev2_sa_match_prop(rxf, prop, m, rekey));
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

boolean_t
ikev2_create_nonce(ikev2_sa_args_t *restrict i2a, boolean_t initiator,
    size_t noncelen)
{
	uint8_t *restrict buf = initiator ? i2a->i2a_nonce_i : i2a->i2a_nonce_r;
	size_t *restrict lenp = initiator ?
	    &i2a->i2a_nonce_i_len : &i2a->i2a_nonce_r_len;

	/*
	 * A single getentropy(3C) call is limited to 256 bytes in a single
	 * call.  If further updates to IKEv2 allow for larger nonce sizes,
	 * we want to catch it at compile time so this can be updated
	 * appropriately.
	 */
	CTASSERT(IKEV2_NONCE_MAX <= 256);

	VERIFY3U(noncelen, >=, IKEV2_NONCE_MIN);
	VERIFY3U(noncelen, <=, IKEV2_NONCE_MAX);

	/*
	 * Once set, we don't recreate the nonce for a given exchange, this
	 * simplifies instances such as encountering an INVALID_KE_PAYLOAD
	 * where we need to retry and use the same nonce (i.e. during an
	 * IKE_SA_INIT exchange).
	 */
	if (*lenp != 0)
		return (B_TRUE);

	if (getentropy(buf, noncelen) != 0) {
		STDERR(error, "getentropy(3C) failed while generating nonce");
		return (B_FALSE);
	}

	*lenp = noncelen;
	return (B_TRUE);
}

boolean_t
ikev2_ke(ikev2_sa_args_t *restrict i2a, pkt_t *restrict pkt)
{
	pkt_payload_t *ke_pay = NULL;
	uint8_t *ke = NULL;
	char *hex = NULL;
	size_t kelen = 0, hexlen = 0;
	ikev2_dh_t dh = i2a->i2a_dh;

	if (dh == IKEV2_DH_NONE)
		return (B_TRUE);

	if ((ke_pay = pkt_get_payload(pkt, IKEV2_PAYLOAD_KE, NULL)) == NULL) {
		(void) bunyan_warn(log, "Packet is missing KE payload",
		    BUNYAN_T_END);
		return (B_FALSE);
	}

	ke = ke_pay->pp_ptr + sizeof (ikev2_ke_t);
	kelen = ke_pay->pp_len - sizeof (ikev2_ke_t);

	if (!derivekey(dh, i2a->i2a_privkey, ke, kelen, &i2a->i2a_dhkey))
		return (B_FALSE);

	if (show_keys) {
		/* XXX: should rename these to something more generic */
		void *gir = NULL;
		size_t gir_len = 0;
		CK_RV rc;

		rc = pkcs11_ObjectToKey(p11h(), i2a->i2a_dhkey, &gir, &gir_len,
		    B_FALSE);

		hexlen = gir_len * 2 + 1;
		if (rc == CKR_OK && ((hex = malloc(hexlen)) != NULL)) {
			bzero(hex, hexlen);
			(void) writehex(gir, gir_len, "", hex, hexlen);
		}
		explicit_bzero(gir, gir_len);
		free(gir);
	}

	(void) bunyan_debug(log, "Created shared secret key",
	    show_keys ? BUNYAN_T_STRING : BUNYAN_T_END, "key", hex,
	    BUNYAN_T_END);

	if (hex != NULL) {
		explicit_bzero(hex, hexlen);
		free(hex);
	}

	return (B_TRUE);
}

void
ikev2_save_nonce(ikev2_sa_args_t *restrict i2a, pkt_t *restrict pkt)
{
	pkt_payload_t *no_pay = pkt_get_payload(pkt, IKEV2_PAYLOAD_NONCE, NULL);

	VERIFY3U(no_pay->pp_len, <=, IKEV2_NONCE_MAX);

	if (I2P_INITIATOR(pkt)) {
		bcopy(no_pay->pp_ptr, i2a->i2a_nonce_i, no_pay->pp_len);
		i2a->i2a_nonce_i_len = no_pay->pp_len;
	} else {
		bcopy(no_pay->pp_ptr, i2a->i2a_nonce_r, no_pay->pp_len);
		i2a->i2a_nonce_r_len = no_pay->pp_len;
	}
}

void
ikev2_save_i2sa_results(ikev2_sa_t *restrict i2sa,
    ikev2_sa_match_t *restrict result)
{
	const encr_data_t *ed = encr_data(result->ism_encr);

	i2sa->encr = result->ism_encr;
	i2sa->auth = result->ism_auth;
	i2sa->prf = result->ism_prf;
	i2sa->dhgrp = result->ism_dh;
	i2sa->saltlen = ed->ed_saltlen;
	i2sa->encr_keylen = result->ism_encr_keylen;

	if (i2sa->encr_keylen == 0)
		i2sa->encr_keylen = ed->ed_keydefault;
}

boolean_t
ikev2_create_i2sa_keys(ikev2_sa_t *restrict i2sa, CK_OBJECT_HANDLE skeyseed,
    uint8_t *restrict ni, size_t ni_len, uint8_t *restrict nr, size_t nr_len)
{
	const auth_data_t *ad = auth_data(i2sa->auth);

	uint64_t spis[2] = { i2sa->i_spi, i2sa->r_spi };
	size_t encrlen = SADB_1TO8(i2sa->encr_keylen);
	size_t prflen = ikev2_prf_keylen(i2sa->prf);
	size_t authlen = ad->ad_keylen;
	CK_MECHANISM_TYPE p11prf = ikev2_prf_to_p11(i2sa->prf);
	CK_MECHANISM_TYPE p11encr = encr_data(i2sa->encr)->ed_p11id;
	CK_MECHANISM_TYPE p11auth = ad->ad_p11id;
	boolean_t ret = B_FALSE;
	prfp_t prfp = { 0 };

	/*
	 * RFC7296 2.14:
	 *
	 * {SK_d | SK_ai | SK_ar | SK_ei | SK_er | SK_pi | SK_pr}
	 *			 = prf+ (SKEYSEED, Ni | Nr | SPIi | SPIr)
	 *
	 * Note: some encryption mechanisms (e.g. AES-GCM) include a salt
	 * value (sa->saltlen > 0) as part of their key.  For all currently
	 * defined mechanisms, these take the form of a cipher key
	 * (encr_key_len bytes long) followed by the salt bytes.  Since usage
	 * of these mechanisms requires the salt to be used separate from the
	 * cipher key, we generate the salt bits in their own operation
	 * immediately after we've generated the corresponding cipher key.
	 *
	 * For more details, see:
	 *      RFC5282 7.1 for AES-{CCM,GCM}
	 *      RFC5529 4.1 for Camellia
	 */
	if (!prfplus_init(&prfp, i2sa->prf, skeyseed,
	    ni, ni_len, nr, nr_len, &spis, sizeof (spis), NULL))
		goto done;

	/*
	 * If any one of these fail, there's nothing to salvage and the
	 * functions themselves will log any errors, so take advantage of
	 * short circuit evaluation.
	 */
	ret = prf_to_p11key(&prfp, "SK_d", p11prf, prflen, &i2sa->sk_d) &&
	    prf_to_p11key(&prfp, "SK_ai", p11auth, authlen, &i2sa->sk_ai) &&
	    prf_to_p11key(&prfp, "SK_ar", p11auth, authlen, &i2sa->sk_ar) &&
	    prf_to_p11key(&prfp, "SK_ei", p11encr, encrlen, &i2sa->sk_ei) &&
	    prfplus(&prfp, i2sa->salt_i, SADB_1TO8(i2sa->saltlen)) &&
	    prf_to_p11key(&prfp, "SK_er", p11encr, encrlen, &i2sa->sk_er) &&
	    prfplus(&prfp, i2sa->salt_r, SADB_1TO8(i2sa->saltlen)) &&
	    prf_to_p11key(&prfp, "SK_pi", p11prf, prflen, &i2sa->sk_pi) &&
	    prf_to_p11key(&prfp, "SK_pr", p11prf, prflen, &i2sa->sk_pr);

done:
	prfplus_fini(&prfp);
	return (ret);
}

ikev2_sa_args_t *
ikev2_sa_args_new(boolean_t create_children)
{
	ikev2_sa_args_t *args = NULL;
	ikev2_child_sa_t *in = NULL, *out = NULL;

	if ((args = umem_zalloc(sizeof *args, UMEM_DEFAULT)) == NULL)
		return (NULL);

	if (create_children) {
		in = ikev2_child_sa_alloc(B_TRUE);
		out = ikev2_child_sa_alloc(B_FALSE);

		if (in == NULL || out == NULL) {
			ikev2_child_sa_free(NULL, in);
			ikev2_child_sa_free(NULL, out);
			umem_free(args, sizeof (*args));
			return (NULL);
		}
	}

	args->i2a_child[CSA_IN].csa_child = in;
	args->i2a_child[CSA_OUT].csa_child = out;
	return (args);
}

void
ikev2_sa_args_free(ikev2_sa_args_t *i2a)
{
	if (i2a == NULL)
		return;

	if (i2a->i2a_pmsg != NULL)
		parsedmsg_free(i2a->i2a_pmsg);

	if (i2a->i2a_init_i != NULL)
		umem_free(i2a->i2a_init_i, i2a->i2a_init_i_len);
	if (i2a->i2a_init_r != NULL)
		umem_free(i2a->i2a_init_r, i2a->i2a_init_r_len);

	ikev2_child_sa_state_t *kids = i2a->i2a_child;
	for (int i = 0; i < 2; i++) {
		if (!kids[i].csa_child_added)
			ikev2_child_sa_free(i2a->i2a_i2sa, kids[i].csa_child);
		explicit_bzero(kids[i].csa_child_encr, ENCR_MAX);
		explicit_bzero(kids[i].csa_child_auth, AUTH_MAX);
	}

	pkcs11_destroy_obj("dh_pubkey", &i2a->i2a_pubkey);
	pkcs11_destroy_obj("dh_privkey", &i2a->i2a_privkey);
	pkcs11_destroy_obj("dh_key", &i2a->i2a_dhkey);

	explicit_bzero(i2a, sizeof (*i2a));
	umem_free(i2a, sizeof (*i2a));
}
