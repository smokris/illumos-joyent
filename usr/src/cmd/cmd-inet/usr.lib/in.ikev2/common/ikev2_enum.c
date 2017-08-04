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
 * Copyright (c) 2017 Joyent, Inc.
 */

#include "ikev2_enum.h"
#include "ikev2.h"

#define	STR(x) case x: return (#x)

/*
 * NOTE: We intentionally use switch statements instead of arrays for
 * mapping enumerated constants to strings.  Doing so will allow the
 * compiler to flag missing conversions for any entries that get added
 * to enumerated types as long as no default clause is used in the switch.
 */

const char *
ikev2_exch_str(ikev2_exch_t id)
{
	switch (id) {
	case IKEV2_EXCH_IKE_SA_INIT:
		return ("SA_INIT");
	case IKEV2_EXCH_IKE_AUTH:
		return ("AUTH");
	case IKEV2_EXCH_CREATE_CHILD_SA:
		return ("CREATE_CHILD_SA");
	case IKEV2_EXCH_INFORMATIONAL:
		return ("INFORMATIONAL");
	case IKEV2_EXCH_IKE_SESSION_RESUME:
		return ("SESSION_RESUME");
	}
	return ("UNKNOWN");
}

const char *
ikev2_pay_str(ikev2_pay_type_t id)
{
	switch (id) {
	STR(IKEV2_PAYLOAD_NONE);
	STR(IKEV2_PAYLOAD_SA);
	STR(IKEV2_PAYLOAD_KE);
	STR(IKEV2_PAYLOAD_IDi);
	STR(IKEV2_PAYLOAD_IDr);
	STR(IKEV2_PAYLOAD_CERT);
	STR(IKEV2_PAYLOAD_CERTREQ);
	STR(IKEV2_PAYLOAD_AUTH);
	STR(IKEV2_PAYLOAD_NONCE);
	STR(IKEV2_PAYLOAD_NOTIFY);
	STR(IKEV2_PAYLOAD_DELETE);
	STR(IKEV2_PAYLOAD_VENDOR);
	STR(IKEV2_PAYLOAD_TSi);
	STR(IKEV2_PAYLOAD_TSr);
	STR(IKEV2_PAYLOAD_SK);
	STR(IKEV2_PAYLOAD_CP);
	STR(IKEV2_PAYLOAD_EAP);
	STR(IKEV2_PAYLOAD_GSPM);
	}
	return ("UNKNOWN");
}

const char *
ikev2_spi_str(ikev2_spi_proto_t id)
{
	switch (id) {
	case IKEV2_PROTO_NONE:
		return ("NONE");
	case IKEV2_PROTO_IKE:
		return ("IKE");
	case IKEV2_PROTO_AH:
		return ("AH");
	case IKEV2_PROTO_ESP:
		return ("ESP");
	case IKEV2_PROTO_FC_ESP_HEADER:
		return ("FC_ESP_HEADER");
	case IKEV2_PROTO_FC_CT_AUTH:
		return ("FC_CT_AUTH");
	}
	return ("UNKNOWN");
}

const char *
ikev2_xf_type_str(ikev2_xf_type_t id)
{
	switch (id) {
	case IKEV2_XF_ENCR:
		return ("ENCR");
	case IKEV2_XF_PRF:
		return ("PRF");
	case IKEV2_XF_AUTH:
		return ("AUTH");
	case IKEV2_XF_DH:
		return ("DH");
	case IKEV2_XF_ESN:
		return ("ESN");
	}
	return ("UNKNOWN");
}

const char *
ikev2_xf_encr_str(ikev2_xf_encr_t id)
{
	switch (id) {
	STR(IKEV2_ENCR_NONE);
	STR(IKEV2_ENCR_DES_IV64);
	STR(IKEV2_ENCR_DES);
	STR(IKEV2_ENCR_3DES);
	STR(IKEV2_ENCR_RC5);
	STR(IKEV2_ENCR_IDEA);
	STR(IKEV2_ENCR_CAST);
	STR(IKEV2_ENCR_BLOWFISH);
	STR(IKEV2_ENCR_3IDEA);
	STR(IKEV2_ENCR_DES_IV32);
	STR(IKEV2_ENCR_RC4);
	STR(IKEV2_ENCR_NULL);
	STR(IKEV2_ENCR_AES_CBC);
	STR(IKEV2_ENCR_AES_CTR);
	STR(IKEV2_ENCR_AES_CCM_8);
	STR(IKEV2_ENCR_AES_CCM_12);
	STR(IKEV2_ENCR_AES_CCM_16);
	STR(IKEV2_ENCR_AES_GCM_8);
	STR(IKEV2_ENCR_AES_GCM_12);
	STR(IKEV2_ENCR_AES_GCM_16);
	STR(IKEV2_ENCR_NULL_AES_GMAC);
	STR(IKEV2_ENCR_XTS_AES);
	STR(IKEV2_ENCR_CAMELLIA_CBC);
	STR(IKEV2_ENCR_CAMELLIA_CTR);
	STR(IKEV2_ENCR_CAMELLIA_CCM_8);
	STR(IKEV2_ENCR_CAMELLIA_CCM_12);
	STR(IKEV2_ENCR_CAMELLIA_CCM_16);
	}
	return ("UNKNOWN");
}

const char *
ikev2_xf_auth_str(ikev2_xf_auth_t id)
{
	switch (id) {
	STR(IKEV2_XF_AUTH_NONE);
	STR(IKEV2_XF_AUTH_HMAC_MD5_96);
	STR(IKEV2_XF_AUTH_HMAC_SHA1_96);
	STR(IKEV2_XF_AUTH_DES_MAC);
	STR(IKEV2_XF_AUTH_KPDK_MD5);
	STR(IKEV2_XF_AUTH_AES_XCBC_96);
	STR(IKEV2_XF_AUTH_HMAC_MD5_128);
	STR(IKEV2_XF_AUTH_HMAC_SHA1_160);
	STR(IKEV2_XF_AUTH_AES_CMAC_96);
	STR(IKEV2_XF_AUTH_AES_128_GMAC);
	STR(IKEV2_XF_AUTH_AES_192_GMAC);
	STR(IKEV2_XF_AUTH_AES_256_GMAC);
	STR(IKEV2_XF_AUTH_HMAC_SHA2_256_128);
	STR(IKEV2_XF_AUTH_HMAC_SHA2_384_192);
	STR(IKEV2_XF_AUTH_HMAC_SHA2_512_256);
	}
	return ("UNKNOWN");
}

const char *
ikev2_auth_type_str(ikev2_auth_type_t id)
{
	switch (id) {
	STR(IKEV2_AUTH_NONE);
	STR(IKEV2_AUTH_RSA_SIG);
	STR(IKEV2_AUTH_SHARED_KEY_MIC);
	STR(IKEV2_AUTH_DSS_SIG);
	STR(IKEV2_AUTH_ECDSA_256);
	STR(IKEV2_AUTH_ECDSA_384);
	STR(IKEV2_AUTH_ECDSA_512);
	STR(IKEV2_AUTH_GSPM);
	}
	return ("UNKNOWN");
}
