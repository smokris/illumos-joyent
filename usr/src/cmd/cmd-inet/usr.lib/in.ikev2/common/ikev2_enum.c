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
#include <stdio.h>
#include <string.h>
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
ikev2_exch_str(ikev2_exch_t id, char *buf, size_t buflen)
{
	switch (id) {
	case IKEV2_EXCH_IKE_SA_INIT:
		return ("IKE_SA_INIT");
	case IKEV2_EXCH_IKE_AUTH:
		return ("IKE_AUTH");
	case IKEV2_EXCH_CREATE_CHILD_SA:
		return ("CREATE_CHILD_SA");
	case IKEV2_EXCH_INFORMATIONAL:
		return ("INFORMATIONAL");
	case IKEV2_EXCH_IKE_SESSION_RESUME:
		return ("IKE_SESSION_RESUME");
	case IKEV2_EXCH_GSA_AUTH:
		return ("GSA_AUTH");
	case IKEV2_EXCH_GSA_REGISTRATION:
		return ("GSA_REGISTRATION");
	case IKEV2_EXCH_GSA_REKEY:
		return ("GSA_REKEY");
	}

	(void) snprintf(buf, buflen, "UNKNOWN <%hhu>", (uint8_t)id);
	return (buf);
}

const char *
ikev2_pay_str(ikev2_pay_type_t id, char *buf, size_t buflen)
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
	STR(IKEV2_PAYLOAD_IDg);
	STR(IKEV2_PAYLOAD_GSA);
	STR(IKEV2_PAYLOAD_KD);
	STR(IKEV2_PAYLOAD_SKF);
	STR(IKEV2_PAYLOAD_PS);
	}

	(void) snprintf(buf, buflen, "%hhu", (uint8_t)id);
	return (buf);
}

const char *
ikev2_pay_short_str(ikev2_pay_type_t id, char *buf, size_t buflen)
{
	switch (id) {
	case IKEV2_PAYLOAD_NONE:
		return ("NONE");
	case IKEV2_PAYLOAD_SA:
		return ("SA");
	case IKEV2_PAYLOAD_KE:
		return ("KE");
	case IKEV2_PAYLOAD_IDi:
		return ("IDi");
	case IKEV2_PAYLOAD_IDr:
		return ("IDr");
	case IKEV2_PAYLOAD_CERT:
		return ("CERT");
	case IKEV2_PAYLOAD_CERTREQ:
		return ("CERTREQ");
	case IKEV2_PAYLOAD_AUTH:
		return ("AUTH");
	case IKEV2_PAYLOAD_NONCE:
		return ("No");
	case IKEV2_PAYLOAD_NOTIFY:
		return ("N");
	case IKEV2_PAYLOAD_DELETE:
		return ("D");
	case IKEV2_PAYLOAD_VENDOR:
		return ("V");
	case IKEV2_PAYLOAD_TSi:
		return ("TSi");
	case IKEV2_PAYLOAD_TSr:
		return ("TSr");
	case IKEV2_PAYLOAD_SK:
		return ("SK");
	case IKEV2_PAYLOAD_CP:
		return ("CP");
	case IKEV2_PAYLOAD_EAP:
		return ("EAP");
	case IKEV2_PAYLOAD_GSPM:
		return ("GSPM");
	case IKEV2_PAYLOAD_IDg:
		return ("IDg");
	case IKEV2_PAYLOAD_GSA:
		return ("GSA");
	case IKEV2_PAYLOAD_KD:
		return ("KD");
	case IKEV2_PAYLOAD_SKF:
		return ("SKF");
	case IKEV2_PAYLOAD_PS:
		return ("PS");
	}
	(void) snprintf(buf, buflen, "%hhu", (uint8_t)id);
	return (buf);
}
const char *
ikev2_spi_str(ikev2_spi_proto_t id, char *buf, size_t buflen)
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
	(void) snprintf(buf, buflen, "%hhu", (uint8_t)id);
	return (buf);
}

const char *
ikev2_xf_type_str(ikev2_xf_type_t id, char *buf, size_t buflen)
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
	(void) snprintf(buf, buflen, "%hhu", (uint8_t)id);
	return (buf);
}

const char *
ikev2_xf_encr_str(ikev2_xf_encr_t id, char *buf, size_t buflen)
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
	(void) snprintf(buf, buflen, "%hhu", (uint8_t)id);
	return (buf);
}

const char *
ikev2_xf_auth_str(ikev2_xf_auth_t id, char *buf, size_t buflen)
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
	(void) snprintf(buf, buflen, "%hhu", (uint8_t)id);
	return (buf);
}

const char *
ikev2_auth_type_str(ikev2_auth_type_t id, char *buf, size_t buflen)
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
	(void) snprintf(buf, buflen, "%hhu", (uint8_t)id);
	return (buf);
}

const char *
ikev2_dh_str(ikev2_dh_t id, char *buf, size_t buflen)
{
	switch (id) {
	STR(IKEV2_DH_NONE);
	STR(IKEV2_DH_MODP_768);
	STR(IKEV2_DH_MODP_1024);
	STR(IKEV2_DH_EC2N_155);
	STR(IKEV2_DH_EC2N_185);
	STR(IKEV2_DH_MODP_1536);
	STR(IKEV2_DH_MODP_2048);
	STR(IKEV2_DH_MODP_3072);
	STR(IKEV2_DH_MODP_4096);
	STR(IKEV2_DH_MODP_6144);
	STR(IKEV2_DH_MODP_8192);
	STR(IKEV2_DH_ECP_256);
	STR(IKEV2_DH_ECP_384);
	STR(IKEV2_DH_ECP_521);
	STR(IKEV2_DH_MODP_1024_160);
	STR(IKEV2_DH_MODP_2048_224);
	STR(IKEV2_DH_MODP_2048_256);
	STR(IKEV2_DH_ECP_192);
	STR(IKEV2_DH_ECP_224);
	STR(IKEV2_DH_BRAINPOOL_P224R1);
	STR(IKEV2_DH_BRAINPOOL_P256R1);
	STR(IKEV2_DH_BRAINPOOL_P384R1);
	STR(IKEV2_DH_BRAINPOOL_P512R1);
	}
	(void) snprintf(buf, buflen, "%hhu", (uint8_t)id);
	return (buf);
}

const char *
ikev2_prf_str(ikev2_prf_t id, char *buf, size_t buflen)
{
	switch (id) {
	STR(IKEV2_PRF_HMAC_MD5);
	STR(IKEV2_PRF_HMAC_SHA1);
	STR(IKEV2_PRF_HMAC_TIGER);
	STR(IKEV2_PRF_AES128_XCBC);
	STR(IKEV2_PRF_HMAC_SHA2_256);
	STR(IKEV2_PRF_HMAC_SHA2_384);
	STR(IKEV2_PRF_HMAC_SHA2_512);
	STR(IKEV2_PRF_AES128_CMAC);
	}
	(void) snprintf(buf, buflen, "%hhu", (uint8_t)id);
	return (buf);
}

const char *
ikev2_notify_str(ikev2_notify_type_t id, char *buf, size_t buflen)
{
	switch (id) {
	case IKEV2_N_UNSUPPORTED_CRITICAL_PAYLOAD:
		return ("UNSUPPORTED_CRITICAL_PAYLOAD");
	case IKEV2_N_INVALID_IKE_SPI:
		return ("INVALID_IKE_SPI");
	case IKEV2_N_INVALID_MAJOR_VERSION:
		return ("INVALID_MAJOR_VERSION");
	case IKEV2_N_INVALID_SYNTAX:
		return ("INVALID_SYNTAX");
	case IKEV2_N_INVALID_MESSAGE_ID:
		return ("INVALID_MESSAGE_ID");
	case IKEV2_N_INVALID_SPI:
		return ("INVALID_SPI");
	case IKEV2_N_NO_PROPOSAL_CHOSEN:
		return ("NO_PROPOSAL_CHOSEN");
	case IKEV2_N_INVALID_KE_PAYLOAD:
		return ("INVALID_KE_PAYLOAD");
	case IKEV2_N_AUTHENTICATION_FAILED:
		return ("AUTHENTICATION_FAILED");
	case IKEV2_N_SINGLE_PAIR_REQUIRED:
		return ("SINGLE_PAIR_REQUIRED");
	case IKEV2_N_NO_ADDITIONAL_SAS:
		return ("NO_ADDITIONAL_SAS");
	case IKEV2_N_INTERNAL_ADDRESS_FAILURE:
		return ("INTERNAL_ADDRESS_FAILURE");
	case IKEV2_N_FAILED_CP_REQUIRED:
		return ("FAILED_CP_REQUIRED");
	case IKEV2_N_TS_UNACCEPTABLE:
		return ("TS_UNACCEPTABLE");
	case IKEV2_N_INVALID_SELECTORS:
		return ("INVALID_SELECTORS");
	case IKEV2_N_UNACCEPTABLE_ADDRESSES:
		return ("UNACCEPTABLE_ADDRESSES");
	case IKEV2_N_UNEXPECTED_NAT_DETECTED:
		return ("UNEXPECTED_NAT_DETECTED");
	case IKEV2_N_USE_ASSIGNED_HoA:
		return ("USE_ASSIGNED_HoA");
	case IKEV2_N_TEMPORARY_FAILURE:
		return ("TEMPORARY_FAILURE");
	case IKEV2_N_CHILD_SA_NOT_FOUND:
		return ("CHILD_SA_NOT_FOUND");
	case IKEV2_N_INITIAL_CONTACT:
		return ("INITIAL_CONTACT");
	case IKEV2_N_SET_WINDOW_SIZE:
		return ("SET_WINDOW_SIZE");
	case IKEV2_N_ADDITIONAL_TS_POSSIBLE:
		return ("ADDITIONAL_TS_POSSIBLE");
	case IKEV2_N_IPCOMP_SUPPORTED:
		return ("IPCOMP_SUPPORTED");
	case IKEV2_N_NAT_DETECTION_SOURCE_IP:
		return ("NAT_DETECTION_SOURCE_IP");
	case IKEV2_N_NAT_DETECTION_DESTINATION_IP:
		return ("NAT_DETECTION_DESTINATION_IP");
	case IKEV2_N_COOKIE:
		return ("COOKIE");
	case IKEV2_N_USE_TRANSPORT_MODE:
		return ("USE_TRANSPORT_MODE");
	case IKEV2_N_HTTP_CERT_LOOKUP_SUPPORTED:
		return ("HTTP_CERT_LOOKUP_SUPPORTED");
	case IKEV2_N_REKEY_SA:
		return ("REKEY_SA");
	case IKEV2_N_ESP_TFC_PADDING_NOT_SUPPORTED:
		return ("ESP_TFC_PADDING_NOT_SUPPORTED");
	case IKEV2_N_NON_FIRST_FRAGMENTS_ALSO:
		return ("NON_FIRST_FRAGMENTS_ALSO");
	case IKEV2_N_MOBIKE_SUPPORTED:
		return ("MOBIKE_SUPPORTED");
	case IKEV2_N_ADDITIONAL_IP4_ADDRESS:
		return ("ADDITIONAL_IP4_ADDRESS");
	case IKEV2_N_ADDITIONAL_IP6_ADDRESS:
		return ("ADDITIONAL_IP6_ADDRESS");
	case IKEV2_N_NO_ADDITIONAL_ADDRESSES:
		return ("NO_ADDITIONAL_ADDRESSES");
	case IKEV2_N_UPDATE_SA_ADDRESSES:
		return ("UPDATE_SA_ADDRESSES");
	case IKEV2_N_COOKIE2:
		return ("COOKIE2");
	case IKEV2_N_NO_NATS_ALLOWED:
		return ("NO_NATS_ALLOWED");
	case IKEV2_N_AUTH_LIFETIME:
		return ("AUTH_LIFETIME");
	case IKEV2_N_MULTIPLE_AUTH_SUPPORTED:
		return ("MULTIPLE_AUTH_SUPPORTED");
	case IKEV2_N_ANOTHER_AUTH_FOLLOWS:
		return ("ANOTHER_AUTH_FOLLOWS");
	case IKEV2_N_REDIRECT_SUPPORTED:
		return ("REDIRECT_SUPPORTED");
	case IKEV2_N_REDIRECT:
		return ("REDIRECT");
	case IKEV2_N_REDIRECTED_FROM:
		return ("REDIRECTED_FROM");
	case IKEV2_N_TICKET_LT_OPAQUE:
		return ("TICKET_LT_OPAQUE");
	case IKEV2_N_TICKET_REQUEST:
		return ("TICKET_REQUEST");
	case IKEV2_N_TICKET_ACK:
		return ("TICKET_ACK");
	case IKEV2_N_TICKET_NACK:
		return ("TICKET_NACK");
	case IKEV2_N_TICKET_OPAQUE:
		return ("TICKET_OPAQUE");
	case IKEV2_N_LINK_ID:
		return ("LINK_ID");
	case IKEV2_N_USE_WESP_MODE:
		return ("USE_WESP_MODE");
	case IKEV2_N_ROHC_SUPPORTED:
		return ("ROHC_SUPPORTED");
	case IKEV2_N_EAP_ONLY_AUTHENTICATION:
		return ("EAP_ONLY_AUTHENTICATION");
	case IKEV2_N_CHILDLESS_IKEV2_SUPPORTED:
		return ("CHILDLESS_IKEV2_SUPPORTED");
	case IKEV2_N_QUICK_CRASH_DETECTION:
		return ("QUICK_CRASH_DETECTION");
	case IKEV2_N_IKEV2_MESSAGE_ID_SYNC_SUPPORTED:
		return ("IKEV2_MESSAGE_ID_SYNC_SUPPORTED");
	case IKEV2_N_IPSEC_REPLAY_CTR_SYNC_SUPPORTED:
		return ("IPSEC_REPLAY_CTR_SYNC_SUPPORTED");
	case IKEV2_N_IKEV2_MESSAGE_ID_SYNC:
		return ("IKEV2_MESSAGE_ID_SYNC");
	case IKEV2_N_IPSEC_REPLAY_CTR_SYNC:
		return ("IPSEC_REPLAY_CTR_SYNC");
	case IKEV2_N_SECURE_PASSWORD_METHODS:
		return ("SECURE_PASSWORD_METHODS");
	case IKEV2_N_PSK_PERSIST:
		return ("PSK_PERSIST");
	case IKEV2_N_PSK_CONFIRM:
		return ("PSK_CONFIRM");
	case IKEV2_N_ERX_SUPPORTED:
		return ("ERX_SUPPORTED");
	case IKEV2_N_IFOM_CAPABILITY:
		return ("IFOM_CAPABILITY");
	}
	(void) snprintf(buf, buflen, "%hu", (uint16_t)id);
	return (buf);
}

const char *
ikev2_id_type_str(ikev2_id_type_t id, char *buf, size_t buflen)
{
	switch (id) {
	STR(IKEV2_ID_IPV4_ADDR);
	STR(IKEV2_ID_FQDN);
	STR(IKEV2_ID_RFC822_ADDR);
	STR(IKEV2_ID_IPV6_ADDR);
	STR(IKEV2_ID_DER_ASN1_DN);
	STR(IKEV2_ID_DER_ASN1_GN);
	STR(IKEV2_ID_KEY_ID);
	STR(IKEV2_ID_FC_NAME);
	}
	(void) snprintf(buf, buflen, "%hhu", (uint8_t)id);
	return (buf);
}
