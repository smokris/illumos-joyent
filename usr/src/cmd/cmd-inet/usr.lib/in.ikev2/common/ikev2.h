/*
 * Copyright (c) 2010-2013 Reyk Floeter <reyk@openbsd.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 * Copyright (c) 2017, Joyent, Inc.
 */

#ifndef _IKEV2_H
#define	_IKEV2_H

#include <inttypes.h>

#ifdef __cplusplus
extern "C" {
#endif

#define	__packed __attribute__((packed))

#define	IKEV2_VERSION		0x20	/* IKE version 2.0 */
#define	IKEV2_KEYPAD		"Key Pad for IKEv2"	/* don't change! */

/*
 * "IKEv2 Parameters" based on the official RFC-based assignments by IANA
 * (http://www.iana.org/assignments/ikev2-parameters/ikev2-parameters.txt)
 */

/*
 * IKEv2 definitions of the IKE header
 */

/* IKEv2 exchange types */
typedef enum ikev2_exch_e {
	IKEV2_EXCH_IKE_SA_INIT		= 34,
	IKEV2_EXCH_IKE_AUTH		= 35,
	IKEV2_EXCH_CREATE_CHILD_SA	= 36,
	IKEV2_EXCH_INFORMATIONAL	= 37,
	IKEV2_EXCH_IKE_SESSION_RESUME	= 38
} ikev2_exch_t;

/* IKEv2 message flags */
#define	IKEV2_FLAG_INITIATOR	0x08	/* Sent by the initiator */
#define	IKEV2_FLAG_VERSION	0x10	/* Supports a higher IKE version */
#define	IKEV2_FLAG_RESPONSE	0x20	/* Message is a response */

/*
 * IKEv2 payloads
 */
struct ikev2_payload {
	uint8_t		pld_nextpayload;	/* Next payload type */
	uint8_t		pld_reserved;		/* Contains the critical bit */
	uint16_t	pld_length;		/* Payload length with header */
} __packed;

#define	IKEV2_CRITICAL_PAYLOAD	0x01	/* First bit in the reserved field */

/* IKEv2 payload types */
typedef enum ikev2_pay_type {
	IKEV2_PAYLOAD_NONE =	0,	/* No payload */
	IKEV2_PAYLOAD_SA =	33,	/* Security Association */
	IKEV2_PAYLOAD_KE =	34,	/* Key Exchange */
	IKEV2_PAYLOAD_IDi =	35,	/* Identification - Initiator */
	IKEV2_PAYLOAD_IDr =	36,	/* Identification - Responder */
	IKEV2_PAYLOAD_CERT =	37,	/* Certificate */
	IKEV2_PAYLOAD_CERTREQ =	38,	/* Certificate Request */
	IKEV2_PAYLOAD_AUTH =	39,	/* Authentication */
	IKEV2_PAYLOAD_NONCE =	40,	/* Nonce */
	IKEV2_PAYLOAD_NOTIFY =	41,	/* Notify */
	IKEV2_PAYLOAD_DELETE =	42,	/* Delete */
	IKEV2_PAYLOAD_VENDOR =	43,	/* Vendor ID */
	IKEV2_PAYLOAD_TSi =	44,	/* Traffic Selector - Initiator */
	IKEV2_PAYLOAD_TSr =	45,	/* Traffic Selector - Responder */
	IKEV2_PAYLOAD_SK =	46,	/* Encrypted */
	IKEV2_PAYLOAD_CP =	47,	/* Configuration Payload */
	IKEV2_PAYLOAD_EAP =	48,	/* Extensible Authentication */
	IKEV2_PAYLOAD_GSPM =	49	/* RFC6467 Generic Secure Password */
} ikev2_pay_type_t;

#define	IKEV2_PAYLOAD_MIN	IKEV2_PAYLOAD_SA
#define	IKEV2_PAYLOAD_MAX	IKEV2_PAYLOAD_GSPM
#define	IKEV2_NUM_PAYLOADS	(IKEV2_PAYLOAD_MAX - IKEV2_PAYLOAD_MIN + 1)
#define	IKEV2_VALID_PAYLOAD(paytype) \
	(((paytype) >= IKEV2_PAYLOAD_MIN) && ((paytype) <= IKEV2_PAYLOAD_MAX))

/*
 * SA payload
 */

struct ikev2_sa_proposal {
	uint8_t		proto_more;		/* Last proposal or more */
	uint8_t		proto_reserved;		/* Must be set to zero */
	uint16_t	proto_length;		/* Proposal length */
	uint8_t		proto_proposalnr;	/* Proposal number */
	uint8_t		proto_protoid;		/* Protocol Id */
	uint8_t		proto_spisize;		/* SPI size */
	uint8_t		proto_transforms;	/* Number of transforms */
	/* Followed by variable-length SPI */
	/* Followed by variable-length transforms */
} __packed;

#define	IKEV2_PROP_LAST	0
#define	IKEV2_PROP_MORE	2

typedef enum ikev2_spi_proto_e {
	IKEV2_PROTO_NONE		= 0,	/* None */
	IKEV2_PROTO_IKE			= 1,	/* IKEv2 */
	IKEV2_PROTO_AH			= 2,	/* AH */
	IKEV2_PROTO_ESP			= 3,	/* ESP */
	IKEV2_PROTO_FC_ESP_HEADER	= 4,	/* RFC4595 */
	IKEV2_PROTO_FC_CT_AUTH		= 5	/* RFC4595 */
} ikev2_spi_proto_t;

struct ikev2_transform {
	uint8_t		xf_more;		/* Last transform or more */
	uint8_t		xf_reserved;		/* Must be set to zero */
	uint16_t	xf_length;		/* Transform length */
	uint8_t		xf_type;		/* Transform type */
	uint8_t		xf_reserved1;		/* Must be set to zero */
	uint16_t	xf_id;		/* Transform Id */
	/* Followed by variable-length transform attributes */
} __packed;

#define	IKEV2_XF_LAST		0
#define	IKEV2_XF_MORE		3

typedef enum ikev2_xf_type_e {
	IKEV2_XF_ENCR	= 1,	/* Encryption */
	IKEV2_XF_PRF	= 2,	/* Pseudo-Random Function */
	IKEV2_XF_AUTH	= 3,	/* Integrity Algorithm */
	IKEV2_XF_DH	= 4,	/* Diffie-Hellman Group */
	IKEV2_XF_ESN	= 5	/* Extended Sequence Numbers */
} ikev2_xf_type_t;
#define	IKEV2_XF_MAX		6

typedef enum ikev2_encr_e {
	IKEV2_ENCR_NONE			= 0,	/* None */
	IKEV2_ENCR_DES_IV64		= 1,	/* RFC1827 */
	IKEV2_ENCR_DES			= 2,	/* RFC2405 */
	IKEV2_ENCR_3DES			= 3,	/* RFC2451 */
	IKEV2_ENCR_RC5			= 4,	/* RFC2451 */
	IKEV2_ENCR_IDEA			= 5,	/* RFC2451 */
	IKEV2_ENCR_CAST			= 6,	/* RFC2451 */
	IKEV2_ENCR_BLOWFISH		= 7,	/* RFC2451 */
	IKEV2_ENCR_3IDEA		= 8,	/* RFC2451 */
	IKEV2_ENCR_DES_IV32		= 9,	/* DESIV32 */
	IKEV2_ENCR_RC4			= 10,	/* RFC2451 */
	IKEV2_ENCR_NULL			= 11,	/* RFC2410 */
	IKEV2_ENCR_AES_CBC		= 12,	/* RFC3602 */
	IKEV2_ENCR_AES_CTR		= 13,	/* RFC3664 */
	IKEV2_ENCR_AES_CCM_8		= 14,	/* RFC5282 */
	IKEV2_ENCR_AES_CCM_12		= 15,	/* RFC5282 */
	IKEV2_ENCR_AES_CCM_16		= 16,	/* RFC5282 */
	IKEV2_ENCR_AES_GCM_8		= 18,	/* RFC5282 */
	IKEV2_ENCR_AES_GCM_12		= 19,	/* RFC5282 */
	IKEV2_ENCR_AES_GCM_16		= 20,	/* RFC5282 */
	IKEV2_ENCR_NULL_AES_GMAC	= 21,	/* RFC4543 */
	IKEV2_ENCR_XTS_AES		= 22,	/* IEEE P1619 */
	IKEV2_ENCR_CAMELLIA_CBC		= 23,	/* RFC5529 */
	IKEV2_ENCR_CAMELLIA_CTR		= 24,	/* RFC5529 */
	IKEV2_ENCR_CAMELLIA_CCM_8	= 25,	/* RFC5529 */
	IKEV2_ENCR_CAMELLIA_CCM_12	= 26,	/* RFC5529 */
	IKEV2_ENCR_CAMELLIA_CCM_16	= 27,	/* RFC5529 */
} ikev2_xf_encr_t;

#define	IKEV2_IPCOMP_OUI		1	/* RFC5996 */
#define	IKEV2_IPCOMP_DEFLATE		2	/* RFC2394 */
#define	IKEV2_IPCOMP_LZS		3	/* RFC2395 */
#define	IKEV2_IPCOMP_LZJH		4	/* RFC3051 */

typedef enum ikev2_prf {
	IKEV2_PRF_HMAC_MD5		= 1,	/* RFC2104 */
	IKEV2_PRF_HMAC_SHA1		= 2,	/* RFC2104 */
	IKEV2_PRF_HMAC_TIGER		= 3,	/* RFC2104 */
	IKEV2_PRF_AES128_XCBC		= 4,	/* RFC3664 */
	IKEV2_PRF_HMAC_SHA2_256		= 5,	/* RFC4868 */
	IKEV2_PRF_HMAC_SHA2_384		= 6,	/* RFC4868 */
	IKEV2_PRF_HMAC_SHA2_512		= 7,	/* RFC4868 */
	IKEV2_PRF_AES128_CMAC		= 8	/* RFC4615 */
} ikev2_prf_t;

typedef enum ikev2_xf_auth_e {
	IKEV2_XF_AUTH_NONE			= 0,	/* No Authentication */
	IKEV2_XF_AUTH_HMAC_MD5_96		= 1,	/* RFC2403 */
	IKEV2_XF_AUTH_HMAC_SHA1_96		= 2,	/* RFC2404 */
	IKEV2_XF_AUTH_DES_MAC			= 3,	/* DES-MAC */
	IKEV2_XF_AUTH_KPDK_MD5			= 4,	/* RFC1826 */
	IKEV2_XF_AUTH_AES_XCBC_96		= 5,	/* RFC3566 */
	IKEV2_XF_AUTH_HMAC_MD5_128		= 6,	/* RFC4595 */
	IKEV2_XF_AUTH_HMAC_SHA1_160		= 7,	/* RFC4595 */
	IKEV2_XF_AUTH_AES_CMAC_96		= 8,	/* RFC4494 */
	IKEV2_XF_AUTH_AES_128_GMAC		= 9,	/* RFC4543 */
	IKEV2_XF_AUTH_AES_192_GMAC		= 10,	/* RFC4543 */
	IKEV2_XF_AUTH_AES_256_GMAC		= 11,	/* RFC4543 */
	IKEV2_XF_AUTH_HMAC_SHA2_256_128 	= 12,	/* RFC4868 */
	IKEV2_XF_AUTH_HMAC_SHA2_384_192 	= 13,	/* RFC4868 */
	IKEV2_XF_AUTH_HMAC_SHA2_512_256 	= 14	/* RFC4868 */
} ikev2_xf_auth_t;

typedef enum ikev2_dh {
	IKEV2_DH_NONE			= 0,	/* No DH */
	IKEV2_DH_MODP_768		= 1,	/* DH Group 1 */
	IKEV2_DH_MODP_1024		= 2,	/* DH Group 2 */
	IKEV2_DH_EC2N_155		= 3,	/* DH Group 3 */
	IKEV2_DH_EC2N_185		= 4,	/* DH Group 3 */
	IKEV2_DH_MODP_1536		= 5,	/* DH Group 5 */
	IKEV2_DH_MODP_2048		= 14,	/* DH Group 14 */
	IKEV2_DH_MODP_3072		= 15,	/* DH Group 15 */
	IKEV2_DH_MODP_4096		= 16,	/* DH Group 16 */
	IKEV2_DH_MODP_6144		= 17,	/* DH Group 17 */
	IKEV2_DH_MODP_8192		= 18,	/* DH Group 18 */
	IKEV2_DH_ECP_256		= 19,	/* DH Group 19 */
	IKEV2_DH_ECP_384		= 20,	/* DH Group 20 */
	IKEV2_DH_ECP_521		= 21,	/* DH Group 21 */
	IKEV2_DH_MODP_1024_160		= 22,	/* DH Group 22 */
	IKEV2_DH_MODP_2048_224		= 23,	/* DH Group 23 */
	IKEV2_DH_MODP_2048_256		= 24,	/* DH Group 24 */
	IKEV2_DH_ECP_192		= 25,	/* DH Group 25 */
	IKEV2_DH_ECP_224		= 26,	/* DH Group 26 */
	IKEV2_DH_BRAINPOOL_P224R1	= 27,	/* DH Group 27 */
	IKEV2_DH_BRAINPOOL_P256R1	= 28,	/* DH Group 28 */
	IKEV2_DH_BRAINPOOL_P384R1	= 29,	/* DH Group 29 */
	IKEV2_DH_BRAINPOOL_P512R1	= 30	/* DH Group 30 */
} ikev2_dh_t;
#define	IKEV2_DH_MAX			31

#define	IKEV2_XFORMESN_NONE		0	/* No ESN */
#define	IKEV2_XFORMESN_ESN		1	/* ESN */

struct ikev2_attribute {
	uint16_t	attr_type;	/* Attribute type */
	uint16_t	attr_length;	/* Attribute length or value */
	/* Followed by variable length (TLV) */
} __packed;

#define	IKEV2_ATTRAF_TLV		0x0000	/* Type-Length-Value format */
#define	IKEV2_ATTRAF_TV			0x8000	/* Type-Value format */

typedef enum ikev2_xf_attr_type {
	IKEV2_XF_ATTR_KEYLEN	= 14		/* Key length */
} ikev2_xf_attr_type_t;

/*
 * KE Payload
 */
struct ikev2_ke {
	uint16_t	 kex_dhgroup;		/* DH Group # */
	uint16_t	 kex_reserved;		/* Reserved */
} __packed;

/*
 * N payload
 */
struct ikev2_notify {
	uint8_t		n_protoid;		/* Protocol Id */
	uint8_t		n_spisize;		/* SPI size */
	uint16_t	n_type;		/* Notify message type */
	/* Followed by variable length SPI */
	/* Followed by variable length notification data */
} __packed;

/*
 * NOTIFY types.  We don't support all of these, however for observability
 * and debugging purposes, we try to maintain a list of all known values.
 */
typedef enum ikev2_notify_type {
	IKEV2_N_UNSUPPORTED_CRITICAL_PAYLOAD	= 1,		/* RFC4306 */
	IKEV2_N_INVALID_IKE_SPI			= 4,		/* RFC4306 */
	IKEV2_N_INVALID_MAJOR_VERSION		= 5,		/* RFC4306 */
	IKEV2_N_INVALID_SYNTAX			= 7,		/* RFC4306 */
	IKEV2_N_INVALID_MESSAGE_ID		= 9,		/* RFC4306 */
	IKEV2_N_INVALID_SPI			= 11,		/* RFC4306 */
	IKEV2_N_NO_PROPOSAL_CHOSEN		= 14,		/* RFC4306 */
	IKEV2_N_INVALID_KE_PAYLOAD		= 17,		/* RFC4306 */
	IKEV2_N_AUTHENTICATION_FAILED		= 24,		/* RFC4306 */
	IKEV2_N_SINGLE_PAIR_REQUIRED		= 34,		/* RFC4306 */
	IKEV2_N_NO_ADDITIONAL_SAS		= 35,		/* RFC4306 */
	IKEV2_N_INTERNAL_ADDRESS_FAILURE	= 36,		/* RFC4306 */
	IKEV2_N_FAILED_CP_REQUIRED		= 37,		/* RFC4306 */
	IKEV2_N_TS_UNACCEPTABLE			= 38,		/* RFC4306 */
	IKEV2_N_INVALID_SELECTORS		= 39,		/* RFC4306 */
	IKEV2_N_UNACCEPTABLE_ADDRESSES		= 40,		/* RFC4555 */
	IKEV2_N_UNEXPECTED_NAT_DETECTED		= 41,		/* RFC4555 */
	IKEV2_N_USE_ASSIGNED_HoA		= 42,		/* RFC5026 */
	IKEV2_N_TEMPORARY_FAILURE		= 43,		/* RFC5996 */
	IKEV2_N_CHILD_SA_NOT_FOUND		= 44,		/* RFC5996 */
	IKEV2_N_INITIAL_CONTACT			= 16384,	/* RFC4306 */
	IKEV2_N_SET_WINDOW_SIZE			= 16385,	/* RFC4306 */
	IKEV2_N_ADDITIONAL_TS_POSSIBLE		= 16386,	/* RFC4306 */
	IKEV2_N_IPCOMP_SUPPORTED		= 16387,	/* RFC4306 */
	IKEV2_N_NAT_DETECTION_SOURCE_IP		= 16388,	/* RFC4306 */
	IKEV2_N_NAT_DETECTION_DESTINATION_IP	= 16389,	/* RFC4306 */
	IKEV2_N_COOKIE				= 16390,	/* RFC4306 */
	IKEV2_N_USE_TRANSPORT_MODE		= 16391,	/* RFC4306 */
	IKEV2_N_HTTP_CERT_LOOKUP_SUPPORTED	= 16392,	/* RFC4306 */
	IKEV2_N_REKEY_SA			= 16393,	/* RFC4306 */
	IKEV2_N_ESP_TFC_PADDING_NOT_SUPPORTED	= 16394,	/* RFC4306 */
	IKEV2_N_NON_FIRST_FRAGMENTS_ALSO	= 16395,	/* RFC4306 */
	IKEV2_N_MOBIKE_SUPPORTED		= 16396,	/* RFC4555 */
	IKEV2_N_ADDITIONAL_IP4_ADDRESS		= 16397,	/* RFC4555 */
	IKEV2_N_ADDITIONAL_IP6_ADDRESS		= 16398,	/* RFC4555 */
	IKEV2_N_NO_ADDITIONAL_ADDRESSES		= 16399,	/* RFC4555 */
	IKEV2_N_UPDATE_SA_ADDRESSES		= 16400,	/* RFC4555 */
	IKEV2_N_COOKIE2				= 16401,	/* RFC4555 */
	IKEV2_N_NO_NATS_ALLOWED			= 16402,	/* RFC4555 */
	IKEV2_N_AUTH_LIFETIME			= 16403,	/* RFC4478 */
	IKEV2_N_MULTIPLE_AUTH_SUPPORTED		= 16404,	/* RFC4739 */
	IKEV2_N_ANOTHER_AUTH_FOLLOWS		= 16405,	/* RFC4739 */
	IKEV2_N_REDIRECT_SUPPORTED		= 16406,	/* RFC5685 */
	IKEV2_N_REDIRECT			= 16407,	/* RFC5685 */
	IKEV2_N_REDIRECTED_FROM			= 16408,	/* RFC5685 */
	IKEV2_N_TICKET_LT_OPAQUE		= 16409,	/* RFC5723 */
	IKEV2_N_TICKET_REQUEST			= 16410,	/* RFC5723 */
	IKEV2_N_TICKET_ACK			= 16411,	/* RFC5723 */
	IKEV2_N_TICKET_NACK			= 16412,	/* RFC5723 */
	IKEV2_N_TICKET_OPAQUE			= 16413,	/* RFC5723 */
	IKEV2_N_LINK_ID				= 16414,	/* RFC5739 */
	IKEV2_N_USE_WESP_MODE			= 16415,
			/* RFC-ietf-ipsecme-traffic-visibility-12.txt */
	IKEV2_N_ROHC_SUPPORTED			= 16416,
			/* RFC-ietf-rohc-ikev2-extensions-hcoipsec-12.txt */
	IKEV2_N_EAP_ONLY_AUTHENTICATION		= 16417,	/* RFC5998 */
	IKEV2_N_CHILDLESS_IKEV2_SUPPORTED	= 16418,	/* RFC6023 */
	IKEV2_N_QUICK_CRASH_DETECTION		= 16419,	/* RFC6290 */
	IKEV2_N_IKEV2_MESSAGE_ID_SYNC_SUPPORTED	= 16420,	/* RFC6311 */
	IKEV2_N_IPSEC_REPLAY_CTR_SYNC_SUPPORTED	= 16421,	/* RFC6311 */
	IKEV2_N_IKEV2_MESSAGE_ID_SYNC		= 16422,	/* RFC6311 */
	IKEV2_N_IPSEC_REPLAY_CTR_SYNC		= 16423,	/* RFC6311 */
	IKEV2_N_SECURE_PASSWORD_METHODS		= 16424,	/* RFC6467 */
	IKEV2_N_PSK_PERSIST			= 16425,	/* RFC6631 */
	IKEV2_N_PSK_CONFIRM			= 16426,	/* RFC6631 */
	IKEV2_N_ERX_SUPPORTED			= 16427,	/* RFC6867 */
	IKEV2_N_IFOM_CAPABILITY			= 16428		/* OA3GPP */
} ikev2_notify_type_t;

/*
 * DELETE payload
 */
struct ikev2_delete {
	uint8_t 	del_protoid;		/* Protocol Id */
	uint8_t		del_spisize;		/* SPI size */
	uint16_t	del_nspi;		/* Number of SPIs */
	/* Followed by variable length SPIs */
} __packed;

/*
 * ID payload
 */
struct ikev2_id {
	uint8_t	 id_type;		/* Id type */
	uint8_t	 id_reserved[3];	/* Reserved */
	/* Followed by the identification data */
} __packed;

typedef enum ikev2_id_type {
	IKEV2_ID_IPV4_ADDR	= 1,	/* RFC7296 */
	IKEV2_ID_FQDN		= 2,	/* RFC7296 */
	IKEV2_ID_RFC822_ADDR	= 3,	/* RFC7296 */
	IKEV2_ID_IPV6_ADDR	= 5,	/* RFC7296 */
	IKEV2_ID_DER_ASN1_DN	= 9,	/* RFC7296 */
	IKEV2_ID_DER_ASN1_GN	= 10,	/* RFC7296 */
	IKEV2_ID_KEY_ID		= 11,	/* RFC7296 */
	IKEV2_ID_FC_NAME	= 12	/* RFC4595 */
} ikev2_id_type_t;

/*
 * CERT/CERTREQ payloads
 */
typedef enum ikev2_cert {
	IKEV2_CERT_NONE =			0,	/* None */
	IKEV2_CERT_X509_PKCS7 =			1,	/* RFC4306 */
	IKEV2_CERT_PGP =			2,	/* RFC4306 */
	IKEV2_CERT_DNS_SIGNED_KEY =		3,	/* RFC4306 */
	IKEV2_CERT_X509_CERT =			4,	/* RFC4306 */
	IKEV2_CERT_KERBEROS_TOKEN =		6,	/* RFC4306 */
	IKEV2_CERT_CRL =			7,	/* RFC4306 */
	IKEV2_CERT_ARL =			8,	/* RFC4306 */
	IKEV2_CERT_SPKI =			9,	/* RFC4306 */
	IKEV2_CERT_X509_ATTR =			10,	/* RFC4306 */
	IKEV2_CERT_RSA_KEY =			11,	/* RFC4306 */
	IKEV2_CERT_HASHURL_X509 =		12,	/* RFC4306 */
	IKEV2_CERT_HASHURL_X509_BUNDLE =	13,	/* RFC4306 */
	IKEV2_CERT_OCSP =			14	/* RFC4806 */
} ikev2_cert_t;

/*
 * TSi/TSr payloads
 */
struct ikev2_tsp {
	uint8_t	tsp_count;		/* Number of TSs */
	uint8_t	tsp_reserved[3];	/* Reserved */
	/* Followed by the traffic selectors */
} __packed;

struct ikev2_ts {
	uint8_t		ts_type;		/* TS type */
	uint8_t		ts_protoid;		/* Protocol Id */
	uint16_t	ts_length;		/* Length */
	uint16_t	ts_startport;		/* Start port */
	uint16_t	ts_endport;		/* End port */
} __packed;

typedef enum ikev2_ts_type {
	IKEV2_TS_IPV4_ADDR_RANGE =	7,	/* RFC4306 */
	IKEV2_TS_IPV6_ADDR_RANGE =	8,	/* RFC4306 */
	IKEV2_TS_FC_ADDR_RANGE =	9	/* RFC4595 */
} ikev2_ts_type_t;

/*
 * AUTH payload
 */
struct ikev2_auth {
	uint8_t	auth_method;		/* Signature type */
	uint8_t	auth_reserved[3];	/* Reserved */
	/* Followed by the signature */
} __packed;

typedef enum ikev2_auth_type {
	IKEV2_AUTH_NONE =		0,	/* None */
	IKEV2_AUTH_RSA_SIG =		1,	/* RFC4306 */
	IKEV2_AUTH_SHARED_KEY_MIC =	2,	/* RFC4306 */
	IKEV2_AUTH_DSS_SIG =		3,	/* RFC4306 */
	IKEV2_AUTH_ECDSA_256 =		9,	/* RFC4754 */
	IKEV2_AUTH_ECDSA_384 =		10,	/* RFC4754 */
	IKEV2_AUTH_ECDSA_512 =		11,	/* RFC4754 */
	IKEV2_AUTH_GSPM =		12	/* RFC6467 */
} ikev2_auth_type_t;

/*
 * CP payload
 */
struct ikev2_cp {
	uint8_t	cp_type;
	uint8_t	cp_reserved[3];
	/* Followed by the attributes */
} __packed;

typedef enum ikev2_cfg_type {
	IKEV2_CP_REQUEST	= 1,	/* CFG-Request */
	IKEV2_CP_REPLY		= 2,	/* CFG-Reply */
	IKEV2_CP_SET		= 3,	/* CFG-SET */
	IKEV2_CP_ACK		= 4	/* CFG-ACK */
} ikev2_cfg_type_t;

struct ikev2_cfg {
	uint16_t	cfg_type;	/* first bit must be set to zero */
	uint16_t	cfg_length;
	/* Followed by variable-length data */
} __packed;

typedef enum ikev2_cfg_attr_type {
	IKEV2_CFG_INTERNAL_IP4_ADDRESS		= 1,	/* RFC5996 */
	IKEV2_CFG_INTERNAL_IP4_NETMASK		= 2,	/* RFC5996 */
	IKEV2_CFG_INTERNAL_IP4_DNS		= 3,	/* RFC5996 */
	IKEV2_CFG_INTERNAL_IP4_NBNS		= 4,	/* RFC5996 */
	IKEV2_CFG_INTERNAL_ADDRESS_EXPIRY	= 5,	/* RFC4306 */
	IKEV2_CFG_INTERNAL_IP4_DHCP		= 6,	/* RFC5996 */
	IKEV2_CFG_APPLICATION_VERSION		= 7,	/* RFC5996 */
	IKEV2_CFG_INTERNAL_IP6_ADDRESS		= 8,	/* RFC5996 */
	IKEV2_CFG_INTERNAL_IP6_DNS		= 10,	/* RFC5996 */
	IKEV2_CFG_INTERNAL_IP6_NBNS		= 11,	/* RFC4306 */
	IKEV2_CFG_INTERNAL_IP6_DHCP		= 12,	/* RFC5996 */
	IKEV2_CFG_INTERNAL_IP4_SUBNET		= 13,	/* RFC5996 */
	IKEV2_CFG_SUPPORTED_ATTRIBUTES		= 14,	/* RFC5996 */
	IKEV2_CFG_INTERNAL_IP6_SUBNET		= 15,	/* RFC5996 */
	IKEV2_CFG_MIP6_HOME_PREFIX		= 16,	/* RFC5026 */
	IKEV2_CFG_INTERNAL_IP6_LINK		= 17,	/* RFC5739 */
	IKEV2_CFG_INTERNAL_IP6_PREFIX		= 18,	/* RFC5739 */
	IKEV2_CFG_HOME_AGENT_ADDRESS		= 19,
/* BEGIN CSTYLED */
		/* http://www.3gpp.org/ftp/Specs/html-info/24302.htm */
/* END CSTYLED */
	IKEV2_CFG_INTERNAL_IP4_SERVER		= 23456, /* MS-IKEE */
	IKEV2_CFG_INTERNAL_IP6_SERVER		= 23457  /* MS-IKEE */
} ikev2_cfg_attr_type_t;

/* The vendor types + versions we recognize */
typedef enum vendor {
	VENDOR_UNKNOWN			= 0,
	VENDOR_ILLUMOS_1			= 1
} vendor_t;

typedef struct ikev2_payload ikev2_payload_t;
typedef struct ikev2_sa_proposal ikev2_sa_proposal_t;
typedef struct ikev2_transform ikev2_transform_t;
typedef struct ikev2_attribute ikev2_attribute_t;
typedef struct ikev2_ke ikev2_ke_t;
typedef struct ikev2_notify ikev2_notify_t;
typedef struct ikev2_delete ikev2_delete_t;
typedef struct ikev2_id ikev2_id_t;
typedef struct ikev2_tsp ikev2_tsp_t;
typedef struct ikev2_ts ikev2_ts_t;
typedef struct ikev2_auth ikev2_auth_t;
typedef struct ikev2_cp ikev2_cp_t;
typedef struct ikev2_cfg ikev2_cfg_t;

#ifdef __cplusplus
}
#endif

#endif /* _IKEV2_H */
