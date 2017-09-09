/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */

/*
 * Copyright 2014 Jason King.
 */

#ifndef _IKEV1_H
#define	_IKEV1_H

#include <sys/types.h>
#include "ike.h"

#ifdef __cplusplus
extern "C" {
#endif

#define	IKEV1_MAJOR_VERSION	1
#define	IKEV1_MINOR_VERSION	0
#define	IKEV1_VERSION		0x10

typedef struct ike_header ikev1_header_t;

enum ikev1_exch {
	IKEV1_EXCH_BASE			= 1,
	IKEV1_EXCH_IDPROT		= 2,
	IKEV1_EXCH_AUTH_ONLY		= 3,
	IKEV1_EXCH_AGGRESSIVE		= 4,
	IKEV1_EXCH_INFORMATIONAL	= 5,
};
#define	IKEV1_VALID_EXCH(exch) \
	(((exch) >= IKEV1_EXCH_BASE) && (exch) <= ((IKEV1_EXCH_INFORMATIONAL)))
typedef enum ikev1_exch ikev1_exch_t;

#define	IKEV1_FLAG_ENCR		(1 << 0)
#define	IKEV1_FLAG_COMMIT	(1 << 1)
#define	IKEV1_FLAG_AUTH_ONLY	(1 << 2)
#define	IKEV1_FLAGS \
	(IKEV1_FLAG_ENCR|IKEV1_FLAG_COMMIT|IKEV1_FLAG_AUTH_ONLY)

typedef struct ike_payload ikev1_payload_t;

enum ikev1_pay_type {
	IKEV1_PAYLOAD_SA	= 1,
	IKEV1_PAYLOAD_PROP	= 2,
	IKEV1_PAYLOAD_XFORM	= 3,
	IKEV1_PAYLOAD_KE	= 4,
	IKEV1_PAYLOAD_ID	= 5,
	IKEV1_PAYLOAD_CERT	= 6,
	IKEV1_PAYLOAD_CREQ	= 7,
	IKEV1_PAYLOAD_HASH	= 8,
	IKEV1_PAYLOAD_SIG	= 9,
	IKEV1_PAYLOAD_NONCE	= 10,
	IKEV1_PAYLOAD_NOTIFY	= 11,
	IKEV1_PAYLOAD_DELETE	= 12,
	IKEV1_PAYLOAD_VENDOR	= 13,
};
typedef enum ikev1_pay_type ikev1_pay_t;
#define	IKEV1_VALID_PAYLOAD(p) \
	(((p) >= IKEV1_PAYLOAD_SA) && ((p) <= IKEV1_PAYLOAD_VENDOR))

#define	IKEV1_SIT_IDENTITY_ONLY	(0x01)
#define	IKEV1_SIT_SECRECY	(0x02)
#define	IKEV1_SIT_INTEGRITY	(0x04)

typedef enum ikev1_spi_proto_e {
	IKEV1_SPI_PROTO_ISAKMP		= 1,
	IKEV1_SPI_PROTO_IPSEC_AH	= 2,
	IKEV1_SPI_PROTO_IPSEC_ESP	= 3,
	IKEV1_SPI_PROTO_IPCOMP		= 4
} ikev1_spi_proto_t;

typedef struct ike_prop ikev1_prop_t;
#define	IKEV1_PROP_LAST	0
#define	IKEV1_PROP_MORE	2

typedef struct ike_xform ikev1_xform_t;
#define	IKEV1_XFORM_LAST	0
#define	IKEV1_XFORM_MORE	3

enum ikev1_xf_type {
	IKEV1_XF_ENCR		= 1,
	IKEV1_XF_HASH		= 2,
	IKEV1_XF_AUTH		= 3,
	IKEV1_XF_GROUP_DESC	= 4,
	IKEV1_XF_GROUP_TYPE	= 5,
	IKEV1_XF_GROUP_PRIME	= 6,
	IKEV1_XF_GROUP_GEN_1	= 7,
	IKEV1_XF_GROUP_GEN_2	= 8,
	IKEV1_XF_GROUP_CURVE_A	= 9,
	IKEV1_XF_GROUP_CURVE_B	= 10,
	IKEV1_XF_LIFE_TYPE	= 11,
	IKEV1_XF_LIFE_DUR	= 12,
	IKEV1_XF_PRF		= 13,
	IKEV1_XF_KEYLEN		= 14,
	IKEV1_XF_FIELD_SIZE	= 15,
	IKEV1_XF_GROUP_ORDER	= 16
};
typedef enum ikev1_xf_type ikev1_xf_type_t;

typedef struct ike_xf_attr ikev1_xf_attr_t;
#define	IKEV1_ATTR_TV			IKE_ATTR_TV
#define	IKEV1_ATTR_TLV			IKE_ATTR_TLV
#define	IKEV1_ATTR_GET_TYPE(t)		IKE_GET_TYPE(t)
#define	IKEV1_ATTR_GET_FORMAT(t)	IKE_GET_FORMAT(t)
#define	IKEV1_ATTR_TYPE(f, t)		IKE_ATTR_TYPE(f, t)

struct ikev1_notify {
	uint32_t	n_doi;
	uint8_t		n_protoid;
	uint8_t		n_spisize;
	uint16_t	n_type;
	/* Followed by variable length SPI */
	/* Followed by notification data */
} __packed;
typedef struct ikev1_notify ikev1_notify_t;

enum ikev1_notify_e {
	IKEV1_N_INVALID_PAYLOAD_TYPE	= 1,
	IKEV1_N_DOI_NOT_SUPPORTED	= 2,
	IKEV1_N_SITUATION_NOT_SUPPORTED	= 3,
	IKEV1_N_INVALID_COOKIE		= 4,
	IKEV1_N_INVALID_MAJOR_VERSION	= 5,
	IKEV1_N_INVALID_MINOR_VERSION	= 6,
	IKEV1_N_INVALID_EXCHANGE_TYPE	= 7,
	IKEV1_N_INVALID_FLAGS		= 8,
	IKEV1_N_INVALID_MESSAGE_ID	= 9,
	IKEV1_N_INVALID_PROTOCOL_ID	= 10,
	IKEV1_N_INVALID_SPI		= 11,
	IKEV1_N_INVALID_TRANSFORM_ID	= 12,
	IKEV1_N_ATTRIBUTES_NOT_SUPPORTED = 13,
	IKEV1_N_NO_PROPOSAL_CHOSEN	= 14,
	IKEV1_N_BAD_PROPOSAL_SYNTAX	= 15,
	IKEV1_N_PAYLOAD_MALFORMED	= 16,
	IKEV1_N_INVALID_KEY_INFORMATION	= 17,
	IKEV1_N_INVALID_ID_INFORMATION	= 18,
	IKEV1_N_INVALID_CERT_ENCODING	= 19,
	IKEV1_N_INVALID_CERTIFICATE	= 20,
	IKEV1_N_CERT_TYPE_UNSUPPORTED	= 21,
	IKEV1_N_INVALID_CERT_AUTHORITY	= 22,
	IKEV1_N_INVALID_HASH_INFORMATION = 23,
	IKEV1_N_AUTHENTICATION_FAILED	= 24,
	IKEV1_N_INVALID_SIGNATURE	= 25,
	IKEV1_N_ADDRESS_NOTIFICATION	= 26,
	IKEV1_N_NOTIFY_SA_LIFETIME	= 27,
	IKEV1_N_CERTIFICATE_UNAVAILABLE	= 28,
	IKEV1_N_UNSUPPORTED_EXCHANGE_TYPE = 29,
	IKEV1_N_UNEQUAL_PAYLOAD_LENGTHS	= 30,
};
typedef enum ikev1_notify_e ikev1_notify_type_t;

#ifdef __cplusplus
}
#endif

#endif /* _IKEV1_H */
