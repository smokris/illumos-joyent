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

#ifdef __cplusplus
}
#endif

#endif /* _IKEV1_H */
