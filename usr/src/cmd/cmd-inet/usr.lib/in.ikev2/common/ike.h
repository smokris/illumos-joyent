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

#ifndef _IKE_H
#define	_IKE_H

#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Stuff that is the same between IKEv1 and IKEv2 */

#define	IKE_GET_MAJORV(v)	(((v) & 0xf0) >> 4)
#define	IKE_GET_MINORV(v)	((v) & 0x0f)
#define	IKE_VERSION(_maj, _min) (((_maj) & 0xf0 << 4) | (_min) & 0x0f)

#ifndef __packed
#define	__packed __attribute__((packed))
#endif

struct ike_header {
	uint64_t	initiator_spi;
	uint64_t	responder_spi;
	uint8_t		next_payload;
	uint8_t		version;
	uint8_t		exch_type;
	uint8_t		flags;
	uint32_t	msgid;
	uint32_t	length;
} __packed;
typedef struct ike_header ike_header_t;
#define	IKE_HEADER_LEN	(sizeof (ike_header_t))

struct ike_payload {
	uint8_t		pay_next;
	uint8_t		pay_reserved;
	uint16_t	pay_length;
} __packed;
typedef struct ike_payload ike_payload_t;

#define	IKE_PAYLOAD_NONE	0

/* Of the IKEv1 and IKEv2 payloads we recognize, this is MAX of the two */
#define	IKE_NUM_PAYLOADS 17

struct ike_prop {
	uint8_t		prop_more;
	uint8_t		prop_resv;
	uint16_t	prop_len;
	uint8_t		prop_num;
	uint8_t		prop_proto;
	uint8_t		prop_spilen;
	uint8_t		prop_numxform;
} __packed;
typedef struct ike_prop ike_prop_t;
#define	IKE_PROP_NONE	(0)
#define	IKE_PROP_MORE	(2)

struct ike_xform {
	uint8_t		xf_more;
	uint8_t		xf_resv;
	uint16_t	xf_len;
	uint8_t		xf_type;
	uint8_t		xf_resv2;
	uint16_t	xf_id;
} __packed;
typedef struct ike_xform ike_xform_t;
#define	IKE_XFORM_NONE	(0)
#define	IKE_XFORM_MORE	(3)

#define	IKE_ATTR_MAXTYPE	(0x7fff)
#define	IKE_ATTR_MAXLEN		(UINT16_MAX - sizeof (ike_xf_attr_t))
#define	IKE_ATTR_MAXVAL		(UINT16_MAX)
struct ike_xf_attr {
	uint16_t	attr_type;
	uint16_t	attr_len;
};
typedef struct ike_xf_attr ike_xf_attr_t;
#define	IKE_ATTR_TV			(1)
#define	IKE_ATTR_TLV			(0)
#define	IKE_ATTR_GET_TYPE(type)		((type) & 0x7fff)
#define	IKE_ATTR_GET_FORMAT(type)	((type) & 0x8000) >> 15)
#define	IKE_ATTR_TYPE(fmt, type) \
	(((fmt) << 15) | ((type) & 0x7fff))

struct ike_ke {
	uint16_t	ke_group;
	uint16_t	ke_resv;
};
typedef struct ike_ke ike_ke_t;

#ifdef __cplusplus
}
#endif

#endif /* _IKE_H */
