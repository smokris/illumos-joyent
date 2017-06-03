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

/*
 * These are largely the same between v1 & v2
 */

#define	IKEV1_MAJOR_VERSION	1
#define	IKEV1_MINOR_VERSION	0
#define	IKEV1_VERSION		0x10

#define	IKEV2_MAJOR_VERSION	2
#define	IKEV2_MINOR_VERSION	0
#define	IKEV2_VERSION		0x20

#define	ISAKMP_HEADER_LENGTH	28

#define	ISAKMP_GET_MAJORV(v)	(((v) & 0xf0) >> 4)
#define	ISAKMP_GET_MINORV(v)	((v) & 0x0f)
#define	ISAKMP_VERSION(_maj, _min) (((_maj) & 0xf0 << 4) | (_min) & 0x0f)

struct ike_header {
	uint64_t	initiator_spi;
	uint64_t	responder_spi;
	uint8_t		next_payload;
	uint8_t		version;
	uint8_t		exch_type;
	uint8_t		flags;
	uint32_t	msgid;
	uint32_t	length;
} __attribute__((packed));

typedef struct ike_header ike_header_t;

#ifdef __cplusplus
}
#endif

#endif /* _IKE_H */
