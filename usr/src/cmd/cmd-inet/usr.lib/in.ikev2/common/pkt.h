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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright 2014 Jason King.  All rights reserved.
 */

#ifndef _PKT_H
#define	_PKT_H

#include <sys/types.h>
#include "ike.h"
#include "ikev2.h"
#include "buf.h"

#ifdef __cplusplus
extern "C" {
#endif

struct ikev2_sa;
struct pkt;
struct pkt_stack;

#ifndef PKT_T
typedef struct pkt		pkt_t;
typedef struct pkt_stack	pkt_stack_t;
#endif /* PKT_T */

#ifndef PKT_FINISH_FN
typedef void (*pkt_finish_fn)(struct pkt *restrict, buf_t *restrict, uintptr_t,
    size_t);
#endif

typedef enum pkt_stack_item {
	PSI_PACKET,
	PSI_SK,
	PSI_SA,
	PSI_PAYLOAD,
	PSI_PROP,
	PSI_XFORM,
	PSI_XFORM_ATTR,
} pkt_stack_item_t;

struct pkt_stack {
	pkt_finish_fn	stk_finish;
	buf_t		stk_buf;
	size_t		stk_count;
	int		stk_depth;
};
#define	PKT_STACK_DEPTH	6

#define	MAX_PACKET_SIZE	(8192)	/* largest datagram we accept */
struct pkt {
	struct ikev2_sa	*sa;	/* NOT refheld */

			/*
			 * Pointer to payload of a given type.  For
			 * payloads that can appear multiple times,
			 * this is the first payload of that type.
			 */
	uchar_t		*payloads[IKE_NUM_PAYLOADS];

			/* Copy of ISAKMP header in local byte order */
	ike_header_t	header;

			/* Raw packet data */
	uint64_t	raw[SADB_8TO64(MAX_PACKET_SIZE)];

	size_t		reserved;	/* Amt reserved for encr & auth */
	buf_t		buf;		/* Ptr to valid range of raw */
	uint_t		n_xmit;		/* # of transmission attempts */

	struct pkt_stack	stack[PKT_STACK_DEPTH];
	uint_t			stksize;

	uint32_t	msgid;
	size_t		length;
};

#define	PKT_PAY_START(pkt) ((uchar_t *)&(pkt)->raw + sizeof (ike_header_t))
#define	PKT_REMAINING(pkt) ((pkt)->buf.len)

void pkt_hdr_ntoh(ike_header_t *restrict, const ike_header_t *restrict);
void pkt_hdr_hton(ike_header_t *restrict, const ike_header_t *restrict);

void pkt_init(void);
void pkt_fini(void);

typedef enum pkt_walk_ret {
	PKT_WALK_ERROR	= -1,
	PKT_WALK_OK	= 0,
	PKT_WALK_STOP	= 1
} pkt_walk_ret_t;

/* payload type, payload, cookie */
typedef pkt_walk_ret_t (*pkt_walk_fn_t)(uint8_t, buf_t *restrict,
    void *restrict);
pkt_walk_ret_t pkt_payload_walk(buf_t *restrict, pkt_walk_fn_t, void *restrict);
void pkt_free(pkt_t *);

#ifdef __cplusplus
}
#endif

#endif /* _PKT_H */
