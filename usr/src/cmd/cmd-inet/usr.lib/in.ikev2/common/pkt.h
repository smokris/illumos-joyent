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

#ifdef _PKT_H
#define	_PKT_H

#include <sys/types.h>
#include "ike.h"
#include "ikev2.h"
#include "buf.h"

#ifdef __cplusplus
extern "C" {
#endif

#define IKEV2_STD_PAYLOADS      16
#define IKEV2_PAYLOAD_START     33

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

struct pkt_stack {
	pkt_finish_fn	stk_finish;
	buf_t		stk_buf;
	size_t		stk_count;
	int		stk_depth;
};
#define	PKT_STACK_DEPTH	6

struct pkt {
	struct ikev2_sa	*sa;	/* NOT refheld */

			/*
			 * Pointer to payload of a given type.  For
			 * payloads that can appear multiple times,
			 * this is the first payload of that type.
			 */
	uchar_t		*payloads[IKEV2_STD_PAYLOADS];

			/* Copy of ISAKMP header in local byte order */
	ike_header_t	header;

			/* Raw packet data */
	uint64_t	raw[SADB_8TO64(MAX_PACKET_SIZE)];

	size_t		reserved;	/* Amt reserved for encr & auth */
	buf_t		buf;		/* Ptr to valid range of raw */
	uint_t		n_xmit;		/* # of transmission attempts */

	struct pkt_stack	stack[PKT_STACK_DEPTH];
	uint_t			stksize;
};

#define	IKEV2_PAYLOAD_PTR(pkt, num) \
	((pkt)->payloads[(num) - IKEV2_PAYLOAD_START])

#define	INBOUND_LOCAL_SPI(hdr) \
	(((hdr)->flags == IKEV2_FLAG_INITIATOR) ? \
	    (hdr)->responder_spi : (hdr)->initiator_spi)
#define	INBOUND_REMOTE_SPI(hdr) \
	(((hdr)->flags == IKEV2_FLAG_INITIATOR) ? \
	    (hdr)->initiator_spi : (hdr)->reasponder_spi)

void pkt_init(void);
void pkt_fini(void);

boolean_t ikev2_add_auth(pkt_t *restrict, int /* type */, const buf_t *restrict /* data */);
boolean_t ikev2_add_nonce(pkt_t *restrict, const buf_t *restrict /* data */);
boolean_t ikev2_add_notify(pkt_t *restrict, int /* proto */, int /* spi size */, int /* type */, uint32_t /* spi */, const buf_t *restrict /* data */);

boolean_t ikev2_add_delete(pkt_t *, int /* spis size */, size_t /* num spi */, ...);
boolean_t ikev2_add_delete_spi(pkt_t *, uint64_t);

boolean_t ikev2_add_vendor(pkt_t *restrict, const buf_t *restrict);

boolean_t ikev2_add_ts_i(pkt_t *);
boolean_t ikev2_add_ts_r(pkt_t *);
boolean_t ikev2_add_ts(pkt_t *restrict, int /* type */, int /* proto */, const sockaddr_u_t *restrict /* start */, const sockaddr_u_t *restrict /* end */);

boolean_t ikev2_add_sk(pkt_t *);

boolean_t ikev2_add_config(pkt_t *restrict, int /* type */);
boolean_t ikev2_add_config_attr(pkt_t *restrict, int /* type */, ... /*val */);

boolean_t ikev2_add_eap(pkt_t *restrict, const buf_t *restrict);

#ifdef __cplusplus
}
#endif

#endif /* _PKT_H */
