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
 * Copyright 2014 Jason King.  All rights reserved.
 */

#ifndef _PKT_IMPL_H
#define	_PKT_IMPL_H

#include "pkt.h"
#include "ike.h"

#ifdef __cplusplus
extern "C" {
#endif

pkt_t *pkt_in_alloc(const buf_t *);
pkt_t *pkt_out_alloc(uint64_t, uint64_t, uint8_t, uint8_t, uint32_t);
void pkt_free(pkt_t *);

void pkt_stack_push(pkt_t *restrict, int, pkt_finish_fn, uintptr_t);

boolean_t pkt_add_payload(pkt_t *, uint8_t, uint8_t);
boolean_t pkt_add_prop(pkt_t *, uint8_t, uint8_t, size_t, uint64_t);
boolean_t pkt_add_xform(pkt_t *, uint8_t, uint8_t);
boolean_t pkt_add_xform_attr_tv(pkt_t *, uint16_t, uint16_t);
boolean_t pkt_add_xform_attr_tlv(pkt_t *restrict, uint16_t,
    const buf_t *restrict);
boolean_t pkt_add_cert(pkt_t *restrict, uint8_t, const buf_t *restrict);

/* append a struct into the raw buffer of pkt */
inline void
append_struct(pkt_t * restrict pkt, const void * restrict st, size_t len)
{
	buf_t *dest = &pkt->buf;
	buf_t src = { .ptr = (uchar_t *)st, .len = len };

	VERIFY(buf_copy(dest, &src, 1) == len);
	buf_advance(dest, len);
}
#define	APPEND_STRUCT(pkt, s) append_struct(pkt, &(s), sizeof (s))

/* append a buf_t to the raw buffer of pkt */
inline void
append_buf(pkt_t * restrict pkt, const buf_t * restrict src)
{
	buf_t *b = &pkt->buf;

	VERIFY(buf_copy(b, src, 1) == src->len);
	buf_advance(b, src->len);
}

#ifdef __cplusplus
}
#endif

#endif /* _PKT_H */
