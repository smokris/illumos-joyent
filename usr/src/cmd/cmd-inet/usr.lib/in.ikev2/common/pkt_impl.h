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

typedef enum pkt_walk_ret {
	PKT_WALK_ERROR	= -1,
	PKT_WALK_OK = 0,
	PKT_WALK_STOP = 1
} pkt_walk_ret_t;

typedef pkt_walk_ret_t (*pkt_walk_fn_t)(uint8_t, uint8_t, uchar_t *restrict,
    size_t, void *restrict);
pkt_walk_ret_t pkt_payload_walk(uchar_t *restrict, size_t, pkt_walk_fn_t,
    void *restrict);

pkt_t *pkt_in_alloc(uchar_t *, size_t);
pkt_t *pkt_out_alloc(uint64_t, uint64_t, uint8_t, uint8_t, uint32_t);
void pkt_free(pkt_t *);

void pkt_stack_push(pkt_t *restrict, pkt_stack_item_t, pkt_finish_fn,
    uintptr_t);

boolean_t pkt_add_payload(pkt_t *, uint8_t, uint8_t);
boolean_t pkt_add_prop(pkt_t *, uint8_t, uint8_t, size_t, uint64_t);
boolean_t pkt_add_xform(pkt_t *, uint8_t, uint8_t);
boolean_t pkt_add_xform_attr_tv(pkt_t *, uint16_t, uint16_t);
boolean_t pkt_add_xform_attr_tlv(pkt_t *restrict, uint16_t,
    const uchar_t *restrict, size_t);
boolean_t pkt_add_cert(pkt_t *restrict, uint8_t, const uchar_t *restrict,
    size_t);

#ifdef __cplusplus
}
#endif

#endif /* _PKT_IMPL_H */
