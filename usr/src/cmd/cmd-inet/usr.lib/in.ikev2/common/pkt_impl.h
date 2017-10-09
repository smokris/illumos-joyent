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

struct bunyan_logger;

typedef boolean_t (*pkt_walk_fn_t)(uint8_t, uint8_t, uint8_t *restrict,
    size_t, void *restrict);
boolean_t pkt_payload_walk(uint8_t *restrict, size_t, pkt_walk_fn_t,
    uint8_t, void *restrict, struct bunyan_logger *restrict);

boolean_t pkt_count_payloads(uint8_t *restrict, size_t, uint8_t, size_t *,
    size_t *, struct bunyan_logger *restrict);
boolean_t pkt_index_payloads(pkt_t *, uint8_t *, size_t, uint8_t,
    struct bunyan_logger *restrict);
boolean_t pkt_add_index(pkt_t *, uint8_t, uint8_t *, uint16_t);
boolean_t pkt_add_nindex(pkt_t *, uint64_t, uint32_t, uint8_t, uint16_t,
    uint8_t *, size_t);
pkt_payload_t *pkt_payload(pkt_t *, uint16_t);
pkt_notify_t *pkt_notify(pkt_t *, uint16_t);
ike_payload_t *pkt_idx_to_payload(pkt_payload_t *);

pkt_t *pkt_in_alloc(uint8_t *restrict, size_t, struct bunyan_logger *restrict);
pkt_t *pkt_out_alloc(uint64_t, uint64_t, uint8_t, uint8_t, uint32_t, uint8_t);
void pkt_free(pkt_t *);

boolean_t pkt_add_payload(pkt_t *, uint8_t, uint8_t, size_t);
boolean_t pkt_add_sa(pkt_t *restrict, pkt_sa_state_t *restrict);
boolean_t pkt_add_prop(pkt_sa_state_t *, uint8_t, uint8_t, size_t, uint64_t);
boolean_t pkt_add_xform(pkt_sa_state_t *, uint8_t, uint16_t);
boolean_t pkt_add_xform_attr_tv(pkt_sa_state_t *, uint16_t, uint16_t);
boolean_t pkt_add_xform_attr_tlv(pkt_sa_state_t *restrict, uint16_t,
    const uint8_t *restrict, size_t);
boolean_t pkt_add_notify(pkt_t *restrict, uint32_t, uint8_t, uint8_t,
    uint64_t, uint16_t, const void *restrict, size_t);
boolean_t pkt_add_cert(pkt_t *restrict, uint8_t, uint8_t,
    const void *restrict, size_t);

boolean_t pkt_add_spi(pkt_t *, size_t, uint64_t);
boolean_t pkt_get_spi(uint8_t *restrict *, size_t len, uint64_t *restrict);

#ifdef __cplusplus
}
#endif

#endif /* _PKT_IMPL_H */
