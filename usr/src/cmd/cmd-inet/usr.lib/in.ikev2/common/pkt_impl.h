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

#ifdef _PKT_IMPL_H
#define	_PKT_IMPL_H

#include "pkt.h"

#ifdef __cplusplus
extern "C" {
#endif

pkt_t	*pkt_in_alloc(const buf_t *);
pkt_t	*pkt_out_alloc(uint64_t, uint64_t, uint8_t, uint8_t, uint32_t);
void	pkt_free(pkt_t *);

void	pkt_hdr_hton(ike_header_t *restrict, const ike_header_t *restrict);
void	pkt_hdr_ntoh(ike_header_t *restrict, const ike_header_t *restrict);

void pkt_set_prec(pkt_t *restrict, int, uintptr_t, pkt_finish_fn);
boolean_t pkt_add_payload(pkt_t *, uint8_t, uint8_t);
boolean_t pkt_add_prop(pkt_t *, uint8_t, uint8_t, uint8_t, uint64_t);
boolean_t pkt_add_xform(pkt_t *, uint8_t, uint8_t);
boolean_t pkt_add_xform_attr_tv(pkt_t *, uint16_t, uint16_t);
boolean_t pkt_add_xform_attr_tlv(pkt_t *restrict, uint16_t,
    const buf_t *restrict);
boolean_t pkt_add_cert(pkt_t *restrict, uint8_t, const buf_t *restrict);


/* append the given struct into the raw packet buffer of pkt */
#define APPEND_STRUCT(pkt, st)                                  \
        do {                                                    \
                buf_t *_dest = &(pkt)->buf;                     \
                buf_t _src = STRUCT_TO_BUF((st));               \
                VERIFY(buf_copy(_dest, &_src) ==                \
                    sizeof ((st)));                             \
                BUF_ADVANCE(_dest, sizeof ((st)));              \
                NOTE(CONSTCOND)                                 \
        } while (0)

#define	APPEND_BUF(pkt, sbuf)						\
	do {								\
		VERIFY(buf_copy(&(pkt)->buf, sbuf) == sbuf->len);	\
		BUF_ADVANCE(&(pkt)->buf, sbuf->len);			\
		NOTE(CONSTCOND)						\
	} while (0)

#ifdef __cplusplus
}
#endif

#endif /* _PKT_H */
