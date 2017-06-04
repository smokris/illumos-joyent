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

#ifdef _IKEV2_PKT_H
#define	_IKEV2_PKT_H

#include <sys/types.h>
#include "ikev2.h"
#include "pkt.h"
#include "buf.h"

#ifdef __cplusplus
extern "C" {
#endif

struct pkt;
struct ikev2_sa;

#ifndef IKEV2_PKT_T
typedef struct pkt ikev2_pkt_t;
#endif

#define	IKEV2_PAYLOAD_PTR(pkt, num) \
	((pkt)->payloads[(num) - IKEV2_PAYLOAD_START])

ikev2_pkt_t *ikev2_pkt_new_inbound(const buf_t *);
ikev2_pkt_t *ikev2_pkt_new_initiator(struct ikev2_sa *, ikev2_exch_t);
ikev2_pkt_t *ikev2_pkt_new_response(const ikev2_pkt *);
void ikev2_pkt_free(ikev2_pkt_t *);

boolean_t ikev2_add_sa(pkt_t *);
boolean_t ikev2_add_prop(pkt_t *, uint8_t, ike_proto_t, uint64_t);
boolean_t ikev2_add_xform(pkt_t *, ikev2_xf_type_t, int);
boolean_t ikev2_add_xf_attr(pkt_t *, ikev2_xf_attr_type_t, uintptr_t);
boolean_t ikev2_add_ke(pkt_t *restrict, uint_t, const buf_t *restrict);
boolean_t ikev2_add_id_i(pkt_t *restrict, ikev2_id_type_t, const void *);
boolean_t ikev2_add_id_r(pkt_t *restrict, ikev2_id_type_t, const void *);
boolean_t ikev2_add_cert(pkt_t *restrict, ikev2_cert_t, const buf_t *restrict);
boolean_t ikev2_add_certreq(pkt_t *restrict, ikev2_cert_t,
    const buf_t *restrict);
boolean_t ikev2_add_auth(pkt_t *restrict, ikev2_auth_t, const buf_t *restrict );
boolean_t ikev2_add_nonce(pkt_t *restrict, const buf_t *restrict);
boolean_t ikev2_add_notify(pkt_t *restrict, ikev2_proto_t, size_t,
    ike2_notify_type_t, uint64_t, const buf_t *restrict);

boolean_t ikev2_add_delete(pkt_t *, ikev2_proto_t);
boolean_t ikev2_add_delete_spi(pkt_t *, uint64_t);

boolean_t ikev2_add_vendor(pkt_t *restrict, const buf_t *restrict);

boolean_t ikev2_add_ts_i(pkt_t *);
boolean_t ikev2_add_ts_r(pkt_t *);
boolean_t ikev2_add_ts(pkt_t *restrict, int /* type */, int /* proto */, const sockaddr_u_t *restrict /* start */, const sockaddr_u_t *restrict /* end */);

boolean_t ikev2_add_sk(pkt_t *);

boolean_t ikev2_add_config(pkt_t *restrict, ikev2_cfg_type_t);
boolean_t ikev2_add_config_attr(pkt_t *restrict, ikev2_cfg_attr_type_t,
    const void *restrict);

boolean_t ikev2_add_eap(pkt_t *restrict, const buf_t *restrict, size_t);

#ifdef __cplusplus
}
#endif

#endif /* _IKEV2_PKT_H */
