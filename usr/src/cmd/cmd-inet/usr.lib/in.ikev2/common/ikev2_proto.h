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
 * Copyright (c) 2017, Joyent, Inc.
 */

#ifndef _IKEV2_PROTO_H
#define	_IKEV2_PROTO_H

#include <inttypes.h>
#include "ikev2.h"

#ifdef __cplusplus
extern "C" {
#endif


struct pkt_s;
struct ikev2_sa_s;
struct sockaddr_storage;
struct config_rule_s;
struct parsedmsg_s;

void ikev2_inbound(struct pkt_s *restrict, const struct sockaddr *restrict,
    const struct sockaddr *restrict);
void ikev2_pfkey(struct parsedmsg_s *);
void ikev2_sa_init_cfg(struct config_rule_s *);

typedef void (*ikev2_send_cb_t)(struct ikev2_sa_s *restrict,
    struct pkt_s *restrict, void *restrict);
boolean_t ikev2_send_req(struct pkt_s *restrict, ikev2_send_cb_t,
    void *restrict);
boolean_t ikev2_send_resp(struct pkt_s *restrict);
boolean_t ikev2_send_resp_addr(struct pkt_s *restrict,
    const struct sockaddr *restrict,
    const struct sockaddr *restrict);

void ikev2_dispatch(struct ikev2_sa_s *);
void ikev2_retransmit_cb(void *);

void ikev2_sa_init_init(struct ikev2_sa_s *restrict,
    struct parsedmsg_s *restrict);
void ikev2_sa_init_resp(struct pkt_s *);

void ikev2_ike_auth_init(struct ikev2_sa_s *restrict);
void ikev2_ike_auth_resp(struct pkt_s *);

boolean_t ikev2_create_child_sa_init_auth(struct ikev2_sa_s *restrict,
    struct pkt_s *restrict);
boolean_t ikev2_create_child_sa_resp_auth(struct pkt_s *restrict,
    struct pkt_s *restrict);
void ikev2_create_child_sa_init_resp_auth(struct ikev2_sa_s *restrict,
    struct pkt_s *restrict, void *restrict);

void ikev2_create_child_sa_init(struct ikev2_sa_s *restrict,
    struct parsedmsg_s *restrict);
void ikev2_create_child_sa_resp(struct pkt_s *restrict);

#ifdef __cplusplus
}
#endif

#endif /* _IKEV2_PROTO_H */
