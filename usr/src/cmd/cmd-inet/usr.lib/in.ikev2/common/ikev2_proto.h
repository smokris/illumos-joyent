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
 * Copyright 2017 Joyent, Inc.
 */

#ifndef _IKEV2_PROTO_H
#define	_IKEV2_PROTO_H

#include <inttypes.h>
#include "ikev2.h"

#ifdef __cplusplus
extern "C" {
#endif


struct pkt;
struct ikev2_sa;
struct sockaddr_storage;

void ikev2_dispatch(struct pkt *, const struct sockaddr_storage *,
    const struct sockaddr_storage *);
boolean_t ikev2_send(struct pkt *, boolean_t);
void ikev2_inbound(struct pkt *);

void ikev2_sa_init_inbound(struct pkt *);
void ikev2_sa_init_outbound(struct ikev2_sa *);

#ifdef __cplusplus
}
#endif

#endif /* _IKEV2_PROTO_H */
