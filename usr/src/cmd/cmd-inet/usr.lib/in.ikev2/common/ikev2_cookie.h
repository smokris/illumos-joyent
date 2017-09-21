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

#ifndef _IKEV2_COOKIE_H
#define	_IKEV2_COOKIE_H

#include <inttypes.h>

#ifdef __cplusplus
extern "C" {
#endif

#define	IKEV2_COOKIE_OFF_ADJ	(5)	/* XXX: Better name? */
extern size_t ikev2_cookie_threshold;

struct sockaddr_storage;
struct pkt_s;

void ikev2_cookie_enable(void);
void ikev2_cookie_disable(void);
boolean_t ikev2_cookie_check(struct pkt_s *restrict,
    const struct sockaddr_storage *restrict);

#ifdef __cplusplus
}
#endif

#endif /* _IKEV2_COOKIE_H */
