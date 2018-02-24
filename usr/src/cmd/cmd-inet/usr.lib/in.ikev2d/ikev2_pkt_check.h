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
#ifndef _IKEV2_PKT_CHECK_H
#define	_IKEV2_PKT_CHECK_H

#include <inttypes.h>
#include "ikev2.h"

#ifdef __cplusplus
extern "C" {
#endif

struct pkt_s;

boolean_t ikev2_pkt_checklen(uint8_t, const uint8_t *, size_t);
boolean_t ikev2_pkt_check_payloads(struct pkt_s *);
uint8_t ikev2_pkt_check_critical(struct pkt_s *);

#ifdef __cplusplus
}
#endif

#endif /* _IKEV2_PKT_CHECK_H */
