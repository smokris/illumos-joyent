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

#ifndef _PFKEY_H
#define	_PFKEY_H

#include <sys/types.h>
#include <sys/socket.h>
#include <net/pfkeyv2.h>
#include "ikev2.h"

#ifdef __cplusplus
extern "C" {
#endif

void pfkey_msg_init(sadb_msg_t *, uint8_t, uint8_t);
size_t pfkey_add_address(sadb_address_t *, sockaddr_u_t, void *);
void pfkey_send_error(const sadb_msg_t *, uint8_t);
boolean_t pfkey_getspi(sockaddr_u_t, sockaddr_u_t, uint8_t, uint32_t *);
boolean_t pfkey_inverse_acquire(sockaddr_u_t, sockaddr_u_t, sockaddr_u_t,
    sockaddr_u_t, parsedmsg_t **);
ikev2_spi_proto_t satype_to_ikev2(uint8_t);
void sadb_log(bunyan_level_t, const char *restrict, sadb_msg_t *restrict);

#ifdef __cplusplus
}
#endif

#endif /* _PFKEY_H */
