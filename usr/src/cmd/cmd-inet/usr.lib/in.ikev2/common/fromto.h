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
 * Copyright 2017 Joyent, Inc
 */

#ifndef _FROMTO_H
#define	_FROMTO_H

#include <sys/types.h>
#include <sys/socket.h>

#ifdef __cplusplus
extern "C" {
#endif

ssize_t recvfromto(int, uint8_t *restrict, size_t, int,
    struct sockaddr_storage *restrict, socklen_t *restrict,
    struct sockaddr_storage *restrict, socklen_t *restrict);

ssize_t sendfromto(int, const uint8_t *restrict, size_t,
    struct sockaddr_storage *restrict, struct sockaddr_storage *restrict);

#ifdef __cplusplus
}
#endif

#endif /* _FROMTO_H */
