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

#ifndef _RANGE_H
#define	_RANGE_H

#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>

#ifdef __cplusplus
extern "C" {
#endif

#define	SSTOSA(ss) ((struct sockaddr *)(ss))
#define	SSTOSIN(ss) ((struct sockaddr_in *)(ss))
#define	SSTOSIN6(ss) ((struct sockaddr_in6 *)(ss))

struct bunyan_logger;
enum bunyan_level;

typedef struct sockrange_s {
	struct sockaddr_storage sr_start;
	struct sockaddr_storage sr_end;
} sockrange_t;

void range_set_family(sockrange_t *, sa_family_t);
void net_to_range(const struct sockaddr *restrict, uint8_t,
    sockrange_t *restrict);
void range_to_net(const sockrange_t *restrict, struct sockaddr *restrict,
    uint8_t *restrict);
void range_clamp(sockrange_t *restrict);
void range_intersection(const sockrange_t *restrict,
    const sockrange_t *restrict, sockrange_t *restrict);
boolean_t range_is_empty(const sockrange_t *restrict);
boolean_t range_in_net(const sockrange_t *restrict,
    const struct sockaddr *restrict, uint_t);
int range_cmp_size(const sockrange_t *restrict, const sockrange_t *restrict);
void range_log(struct bunyan_logger *restrict, enum bunyan_level,
    const char *restrict, const sockrange_t *restrict);

#ifdef __cplusplus
}
#endif

#endif /* _RANGE_H */
