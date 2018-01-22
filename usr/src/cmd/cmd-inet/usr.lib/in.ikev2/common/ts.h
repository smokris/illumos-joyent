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
 * Copyright (c) 2018, Joyent, Inc.
 */

#ifndef _TS_H
#define	_TS_H

#include <netinet/in.h>
#include <inttypes.h>

#ifdef __cplusplus
extern "C" {
#endif

struct pkt_s;
struct pkt_payload;
struct ikev2_ts;
struct ikev2_pkt_ts_state;
struct sadb_address;
struct sockaddr_storage;
struct bunyan_logger;
enum bunyan_level;

/*
 * A representation of traffic selectors that better matches what the kernel
 * uses (i.e. ([proto], address/prefix, [port])).  This is similar to an
 * sadb_address_t except that the total size of this structure is fixed.
 */
typedef struct ts_s {
	uint8_t ts_proto;		/* TCP, UDP, etc. */
	uint8_t	ts_prefix;
	union {
		struct sockaddr_in	tsu_sin;
		struct sockaddr_in6	tsu_sin6;
		struct sockaddr_storage tsu_ss;
		struct sockaddr		tsu_sa;
	} ts_addru;
#define	ts_sin	ts_addru.tsu_sin
#define	ts_sin6 ts_addru.tsu_sin6
#define	ts_ss	ts_addru.tsu_ss
#define	ts_sa	ts_addru.tsu_sa
} ts_t;

/* pf_key(7P) uses /0 to represent single addresses */
#define	TS_SADB_PREFIX(_t) \
    ((_t)->ts_prefix == ss_addrbits(&(_t)->ts_sa) ? 0 : (_t)->ts_prefix)

ts_t *sadb_to_ts(const struct sadb_address *restrict, ts_t *restrict);
boolean_t ts_add(struct ikev2_pkt_ts_state *restrict, const ts_t *restrict);
boolean_t ts_negotiate(struct pkt_s *restrict, ts_t *restrict, ts_t *restrict,
    boolean_t *restrict);
void ts_first(struct pkt_payload *restrict, ts_t *restrict);
void ts_log(struct bunyan_logger *restrict, enum bunyan_level,
    const char *restrict, const ts_t *restrict);

#ifdef __cplusplus
}
#endif

#endif /* _TS_H */
