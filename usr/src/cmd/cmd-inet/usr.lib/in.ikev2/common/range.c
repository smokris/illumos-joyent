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

/*
 * sockrange_t's represent an arbitrary range of addresses & ports.  These
 * are analogous to IKEv2's traffic selectors (TS), except that they're
 * easier to manipulate.  sockrange_t's consist of a start address & port
 * and an ending address & port (inclusive).
 */

#include <bunyan.h>
#include <errno.h>
#include <libinetutil.h>
#include <netinet/in.h>
#include <strings.h>
#include <sys/debug.h>
#include "defs.h"
#include "range.h"

#define	CHECK_AF(r) VERIFY3U((r)->sr_start.ss_family, ==, (r)->sr_end.ss_family)
#define	SATOSS(sa) ((struct sockaddr_storage *)(sa))

static sa_family_t
get_family(const sockrange_t *range)
{
	return (range->sr_start.ss_family);
}

void
range_set_family(sockrange_t *range, sa_family_t af)
{
	range->sr_start.ss_family = range->sr_end.ss_family = af;
}

/*
 * Set the start & end port to 'port' or [0, UINT16_MAX] if port is 0
 * to match pf_key(7P) semantics.
 */
static void
set_port(sockrange_t *range, in_port_t port)
{
	sockaddr_u_t sau_start = { .sau_ss = &range->sr_start };
	sockaddr_u_t sau_end = { .sau_ss = &range->sr_end };

	/* Take advantage of sockaddr_sin/sin6 port at the same offset */
	if (port != 0) {
		sau_start.sau_sin->sin_port = sau_end.sau_sin->sin_port = port;
		return;
	}

	sau_start.sau_sin->sin_port = 0;
	sau_end.sau_sin->sin_port = UINT16_MAX;
}

/* Convert address/prefixlen to a range */
void
net_to_range(const struct sockaddr *restrict addr, uint_t prefixlen,
    sockrange_t *restrict range)
{
	const uint8_t *addrp = NULL, *maskp = NULL;
	uint8_t *startp = NULL, *endp = NULL;
	struct sockaddr_storage mask = { 0 };
	size_t len = 0;

	VERIFY0(plen2mask(prefixlen, addr->sa_family, SSTOSA(&mask)));

	addrp = ss_addr(SATOSS(addr));
	maskp = ss_addr(SATOSS(&mask));
	len = ss_addrlen(SATOSS(addr));

	range_set_family(range, addr->sa_family);
	startp = (uint8_t *)ss_addr(&range->sr_start);
	endp = (uint8_t *)ss_addr(&range->sr_end);
	len = ss_addrlen(SATOSS(addr));

	for (size_t i = 0; i < len; i++) {
		startp[i] = addrp[i] & maskp[i];
		endp[i] = addrp[i] | ~maskp[i];
	}

	set_port(range, htons(ss_port(SATOSS(addr))));
}

/*
 * Find the least significant bit set/unset in the given address.
 * E.g. 192.168.1.0 -> 24; 10.0.1.255 -> 32
 */
static size_t
addr_lsb(const struct sockaddr_storage *addr, boolean_t set)
{
	const uint8_t *p = ss_addr(addr);
	size_t len = ss_addrlen(addr);
	int bits = len * NBBY;

	/* Work backwards from the least significant octet in addr */
	for (size_t i = len; i > 0; i--) {
		int val = p[i - 1];
		int bit = 0;

		if ((set && val == 0) || (!set && val == UINT8_MAX)) {
			bits -= NBBY;
			continue;
		}

		/*
		 * Since we can only easily find the first set bit
		 * in an integer, for finding unset, we invert and then
		 * check for a set bit.
		 */
		bit = ffs(set ? val : ~val);
		VERIFY3S(bit, >, 0);

		/* ffs(3C) uses 1-based indexing */
		bits -= bit - 1;
		break;
	}

	VERIFY3S(bits, >=, 0);
	return ((size_t)bits);
}

void
range_to_net(const sockrange_t *restrict range,
    struct sockaddr *restrict addr, size_t *restrict prefixlenp)
{
	uint8_t *addrp = NULL;
	size_t start_lsb, end_lsb;
	size_t len = 0;
	uint32_t start_port, end_port;

	CHECK_AF(range);

	switch (range->sr_start.ss_family) {
	case AF_INET:
		len = sizeof (struct sockaddr_in);
		break;
	case AF_INET6:
		len = sizeof (struct sockaddr_in6);
		break;
	default:
		INVALID(range->sr_start.ss_family);
	}

	start_lsb = addr_lsb(&range->sr_start, B_TRUE);
	end_lsb = addr_lsb(&range->sr_end, B_FALSE);
	*prefixlenp = MAX(start_lsb, end_lsb);

	start_port = ss_port(&range->sr_start);
	end_port = ss_port(&range->sr_end);

	bcopy(&range->sr_start, addr, len);

	/* Take advantage of port being at the same offset for IPv4/v6 */
	if (start_port != 0 || end_port != UINT16_MAX)
		((struct sockaddr_in *)addr)->sin_port = start_port;
}

/*
 * Alter the end address of range (if necessary) so that range can be
 * expressed as an address + prefix/subnetmask (within the original range).
 */
void
range_clamp(sockrange_t *restrict range)
{
	struct sockaddr_storage addr = { 0 };
	size_t prefixlen = 0;

	range_to_net(range, SSTOSA(&addr), &prefixlen);
	net_to_range(SSTOSA(&addr), prefixlen, range);
}

void
range_intersection(const sockrange_t *restrict r1,
    const sockrange_t *restrict r2, sockrange_t *restrict res)
{
	const uint8_t *start1p = NULL, *start2p = NULL;
	const uint8_t *end1p = NULL, *end2p = NULL;
	uint8_t *startrp = NULL, *endrp = NULL;
	size_t len = 0;

	CHECK_AF(r1);
	CHECK_AF(r2);
	VERIFY3U(r1->sr_start.ss_family, ==, r2->sr_start.ss_family);

	bzero(res, sizeof (*res));

	start1p = ss_addr(&r1->sr_start);
	end1p = ss_addr(&r1->sr_end);
	start2p = ss_addr(&r2->sr_start);
	end2p = ss_addr(&r2->sr_end);

	range_set_family(res, get_family(r1));
	startrp = (uint8_t *)ss_addr(&res->sr_start);
	endrp = (uint8_t *)ss_addr(&res->sr_end);

	len = ss_addrlen(SATOSS(&r1->sr_start));

	for (size_t i = 0; i < len; i++) {
		startrp[i] = MAX(start1p[i], start2p[i]);
		endrp[i] = MIN(end1p[i], end2p[i]);

		/* If end < start, the two ranges are disjoint, zero result */
		if (startrp[i] > endrp[i])
			goto zero;
	}

	/* Take advantage of port at the same offset for sin/sin6 */
	uint16_t *res_sport = &SSTOSIN(&res->sr_start)->sin_port;
	uint16_t *res_eport = &SSTOSIN(&res->sr_end)->sin_port;
	uint16_t s1port = ntohs(SSTOSIN(&r1->sr_start)->sin_port);
	uint16_t e1port = ntohs(SSTOSIN(&r1->sr_end)->sin_port);
	uint16_t s2port = ntohs(SSTOSIN(&r2->sr_start)->sin_port);
	uint16_t e2port = ntohs(SSTOSIN(&r2->sr_end)->sin_port);

	*res_sport = htons(MAX(s1port, s2port));
	*res_eport = htons(MIN(e1port, e2port));
	if (ntohs(*res_sport) > ntohs(*res_eport))
		goto zero;

	return;

zero:
	bzero(res, sizeof (*res));
	range_set_family(res, get_family(r1));
}

boolean_t
range_is_zero(const sockrange_t *restrict range)
{
	const uint8_t *sp = NULL, *ep = NULL;
	size_t len = 0;

	CHECK_AF(range);

	sp = ss_addr(&range->sr_start);
	ep = ss_addr(&range->sr_end);
	len = ss_addrlen(&range->sr_start);

	for (size_t i = 0; i < len; i++) {
		if (sp[i] != 0 || ep[i] != 0)
			return (B_FALSE);
	}

	return (B_TRUE);
}

boolean_t
range_in_net(const sockrange_t *restrict range,
    const struct sockaddr *restrict net, uint_t prefixlen)
{
	sockrange_t net_range = { 0 };
	const uint8_t *rs = NULL, *re = NULL, *ns = NULL, *ne = NULL;
	size_t len = 0;

	CHECK_AF(range);
	VERIFY3U(range->sr_start.ss_family, ==, net->sa_family);

	net_to_range(net, prefixlen, &net_range);

	rs = ss_addr(&range->sr_start);
	re = ss_addr(&range->sr_end);
	ns = ss_addr(&net_range.sr_start);
	ne = ss_addr(&net_range.sr_end);
	len = ss_addrlen(&range->sr_start);

	for (size_t i = 0; i < len; i++) {
		if (ns[i] > rs[i] || ne[i] < rs[i])
			return (B_FALSE);
	}

	return (B_TRUE);
}

/*
 * This compares the 'sizes' of two ranges, where 'size' is the number of
 * addresses contained within each range.  This is used during TS negotiation
 * to help select the largest range that still complies with our policy.
 */
int
range_cmp_size(const sockrange_t *restrict r1, const sockrange_t *restrict r2)
{
	const uint8_t *r1start = NULL, *r1end = NULL;
	const uint8_t *r2start = NULL, *r2end = NULL;
	size_t len = 0;

	CHECK_AF(r1);
	CHECK_AF(r2);
	VERIFY3U(r1->sr_start.ss_family, ==, r2->sr_start.ss_family);

	r1start = ss_addr(&r1->sr_start);
	r1end = ss_addr(&r1->sr_end);
	r2start = ss_addr(&r2->sr_start);
	r2end = ss_addr(&r2->sr_end);
	len = ss_addrlen(&r1->sr_start);

	/*
	 * While calculating the actual size of an IPv4 range is pretty easy,
	 * for IPv6, we'd need to use a 128bit sized integer.  Since we only
	 * care about the comparison than the actual number, we just check
	 * each octet.
	 */
	for (size_t i = 0; i < len; i++) {
		VERIFY3U(r1end[i], >=, r1start[i]);
		VERIFY3U(r2end[i], >=, r2start[i]);

		uint8_t diff1 = r1end[i] - r1start[i];
		uint8_t diff2 = r2end[i] - r2start[i];

		if (diff1 > diff2)
			return (-1);
		if (diff2 > diff1)
			return (1);
	}

	return (0);
}

void
range_log(bunyan_logger_t *restrict log, bunyan_level_t level,
    const char *restrict msg, const sockrange_t *restrict range)
{
	const struct sockaddr_storage *start = &range->sr_start;
	const struct sockaddr_storage *end = &range->sr_end;

	(void) getlog(level)(log, msg,
	    ss_bunyan(start), "start", ss_addr(start),
	    BUNYAN_T_UINT32, "startport", ss_port(start),
	    ss_bunyan(end), "end", ss_addr(end),
	    BUNYAN_T_UINT32, "endport", ss_port(end),
	    BUNYAN_T_END);
}
