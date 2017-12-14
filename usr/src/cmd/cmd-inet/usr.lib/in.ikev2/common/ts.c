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

#include <bunyan.h>
#include <inttypes.h>
#include <libinetutil.h>	/* For plen2mask */
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/pfkeyv2.h>
#include <netdb.h>
#include <strings.h>
#include "defs.h"
#include "ikev2_enum.h"
#include "ikev2_pkt.h"
#include "ts.h"

/*
 * Much like ts_t are fixed-sized versions of the kernel's traffic selectors,
 * range_t's are fixed-sized versions of IKEv2 traffic selectors and can
 * access all the data via field names instead of requiring lots of pointer
 * math.
 */
typedef struct range_s {
	union {
		struct sockaddr		su_startsa;
		struct sockaddr_in	su_start;
		struct sockaddr_in6	su_start6;
		struct sockaddr_storage su_startss;
	} ra_startu;
	union {
		struct sockaddr		eu_endsa;
		struct sockaddr_in	eu_end;
		struct sockaddr_in6	eu_end6;
		struct sockaddr_storage	eu_endss;
	} ra_endu;
	uint8_t ra_proto;
/* Oh to have C11 anonymous unions.... */
#define	ra_startsa ra_startu.su_startsa
#define	ra_start ra_startu.su_start
#define	ra_start6 ra_startu.su_start6
#define	ra_startss ra_startu.su_startss
#define	ra_endsa ra_endu.eu_endsa
#define	ra_end ra_endu.eu_end
#define	ra_end6 ra_endu.eu_end6
#define	ra_endss ra_endu.eu_endss
} range_t;

#define	RANGE_CHECKAF(r) \
    VERIFY3U((r)->ra_startsa.sa_family, ==, (r)->ra_endsa.sa_family);

static void ts_to_range(const ts_t *restrict, range_t *restrict);
static void range_to_ts(const range_t *restrict, ts_t *restrict);
static boolean_t range_intersection(const range_t *restrict,
    const range_t *restrict, range_t *restrict);
static int range_cmp_size(const range_t *restrict,
    const range_t *restrict);
static boolean_t range_contains(const range_t *restrict,
    const range_t *restrict);
static void range_log(bunyan_logger_t *restrict, bunyan_level_t,
    const char *restrict, const range_t *restrict);

ts_t *
sadb_to_ts(const sadb_address_t *restrict addr, ts_t *restrict ts)
{
	size_t len = SADB_64TO8(addr->sadb_address_len) - sizeof (*addr);

	switch (addr->sadb_address_exttype) {
	case SADB_EXT_ADDRESS_SRC:
	case SADB_EXT_ADDRESS_DST:
	case SADB_X_EXT_ADDRESS_INNER_SRC:
	case SADB_X_EXT_ADDRESS_INNER_DST:
		break;
	default:
		INVALID(addr->sadb_address_exttype);
	}

	bzero(ts, sizeof (*ts));

	ts->ts_proto = addr->sadb_address_proto;
	ts->ts_prefix = addr->sadb_address_prefixlen;
	bcopy(addr + 1, &ts->ts_ss, len);

	/* pf_key(7p) uses /0 for single addresses.  sigh. */
	if (ts->ts_prefix == 0 && !addr_is_zero(&ts->ts_sa))
		ts->ts_prefix = ss_addrbits(&ts->ts_sa);

	return (ts);
}

boolean_t
ts_add(ikev2_pkt_ts_state_t *restrict tss, const ts_t *restrict ts)
{
	range_t r = { 0 };
	char msg[64] = { 0 };
	const char *ts_name = ikev2_pay_short_str(tss->i2ts_idx->pp_type);

	(void) snprintf(msg, sizeof (msg), "Added %s", ts_name);

	ts_to_range(ts, &r);
	if (!ikev2_add_ts(tss, ts->ts_proto, &r.ra_startsa, &r.ra_endsa))
		return (B_FALSE);

	ts_log(log, BUNYAN_L_TRACE, msg, ts);
	return (B_TRUE);
}

/*
 * Adjust our traffic selector to a range that is compatible with the
 * selectors in the given payload.
 *
 *	pay		The payload (TS{i,r}) to compare
 *	ts		Our traffic selector corresponding to selectors in pay.
 *	narrowed	Set on return if the range of ts was narrowed.
 *	from_init	B_TRUE if payload is from the initiator
 *
 * If there was no common subset of addresses between pay and ts, B_FALSE
 * is returned.  Otherwise, B_TRUE is returned.
 */
static boolean_t
ts_negotiate_one(pkt_payload_t *restrict pay, ts_t *restrict ts,
    boolean_t *restrict narrowed, const boolean_t from_init)
{
	const char *ts_type = ikev2_pay_short_str(pay->pp_type);
	char msg[128] = { 0 };
	ikev2_ts_t *tsp = NULL;
	ikev2_ts_iter_t iter = { 0 };
	range_t peer = { 0 };
	range_t ts0 = { 0 };
	range_t us = { 0 };
	range_t res = { 0 };
	range_t cmp = { 0 };
	boolean_t first = B_TRUE;

	ts_to_range(ts, &us);
	(void) snprintf(msg, sizeof (msg), "Local %s", ts_type);
	range_log(log, BUNYAN_L_TRACE, msg, &us);

	/* Get the first TS from the payload */
	tsp = ikev2_ts_iter(pay, &iter, &ts0.ra_startss, &ts0.ra_endss);
	ts->ts_proto = tsp->ts_protoid;

	(void) snprintf(msg, sizeof (msg), "Remote %s[0]", ts_type);
	range_log(log, BUNYAN_L_TRACE, msg, &ts0);

	/*
	 * Determine the addresses in common.  On the responder, this should
	 * always succeed, as we first query the kernel for our policy that
	 * covers TS[0] before attempting to negotiate the traffic selectors,
	 * and will fail at that point if no policy is found.  On the initiator
	 * however, a responder is supposed to send a TS_UNACCEPTABLE if the
	 * proposed selectors are not allowed by it's policy, but we still
	 * want to guard against a peer sending back selectors that violate
	 * our policy.
	 */
	if (!range_intersection(&us, &ts0, &res)) {
		range_log(log, BUNYAN_L_WARN,
		    "Traffic selector from peer violates local policy", &ts0);
		return (B_FALSE);
	}

	(void) snprintf(msg, sizeof (msg), "Local %s & Remote %s[0]", ts_type,
	    ts_type);
	range_log(log, BUNYAN_L_TRACE, msg, &res);

	/*
	 * For payloads from the initiator, if more than one TS is present in
	 * a payload, the first TS is the address of the original packet
	 * that triggered the SA creation, and the additional TS are the
	 * selectors from the initiator's policy that cover the original packet.
	 * This means when additional selectors are present, the intersection
	 * of TS[0] and our selector will result in a single address.  However,
	 * we'd like to use the broadest policy we can express that complies
	 * with both our and our peer's policy (but still includes the address
	 * of the original packet).
	 */
	while (from_init && (tsp = ikev2_ts_iter_next(&iter,
	    &peer.ra_startss, &peer.ra_endss)) != NULL) {
		ts_t ts_tmp = { 0 };

		if (tsp->ts_protoid != ts->ts_proto) {
			struct protoent *pe = NULL;
			char pnum[6] = { 0 };

			pe = getprotobynumber(tsp->ts_protoid);
			if (pe == NULL) {
				(void) snprintf(pnum, sizeof (pnum), "%hhu",
				    tsp->ts_protoid);
			}

			(void) snprintf(msg, sizeof (msg),
			    "Remote %s[%zu] is not the same protocol as our"
			    "local %s", ts_type, iter.i2ti_n, ts_type);

			(void) bunyan_trace(log, msg,
			    BUNYAN_T_STRING, "protocol",
			    (pe != NULL) ? pe->p_name : pnum,
			    BUNYAN_T_END);

			continue;
		}

		bzero(&cmp, sizeof (cmp));

		if (!range_intersection(&peer, &us, &cmp)) {
			(void) snprintf(msg, sizeof (msg),
			    "Remote %s[%zu] has no overlap with local %s",
			    ts_type, iter.i2ti_n, ts_type);
			(void) bunyan_trace(log, msg, BUNYAN_T_END);
			continue;
		}

		(void) snprintf(msg, sizeof (msg),
		    "Remote %s[%zu] & local %s", ts_type, iter.i2ti_n, ts_type);
		range_log(log, BUNYAN_L_TRACE, msg, &cmp);

		/*
		 * Convert the resulting intersection to an address/prefix and
		 * back again.  Because we can only deal with subnets
		 * (address/prefix) and not arbitrary ranges of addresses, the
		 * conversion from a range_t to a ts_t may narrow the result.
		 * Converting the ts_t back to a range_t then gives us a
		 * value that we know is usable by the kernel.  This form is
		 * what we want to use to compare the size of the range_t and
		 * check that the range still contains the original packet.
		 */
		range_to_ts(&cmp, &ts_tmp);
		ts_to_range(&ts_tmp, &cmp);

		(void) strlcat(msg, " (as subnet)", sizeof (msg));
		ts_log(log, BUNYAN_L_TRACE, msg, &ts_tmp);

		if (!range_contains(&cmp, &ts0)) {
			(void) snprintf(msg, sizeof (msg),
			    "Remote %s[%zu] & local %s does not contain %s[0]",
			    ts_type, iter.i2ti_n, ts_type, ts_type);
			range_log(log, BUNYAN_L_TRACE, msg, &cmp);
			continue;
		}

		if (range_cmp_size(&cmp, &res) > 0) {
			/*
			 * If more than one selector is present (excluding the
			 * original packet as a selector), we only support
			 * picking one, so we're definitely narrowing the
			 * proposed selectors.
			 *
			 * XXX: This isn't the only case where it can happen,
			 * need to add checks for those, however this detection
			 * is strictly informational in nature to allow both
			 * peers to detect mismatched policies, so it is not
			 * fatal or even incorrect if we don't report all
			 * instances.
			 */
			if (!first)
				*narrowed = B_TRUE;

			res = cmp;

			(void) snprintf(msg, sizeof (msg),
			    "Remote %s[%zu] is current largest range",
			    ts_type, iter.i2ti_n);
			range_log(log, BUNYAN_L_TRACE, msg, &res);
		}
		first = B_FALSE;
	}

	(void) snprintf(msg, sizeof (msg), "Selected %s", ts_type);
	range_log(log, BUNYAN_L_TRACE, msg, &res);

	range_to_ts(&res, ts);
	return (B_TRUE);
}

boolean_t
ts_negotiate(pkt_t *restrict pkt, ts_t *restrict ts_i, ts_t *restrict ts_r,
    boolean_t *restrict narrowed)
{
	pkt_payload_t *ts_pay = NULL;
	boolean_t is_init = I2P_INITIATOR(pkt);

	*narrowed = B_FALSE;

	if ((ts_pay = pkt_get_payload(pkt, IKEV2_PAYLOAD_TSi, NULL)) == NULL) {
		(void) bunyan_warn(log, "TSi payload missing", BUNYAN_T_END);
		return (B_FALSE);
	}

	if (!ts_negotiate_one(ts_pay, ts_i, narrowed, is_init))
		return (B_FALSE);

	if ((ts_pay = pkt_get_payload(pkt, IKEV2_PAYLOAD_TSr, NULL)) == NULL) {
		(void) bunyan_warn(log, "TSr payload missing", BUNYAN_T_END);
		return (B_FALSE);
	}

	return (ts_negotiate_one(ts_pay, ts_r, narrowed, is_init));
}

void
ts_first(pkt_payload_t *restrict pay, ts_t *restrict ts)
{
	ikev2_ts_t *tsp = NULL;
	ikev2_ts_iter_t iter = { 0 };
	range_t r = { 0 };

	VERIFY(pay->pp_type == IKEV2_PAYLOAD_TSi ||
	    pay->pp_type == IKEV2_PAYLOAD_TSr);

	tsp = ikev2_ts_iter(pay, &iter, &r.ra_startss, &r.ra_endss);
	r.ra_proto = tsp->ts_protoid;
	range_to_ts(&r, ts);
}

static void
range_set_family(range_t *restrict r, sa_family_t af)
{
	r->ra_startsa.sa_family = r->ra_endsa.sa_family = af;
}

static void
range_set_port(range_t *restrict r, uint16_t start_port, uint16_t end_port)
{
	/* Take advantage of port being at the same offset for IPv4/6 */
	uint16_t *startp = &r->ra_start.sin_port;
	uint16_t *endp = &r->ra_end.sin_port;

	RANGE_CHECKAF(r);

	VERIFY(r->ra_startss.ss_family == AF_INET ||
	    r->ra_startss.ss_family == AF_INET6);

	*startp = start_port;
	*endp = end_port;
}

static void
ts_to_range(const ts_t *restrict ts, range_t *restrict r)
{
	struct sockaddr_storage mask = { .ss_family = ts->ts_ss.ss_family };
	const uint8_t *addrp = ss_addr(&ts->ts_sa);
	const uint8_t *maskp = ss_addr(SSTOSA(&mask));
	uint8_t *startp = NULL;
	uint8_t *endp = NULL;
	uint16_t sport = 0, eport = UINT16_MAX;
	size_t len = 0;

	VERIFY0(plen2mask(ts->ts_prefix, ts->ts_sa.sa_family, SSTOSA(&mask)));

	range_set_family(r, ts->ts_sa.sa_family);
	len = ss_addrlen(&ts->ts_sa);
	startp = (uint8_t *)ss_addr(&r->ra_startsa);
	endp = (uint8_t *)ss_addr(&r->ra_endsa);

	for (size_t i = 0; i < len; i++) {
		startp[i] = addrp[i] & maskp[i];
		endp[i] = addrp[i] | ~maskp[i];
	}

	if (ss_port(&ts->ts_sa) != 0) {
		/* ss_port returns the value in host byte order */
		uint32_t val = ss_port(&ts->ts_sa);
		sport = eport = htons(val);
	}

	range_set_port(r, sport, eport);
	r->ra_proto = ts->ts_proto;
}

static boolean_t
range_intersection_addr(const range_t *restrict r1, const range_t *restrict r2,
    range_t *restrict r_res)
{
	const uint8_t *start1p = ss_addr(&r1->ra_startsa);
	const uint8_t *start2p = ss_addr(&r2->ra_startsa);
	const uint8_t *end1p = ss_addr(&r1->ra_endsa);
	const uint8_t *end2p = ss_addr(&r2->ra_endsa);
	uint8_t *res_startp = (uint8_t *)ss_addr(&r_res->ra_startsa);
	uint8_t *res_endp = (uint8_t *)ss_addr(&r_res->ra_endsa);
	size_t len = ss_addrlen(&r1->ra_startsa);

	for (size_t i = 0; i < len; i++) {
		res_startp[i] = MAX(start1p[i], start2p[i]);
		res_endp[i] = MIN(end1p[i], end2p[i]);

		/* If the range is disjoint, set r_res to a zero-sized range */
		if (res_startp[i] > res_endp[i])
			return (B_FALSE);
	}

	return (B_TRUE);
}

static boolean_t
range_intersection_port(const range_t *restrict r1, const range_t *restrict r2,
    range_t *restrict r_res)
{
	uint16_t start1 = ss_port(&r1->ra_startsa);
	uint16_t start2 = ss_port(&r2->ra_startsa);
	uint16_t end1 = ss_port(&r1->ra_endsa);
	uint16_t end2 = ss_port(&r2->ra_endsa);
	uint16_t sport = MAX(start1, start2);
	uint16_t eport = MIN(end1, end2);

	if (sport > eport)
		return (B_FALSE);

	range_set_port(r_res, sport, eport);
	return (B_TRUE);
}

/*
 * Compute the intersection of the two ranges.  Returns B_FALSE if the result
 * is the empty/null set.  B_TRUE otherwise
 */
static boolean_t
range_intersection(const range_t *restrict r1, const range_t *restrict r2,
    range_t *restrict r_res)
{
	RANGE_CHECKAF(r1);
	RANGE_CHECKAF(r2);
	VERIFY3U(r1->ra_startss.ss_family, ==, r2->ra_startss.ss_family);

	bzero(r_res, sizeof (*r_res));
	range_set_family(r_res, r1->ra_startss.ss_family);

	if (r1->ra_proto == 0)
		r_res->ra_proto = r2->ra_proto;
	else if (r2->ra_proto == 0)
		r_res->ra_proto = r1->ra_proto;
	else if (r1->ra_proto != r2->ra_proto)
		goto zero;
	else
		r_res->ra_proto = r1->ra_proto;

	if (!range_intersection_addr(r1, r2, r_res))
		goto zero;

	if (!range_intersection_port(r1, r2, r_res))
		goto zero;

	r_res->ra_proto = r1->ra_proto;
	return (B_TRUE);

zero:
	bzero(r_res, sizeof (*r_res));
	range_set_family(r_res, r1->ra_startss.ss_family);
	return (B_FALSE);
}

/*
 * Find the least significant bit set/unset in the given address.
 */
static size_t
addr_lsb(const struct sockaddr *restrict addr, boolean_t set)
{
	const uint8_t *p = ss_addr(addr);
	size_t len = ss_addrlen(addr);
	int bits = len * NBBY;

	for (size_t i = len; i > 0; i--) {
		int val = p[i - 1];
		int bit = 0;

		if ((set && val == 0) || (!set && val == UINT8_MAX)) {
			bits -= NBBY;
			continue;
		}

		/*
		 * We can only easily check the first set bit in an int.
		 * For finding the first unset bit, invert then check.
		 */
		bit = ffs(set ? val : ~val);
		VERIFY3S(bit, >, 0);

		/* ffc(3C) uses 1-based indexes for bits */
		bits -= bit - 1;
		break;
	}

	VERIFY3S(bits, >=, 0);
	return ((size_t)bits);
}

static void
range_to_ts(const range_t *restrict r, ts_t *restrict ts)
{
	uint8_t *ts_addr = NULL;
	const uint8_t *start_addr = ss_addr(&r->ra_startsa);
	size_t start_lsb = addr_lsb(&r->ra_startsa, B_TRUE);
	size_t end_lsb = addr_lsb(&r->ra_endsa, B_FALSE);
	size_t len = ss_addrlen(&r->ra_startsa);
	uint32_t start_port = ss_port(&r->ra_startsa);
	uint32_t end_port = ss_port(&r->ra_endsa);

	RANGE_CHECKAF(r);

	bzero(&ts->ts_ss, sizeof (ts->ts_ss));

	ts->ts_ss.ss_family = r->ra_startss.ss_family;
	ts_addr = (uint8_t *)ss_addr(&ts->ts_sa);
	bcopy(start_addr, ts_addr, len);

	ts->ts_prefix = MAX(start_lsb, end_lsb);
	ts->ts_proto = r->ra_proto;

	/* Take advantage of the same offset for port for sin/sin6 */
	if (start_port != 0 || end_port != UINT16_MAX)
		ts->ts_sin.sin_port = htons(start_port);
}

/* B_TRUE if r1 contains r2 */
static boolean_t
range_contains_addr(const range_t *restrict r1, const range_t *restrict r2)
{
	const uint32_t *r1start = ss_addr(&r1->ra_startsa);
	const uint32_t *r2start = ss_addr(&r2->ra_startsa);
	const uint32_t *r1end = ss_addr(&r1->ra_endsa);
	const uint32_t *r2end = ss_addr(&r2->ra_endsa);
	size_t len = ss_addrlen(&r1->ra_startsa);

	for (size_t i = 0; i < len; i++) {
		/* Double check our invariants */
		VERIFY3U(r1start[i], <=, r1end[i]);
		VERIFY3U(r2start[i], <=, r2end[i]);

		if (r1start[i] > r2start[i] || r1end[i] < r2end[i])
			return (B_FALSE);
	}

	return (B_TRUE);
}

static boolean_t
range_contains_port(const range_t *restrict r1, const range_t *restrict r2)
{
	uint32_t p1_start = ss_port(&r1->ra_startsa);
	uint32_t p2_start = ss_port(&r2->ra_startsa);
	uint32_t p1_end = ss_port(&r1->ra_endsa);
	uint32_t p2_end = ss_port(&r2->ra_endsa);

	/* Check our invariants */
	VERIFY3U(p1_start, <=, p1_end);
	VERIFY3U(p2_start, <=, p2_end);

	if (p1_start > p2_start || p1_end < p2_end)
		return (B_FALSE);

	return (B_TRUE);
}

static boolean_t
range_contains(const range_t *restrict r1, const range_t *restrict r2)
{
	RANGE_CHECKAF(r1);
	RANGE_CHECKAF(r2);
	VERIFY3U(r1->ra_startsa.sa_family, ==, r2->ra_startsa.sa_family);

	if ((r1->ra_proto != 0) && (r1->ra_proto != r2->ra_proto))
		return (B_FALSE);

	if (!range_contains_addr(r1, r2))
		return (B_FALSE);

	return (range_contains_port(r1, r2));
}

static int
range_cmp_size_addr(const range_t *restrict r1, const range_t *restrict r2)
{
	const uint32_t *r1start = ss_addr(&r1->ra_startsa);
	const uint32_t *r2start = ss_addr(&r2->ra_startsa);
	const uint32_t *r1end = ss_addr(&r1->ra_endsa);
	const uint32_t *r2end = ss_addr(&r2->ra_endsa);
	size_t len = ss_addrlen(&r1->ra_startsa);

	VERIFY3U(len % sizeof (uint32_t), ==, 0);

	/*
	 * Since we currently don't have 128-bit integer support in our compiler
	 * AFAIK, just look in 32-bit chunks.  We only care about the
	 * relative sizes of the range versus the actual sizes, so we don't
	 * need to do the 128-bit math.
	 */
	for (size_t i = 0; i < len / sizeof (uint32_t); i++) {
		uint32_t s1 = ntohl(r1start[i]);
		uint32_t s2 = ntohl(r2start[i]);
		uint32_t e1 = ntohl(r1end[i]);
		uint32_t e2 = ntohl(r2end[i]);
		uint32_t d1 = e1 - s1;
		uint32_t d2 = e2 - e1;

		/* Can't hurt to verify our expected invariants */
		VERIFY3U(s1, <=, e1);
		VERIFY3U(s1, <=, e1);

		if (d1 > d2)
			return (-1);
		if (d1 < d2)
			return (1);
	}

	return (0);
}

static int
range_cmp_size_port(const range_t *restrict r1, const range_t *restrict r2)
{
	uint32_t p1_start = ss_port(&r1->ra_startsa);
	uint32_t p2_start = ss_port(&r2->ra_startsa);
	uint32_t p1_end = ss_port(&r1->ra_endsa);
	uint32_t p2_end = ss_port(&r2->ra_endsa);
	uint32_t d1 = p1_end - p1_start;
	uint32_t d2 = p2_end - p2_start;

	/* Check our invariants */
	VERIFY3U(p1_start, <=, p1_end);
	VERIFY3U(p2_start, <=, p2_end);

	if (d1 > d2)
		return (-1);

	if (d1 < d2)
		return (1);

	return (0);
}

/*
 * Compares the size (number of addresses) of each range.  It does not
 * look at the ordering of the start, end addresses of each range.   For
 * example:
 *
 *	(10.0.2.0 - 10.0.255.255) > (192.168.1.0 - 192.168.2.0)
 *
 * Returns the usual -1, 0, 1 based on the comparison of sizes of r1 to t2.
 */
static int
range_cmp_size(const range_t *restrict r1, const range_t *restrict r2)
{
	int cmp;

	RANGE_CHECKAF(r1);
	RANGE_CHECKAF(r2);
	VERIFY3U(r1->ra_startsa.sa_family, ==, r2->ra_startsa.sa_family);

	if ((cmp = range_cmp_size_addr(r1, r2)) != 0)
		return (cmp);

	return (range_cmp_size_port(r1, r2));
}

static void
range_log(bunyan_logger_t *restrict blog, bunyan_level_t level,
    const char *restrict msg, const range_t *restrict range)
{
	const struct sockaddr *start = &range->ra_startsa;
	const struct sockaddr *end = &range->ra_endsa;
	struct protoent *pe = NULL;
	const char *protostr = NULL;

	pe = getprotobynumber(range->ra_proto);
	protostr = (pe->p_name != NULL) ?
	    pe->p_name : enum_printf("%hhu", range->ra_proto);

	(void) getlog(level)(blog, msg,
	    BUNYAN_T_STRING, "protocol", protostr,
	    ss_bunyan(start), "start_addr", ss_addr(start),
	    BUNYAN_T_UINT32, "start_port", ss_port(start),
	    ss_bunyan(end), "end_addr", ss_addr(end),
	    BUNYAN_T_UINT32, "end_port", ss_port(end),
	    BUNYAN_T_END);
}

void
ts_log(bunyan_logger_t *restrict blog, bunyan_level_t level,
    const char *restrict msg, const ts_t *restrict ts)
{
	const void *aptr = ss_addr(&ts->ts_sa);
	struct protoent *pe = NULL;
	const char *portstr = NULL;
	const char *protostr = NULL;
	char astr[INET6_ADDRSTRLEN + 4] = { 0 }; /* +4 for '/xxx' */
	size_t plen = 0;
	uint32_t port = ss_port(&ts->ts_sa);

	if (inet_ntop(ts->ts_ss.ss_family, aptr, astr, sizeof (astr)) == NULL)
		return;

	if (ts->ts_prefix != ss_addrbits(&ts->ts_sa)) {
		char pfx[5] = { 0 };

		(void) snprintf(pfx, sizeof (pfx), "/%hhu", ts->ts_prefix);
		(void) strlcat(astr, pfx, sizeof (astr));
	}

	plen++;		/* '/' */

	if ((pe = getprotobynumber(ts->ts_proto)) != NULL)
		plen += strlen(pe->p_name);
	else
		plen += 3;	/* 3 digit value */


	portstr = (port == 0) ? "any" : enum_printf("%u", port);

	protostr = (pe != NULL) ?
	    pe->p_name : enum_printf("%hhu", ts->ts_proto);
	plen = strlen(portstr) + strlen(protostr) + 2; /* '/' + NUL */

	char pstr[plen];

	(void) snprintf(pstr, plen, "%s/%s", protostr, portstr);

	(void) getlog(level)(blog, msg,
	    BUNYAN_T_STRING, "ts", astr,
	    BUNYAN_T_STRING, "ts_port", pstr,
	    BUNYAN_T_END);
}
