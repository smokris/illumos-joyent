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

#include <arpa/inet.h>
#include <dlfcn.h>
#include <inet/ip.h>	/* for IP[V6]_ABITS */
#include <inttypes.h>
#include <libinetutil.h>
#include <netinet/in.h>
#include <port.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <thread.h>
#include <umem.h>
#include "config.h"
#include "ike.h"
#include "defs.h"
#include "ilist.h"

struct strbuf_s {
	char	symstr[128];
	char	portstr[6];	/* Size of ushort_t as string + NUL */
	char	afstr[6];	/* Same as portstr */
	char	evtstr[12];	/* Size of int (enum) + NUL */
};

static thread_key_t strbuf_key = THR_ONCE_KEY;

/* Pick a bunyan log function based on level */
bunyan_logfn_t
getlog(bunyan_level_t level)
{
	switch (level) {
	case BUNYAN_L_TRACE:
		return (bunyan_trace);
	case BUNYAN_L_DEBUG:
		return (bunyan_debug);
	case BUNYAN_L_INFO:
		return (bunyan_info);
	case BUNYAN_L_WARN:
		return (bunyan_warn);
	case BUNYAN_L_ERROR:
		return (bunyan_error);
	case BUNYAN_L_FATAL:
		return (bunyan_fatal);
	}

	return (NULL);
}

static void
buf_fini(void *arg)
{
	struct strbuf_s *buf = arg;

	umem_free(buf, sizeof (*buf));
}

static struct strbuf_s *
getbuf(void)
{
	struct strbuf_s *buf = NULL;

	VERIFY0(thr_keycreate_once(&strbuf_key, buf_fini));
	VERIFY0(thr_getspecific(strbuf_key, (void **)&buf));
	if (buf == NULL) {
		buf = umem_alloc(sizeof (*buf), UMEM_DEFAULT);
		if (buf == NULL)
			return (NULL);
		VERIFY0(thr_setspecific(strbuf_key, buf));
	}
	return (buf);
}

const char *
symstr(void *addr, char *buf, size_t buflen)
{
	Dl_info_t dlinfo = { 0 };

	if (dladdr(addr, &dlinfo) != 0)
		return (dlinfo.dli_sname);

	(void) snprintf(buf, buflen, "0x%p", addr);
	return (buf);
}

const char *
afstr(sa_family_t af)
{
	switch (af) {
	case AF_INET:
		return ("AF_INET");
	case AF_INET6:
		return ("AF_INET6");
	}

	struct strbuf_s *buf = getbuf();

	if (buf == NULL)
		return ("");

	(void) snprintf(buf->afstr, sizeof (buf->afstr), "%hhu", af);
	return (buf->afstr);
}

#define	STR(x) case x: return (#x)
const char *
event_str(event_t evt)
{
	switch (evt) {
	STR(EVENT_NONE);
	STR(EVENT_SIGNAL);
	}

	struct strbuf_s *buf = getbuf();

	if (buf == NULL)
		return ("");

	(void) snprintf(buf->evtstr, sizeof (buf->evtstr), "%d", evt);
	return (buf->evtstr);
}
#undef STR

#define	STR(x, s, l) case x: (void) strlcpy(s, #x, l); return (s)
char *
port_source_str(ushort_t src, char *buf, size_t buflen)
{
	switch (src) {
	STR(PORT_SOURCE_AIO, buf, buflen);
	STR(PORT_SOURCE_FD, buf, buflen);
	STR(PORT_SOURCE_MQ, buf, buflen);
	STR(PORT_SOURCE_TIMER, buf, buflen);
	STR(PORT_SOURCE_USER, buf, buflen);
	STR(PORT_SOURCE_ALERT, buf, buflen);
	STR(PORT_SOURCE_FILE, buf, buflen);
	}

	(void) snprintf(buf, buflen, "%hhu", src);
	return (buf);
}
#undef STR

int
ss_bunyan(const struct sockaddr_storage *ss)
{
	switch (ss->ss_family) {
	case AF_INET:
		return (BUNYAN_T_IP);
	case AF_INET6:
		return (BUNYAN_T_IP6);
	default:
		INVALID(ss->ss_family);
		/*NOTREACHED*/
		return (0);
	}
}

/* Returns uint32_t to avoid lots of casts w/ libbunyan */
uint32_t
ss_port(const struct sockaddr_storage *ss)
{
	sockaddr_u_t sau = { .sau_ss = (struct sockaddr_storage *)ss };

	switch (ss->ss_family) {
	case AF_INET:
		return (ntohs(sau.sau_sin->sin_port));
	case AF_INET6:
		return (ntohs(sau.sau_sin6->sin6_port));
	default:
		INVALID(ss->ss_family);
		/*NOTREACHED*/
		return (0);
	}
}

const void *
ss_addr(const struct sockaddr_storage *ss)
{
	sockaddr_u_t sau = { .sau_ss = (struct sockaddr_storage *)ss };

	switch (ss->ss_family) {
	case AF_INET:
		return (&sau.sau_sin->sin_addr);
	case AF_INET6:
		return (&sau.sau_sin6->sin6_addr);
	default:
		INVALID(ss->ss_family);
		/*NOTREACHED*/
		return (0);
	}
}

size_t
ss_addrlen(const struct sockaddr_storage *ss)
{
	switch (ss->ss_family) {
	case AF_INET:
		return (sizeof (in_addr_t));
	case AF_INET6:
		return (sizeof (in6_addr_t));
	default:
		INVALID(ss->ss_family);
		/*NOTREACHED*/
		return (0);
	}
}

uint8_t
ss_addrbits(const struct sockaddr_storage *ss)
{
	switch (ss->ss_family) {
	case AF_INET:
		return (IP_ABITS);
	case AF_INET6:
		return (IPV6_ABITS);
	default:
		INVALID(ss->ss_family);
		/*NOTREACHED*/
		return (0);
	}
}

static const char *log_keys[] = {
	LOG_KEY_ERRMSG,
	LOG_KEY_ERRNO,
	LOG_KEY_FILE,
	LOG_KEY_FUNC,
	LOG_KEY_LINE,
	LOG_KEY_I2SA,
	LOG_KEY_LADDR,
	LOG_KEY_RADDR,
	LOG_KEY_LSPI,
	LOG_KEY_RSPI,
	LOG_KEY_INITIATOR,
	LOG_KEY_REQ,
	LOG_KEY_RESP,
	LOG_KEY_VERSION,
	LOG_KEY_MSGID,
	LOG_KEY_EXCHTYPE,
	LOG_KEY_LOCAL_ID,
	LOG_KEY_LOCAL_ID_TYPE,
	LOG_KEY_REMOTE_ID,
	LOG_KEY_REMOTE_ID_TYPE,
};

void
log_reset_keys(void)
{
	for (size_t i = 0; i < ARRAY_SIZE(log_keys); i++)
		(void) bunyan_key_remove(log, log_keys[i]);
}

void
key_add_ike_spi(const char *name, uint64_t spi)
{
	char buf[19] = { 0 };	/* 0x + 64bit hex + NUL */

	(void) snprintf(buf, sizeof (buf), "0x%016" PRIX64, spi);
	(void) bunyan_key_add(log, BUNYAN_T_STRING, name, buf, BUNYAN_T_END);
}

void
key_add_id(const char *name, const char *typename, config_id_t *id)
{
	bunyan_type_t btype = BUNYAN_T_END;

	switch (id->cid_type) {
	case CFG_AUTH_ID_DNS:
	case CFG_AUTH_ID_EMAIL:
		btype = BUNYAN_T_STRING;
		break;
	case CFG_AUTH_ID_IPV4:
	case CFG_AUTH_ID_IPV4_PREFIX:
	case CFG_AUTH_ID_IPV4_RANGE:
		btype = BUNYAN_T_IP;
		break;
	case CFG_AUTH_ID_IPV6:
	case CFG_AUTH_ID_IPV6_PREFIX:
	case CFG_AUTH_ID_IPV6_RANGE:
		btype = BUNYAN_T_IP6;
		break;
	case CFG_AUTH_ID_DN:
	case CFG_AUTH_ID_GN:
		/*NOTYET*/
		INVALID(id->cid_type);
		break;
	}

	(void) bunyan_key_add(log,
	    BUNYAN_T_STRING, typename, config_id_type_str(id->cid_type),
	    btype, name, id->cid_data,
	    BUNYAN_T_END);
}

void
key_add_addr(const char *name, struct sockaddr_storage *addr)
{
	void *ptr = NULL;
	sockaddr_u_t su = { .sau_ss = addr };
	int af = addr->ss_family;
	uint16_t port = 0;
	char addrbuf[INET6_ADDRSTRLEN];

	switch (af) {
	case AF_INET:
		ptr = &su.sau_sin->sin_addr;
		port = ntohs(su.sau_sin->sin_port);
		break;
	case AF_INET6:
		ptr = &su.sau_sin6->sin6_addr;
		port = ntohs(su.sau_sin->sin_port);
		break;
	default:
		INVALID(af);
	}

	if (inet_ntop(af, ptr, addrbuf, sizeof (addrbuf)) == NULL)
		return;

	if (port == 0) {
		(void) bunyan_key_add(log,
		    BUNYAN_T_STRING, name, addrbuf, BUNYAN_T_END);
		return;
	}

	/* address + [ + ] + / + 16-bit port */
	char buf[INET6_ADDRSTRLEN + 8];

	switch (af) {
	case AF_INET:
		(void) snprintf(buf, sizeof (buf), "%s:%hu", addrbuf, port);
		break;
	case AF_INET6:
		(void) snprintf(buf, sizeof (buf), "[%s]:%hu", addrbuf, port);
		break;
	default:
		INVALID(af);
	}

	(void) bunyan_key_add(log, BUNYAN_T_STRING, name, buf, BUNYAN_T_END);
}

void
key_add_ike_version(const char *name, uint8_t version)
{
	char buf[6] = { 0 }; /* NN.NN + NUL */

	(void) snprintf(buf, sizeof (buf), "%hhu.%hhu", IKE_GET_MAJORV(version),
	    IKE_GET_MINORV(version));
	(void) bunyan_key_add(log, BUNYAN_T_STRING, name, buf, BUNYAN_T_END);
}

char *
writehex(uint8_t *data, size_t datalen, char *sep, char *buf, size_t buflen)
{
	if (datalen == 0) {
		if (buflen > 0)
			buf[0] = '\0';
		return (buf);
	}

	size_t seplen = 0;
	size_t total = 0;

	if (sep == NULL)
		sep = "";
	else
		seplen = strlen(sep);

	for (size_t i = 0; i < datalen; i++) {
		size_t len = (i > 0) ? seplen + 2 : 2;

		/*
		 * Check if next byte (w/ separator) will fit to prevent
		 * partial writing of byte
		 */
		if (len + 1 > buflen)
			break;

		total += snprintf(buf + total, buflen - total, "%s%02hhx",
		    (i > 0) ? sep : "", data[i]);
	}

	return (buf);
}

void
net_to_range(const struct sockaddr_storage *addr, uint8_t prefixlen,
    struct sockaddr_storage *start, struct sockaddr_storage *end)
{
	const uint8_t *addrp = NULL;
	uint8_t *maskp = NULL, *startp = NULL, *endp = NULL;
	struct sockaddr_storage mask = { 0 };
	size_t len = 0;

	VERIFY0(plen2mask(prefixlen, addr->ss_family,
	    (struct sockaddr *)&mask));

	addrp = ss_addr(addr);
	maskp = (uint8_t *)ss_addr(&mask);
	len = ss_addrlen(addr);

	if (start != NULL) {
		start->ss_family = addr->ss_family;
		startp = (uint8_t *)ss_addr(start);
	}
	if (end != NULL) {
		end->ss_family = addr->ss_family;
		endp = (uint8_t *)ss_addr(end);
	}

	for (size_t i = 0; i < len; i++) {
		if (startp != NULL)
			startp[i] = addrp[i] & maskp[i];
		if (endp != NULL)
			endp[i] = addrp[i] | ~maskp[i];
	}

	/*
	 * SADB addresses don't have the concept of a port range, either the
	 * port is 0 (to imply any port) or it is a specific port.
	 */

	/* Take advantage of port at the same offset for IPv4/IPv6 */
	uint16_t addr_port = ss_port(addr);
	if (addr_port == 0) {
		((struct sockaddr_in *)start)->sin_port = 0;
		((struct sockaddr_in *)end)->sin_port = UINT16_MAX;
	} else {
		((struct sockaddr_in *)start)->sin_port = addr_port;
		((struct sockaddr_in *)end)->sin_port = addr_port;
	}
}

void
range_intersection(struct sockaddr_storage *restrict res_start,
    struct sockaddr_storage *restrict res_end,
    const struct sockaddr_storage *restrict start1,
    const struct sockaddr_storage *restrict end1,
    const struct sockaddr_storage *restrict start2,
    const struct sockaddr_storage *restrict end2)
{
	const uint8_t *s1, *s2, *e1, *e2;
	uint8_t *rs, *re;
	size_t len = 0;
	offset_t off = 0;

	VERIFY3U(start1->ss_family, ==, end1->ss_family);
	VERIFY3U(start2->ss_family, ==, end2->ss_family);
	VERIFY3U(start1->ss_family, ==, start2->ss_family);

	switch (start1->ss_family) {
	case AF_INET:
		len = sizeof (in_addr_t);
		off = offsetof(struct sockaddr_in, sin_addr);
		break;
	case AF_INET6:
		len = sizeof (in6_addr_t);
		off = offsetof(struct sockaddr_in6, sin6_addr);
		break;
	default:
		INVALID(start1->ss_family);
	}

	s1 = (const uint8_t *)start1 + off;
	e1 = (const uint8_t *)end1 + off;
	s2 = (const uint8_t *)start2 + off;
	e2 = (const uint8_t *)end2 + off;
	rs = (uint8_t *)res_start + off;
	re = (uint8_t *)res_end + off;

	bzero(rs, len);
	bzero(re, len);

	for (size_t i = 0; i < len; i++) {
		rs[i] = MAX(s1[i], s2[i]);
		re[i] = MIN(e1[i], e2[i]);
	}

	/* If end < start, there is no intersection, so zero out */
	for (size_t i = 0; i < len; i++) {
		if (re[i] < rs[i]) {
			bzero(rs, len);
			bzero(re, len);
			goto done;
		}
	}

	/* Take advantage of port at the same offset for IPv4/IPv6 */
	uint16_t *res_startp = &((struct sockaddr_in *)res_start)->sin_port;
	uint16_t *res_endp = &((struct sockaddr_in *)res_end)->sin_port;
	uint16_t s1port = ntohs(((struct sockaddr_in *)start1)->sin_port);
	uint16_t e1port = ntohs(((struct sockaddr_in *)end1)->sin_port);
	uint16_t s2port = ntohs(((struct sockaddr_in *)start2)->sin_port);
	uint16_t e2port = ntohs(((struct sockaddr_in *)end2)->sin_port);

	*res_startp = htons(MAX(s1port, s2port));
	*res_endp = htons(MIN(e1port, e2port));

	if (ntohs(*res_startp) > ntohs(*res_endp)) {
		bzero(rs, len);
		bzero(re, len);
	}

done:
	res_start->ss_family = res_end->ss_family = start1->ss_family;
}

int
range_cmp_size(const struct sockaddr_storage *l_start,
    const struct sockaddr_storage *l_end,
    const struct sockaddr_storage *r_start,
    const struct sockaddr_storage *r_end)
{
	const uint8_t *lsp, *lep, *rsp, *rep;
	size_t len = 0;
	offset_t off = 0;

	VERIFY3U(l_start->ss_family, ==, l_end->ss_family);
	VERIFY3U(r_start->ss_family, ==, r_end->ss_family);
	VERIFY3U(l_start->ss_family, ==, r_start->ss_family);

	switch (l_start->ss_family) {
	case AF_INET:
		len = sizeof (in_addr_t);
		off = offsetof(struct sockaddr_in, sin_addr);
		break;
	case AF_INET6:
		len = sizeof (in6_addr_t);
		off = offsetof(struct sockaddr_in6, sin6_addr);
		break;
	default:
		INVALID(addr->ss_family);
	}

	lsp = (const uint8_t *)l_start + off;
	lep = (const uint8_t *)l_end + off;
	rsp = (const uint8_t *)r_start + off;
	rep = (const uint8_t *)r_end + off;

	for (size_t i = 0; i < len; i++) {
		VERIFY3U(lep[i], >=, lsp[i]);
		VERIFY3U(rep[i], >=, rsp[i]);

		uint8_t l_diff = lep[i] - lsp[i];
		uint8_t r_diff = rep[i] - rep[i];

		if (l_diff > r_diff)
			return (-1);
		if (l_diff < r_diff)
			return (1);
	}

	return (0);
}

/*
 * Adjust end if necessary so that [start, end] can be expressed as
 * start/mask
 */
void
range_clamp(struct sockaddr_storage *restrict start,
    struct sockaddr_storage *restrict end)
{
}

boolean_t
range_is_zero(const struct sockaddr_storage *start,
    const struct sockaddr_storage *end)
{
	const uint8_t *sp, *ep;
	size_t len = 0;
	offset_t off = 0;

	VERIFY3U(start->ss_family, ==, end->ss_family);

	switch (start->ss_family) {
	case AF_INET:
		len = sizeof (in_addr_t);
		off = offsetof(struct sockaddr_in, sin_addr);
		break;
	case AF_INET6:
		len = sizeof (in6_addr_t);
		off = offsetof(struct sockaddr_in6, sin6_addr);
		break;
	default:
		INVALID(addr->ss_family);
	}

	sp = (const uint8_t *)start + off;
	ep = (const uint8_t *)end + off;

	for (size_t i = 0; i < len; i++) {
		if (sp[i] != 0 || ep[i] != 0)
			return (B_FALSE);
	}
	return (B_TRUE);
}

boolean_t
range_in_net(const struct sockaddr_storage *net, uint8_t prefixlen,
    const struct sockaddr_storage *start, const struct sockaddr_storage *end)
{
	const uint8_t *ns, *ne, *rs, *re;
	struct sockaddr_storage net_start = { 0 };
	struct sockaddr_storage net_end = { 0 };
	size_t len = 0;
	offset_t off = 0;

	VERIFY3U(net->ss_family, ==, start->ss_family);
	VERIFY3U(start->ss_family, ==, end->ss_family);

	net_to_range(net, prefixlen, &net_start, &net_end);

	switch (start->ss_family) {
	case AF_INET:
		len = sizeof (in_addr_t);
		off = offsetof(struct sockaddr_in, sin_addr);
		break;
	case AF_INET6:
		len = sizeof (in6_addr_t);
		off = offsetof(struct sockaddr_in6, sin6_addr);
		break;
	default:
		INVALID(addr->ss_family);
	}

	ns = (const uint8_t *)&net_start + off;
	ne = (const uint8_t *)&net_end + off;
	rs = (const uint8_t *)start + off;
	re = (const uint8_t *)end + off;

	for (size_t i = 0; i < len; i++) {
		if (ns[i] > rs[i] || ne[i] < rs[i])
			return (B_FALSE);
	}

	return (B_TRUE);
}

void
sockaddr_copy(const struct sockaddr_storage *src, struct sockaddr_storage *dst,
    boolean_t copy_port)
{
	sockaddr_u_t du = { .sau_ss = dst };

	(void) memcpy(dst, src, sizeof (struct sockaddr_storage));
	if (!copy_port) {
		switch (src->ss_family) {
		case AF_INET:
			du.sau_sin->sin_port = 0;
			break;
		case AF_INET6:
			du.sau_sin6->sin6_port = 0;
			break;
		INVALID(src->ss_family);
		}
	}
}

/* inline parking lot */
extern inline void ilist_create(ilist_t *, size_t, size_t);
extern inline void ilist_destroy(ilist_t *);
extern inline void ilist_insert_after(ilist_t *, void *, void *);
extern inline void ilist_insert_before(ilist_t *, void *, void *);
extern inline void ilist_insert_head(ilist_t *, void *);
extern inline void ilist_insert_tail(ilist_t *, void *);
extern inline void ilist_remove(ilist_t *, void *);
extern inline void *ilist_remove_head(ilist_t *);
extern inline void *ilist_remove_tail(ilist_t *);
extern inline void *ilist_head(ilist_t *);
extern inline void *ilist_tail(ilist_t *);
extern inline void *ilist_next(ilist_t *, void *);
extern inline void *ilist_prev(ilist_t *, void *);
extern inline void ilist_move_tail(ilist_t *, ilist_t *);
extern inline int ilist_is_empty(ilist_t *);
extern inline size_t ilist_size(ilist_t *);
