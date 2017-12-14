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
#include <stdarg.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <thread.h>
#include <umem.h>
#include "config.h"
#include "ike.h"
#include "defs.h"

#define	ENUMBUF_NUM	8	/* Num of enumbufs that can be used at a time */
#define	ENUMBUF_SZ	11	/* Large enough to hold a 32-bit number + NUL */

struct enumbuf_s {
	uint	eb_idx;
	char	eb_buf[ENUMBUF_NUM][ENUMBUF_SZ];
};

/* XXX: Probably should change this to dynamic allocation */
__thread struct enumbuf_s enumbuf;

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

const char *
enum_printf(const char *fmt, ...)
{
	char *buf = enumbuf.eb_buf[enumbuf.eb_idx++];
	va_list ap;

	enumbuf.eb_idx %= ENUMBUF_NUM;

	va_start(ap, fmt);
	(void) vsnprintf(buf, ENUMBUF_SZ, fmt, ap);
	va_end(ap);

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

	return (enum_printf("%hhu", af));
}

#define	STR(x) case x: return (#x)
const char *
event_str(event_t evt)
{
	switch (evt) {
	STR(EVENT_NONE);
	STR(EVENT_SIGNAL);
	}

	return (enum_printf("%d", evt));
}

const char *
port_source_str(ushort_t src)
{
	switch (src) {
	STR(PORT_SOURCE_AIO);
	STR(PORT_SOURCE_FD);
	STR(PORT_SOURCE_MQ);
	STR(PORT_SOURCE_TIMER);
	STR(PORT_SOURCE_USER);
	STR(PORT_SOURCE_ALERT);
	STR(PORT_SOURCE_FILE);
	}

	return (enum_printf("%hhu", src));
}
#undef STR

int
ss_bunyan(const struct sockaddr *sa)
{
	switch (sa->sa_family) {
	case AF_INET:
		return (BUNYAN_T_IP);
	case AF_INET6:
		return (BUNYAN_T_IP6);
	default:
		INVALID(sa->sa_family);
		/*NOTREACHED*/
		return (0);
	}
}

/* Returns uint32_t to avoid lots of casts w/ libbunyan */
uint32_t
ss_port(const struct sockaddr *sa)
{
	const sockaddr_u_t sau = { .sau_sa = (struct sockaddr *)sa };

	switch (sa->sa_family) {
	case AF_INET:
		return (ntohs(sau.sau_sin->sin_port));
	case AF_INET6:
		return (ntohs(sau.sau_sin6->sin6_port));
	default:
		INVALID(sa->sa_family);
		/*NOTREACHED*/
		return (0);
	}
}

const void *
ss_addr(const struct sockaddr *sa)
{
	sockaddr_u_t sau = { .sau_sa = (struct sockaddr *)sa };

	switch (sa->sa_family) {
	case AF_INET:
		return (&sau.sau_sin->sin_addr);
	case AF_INET6:
		return (&sau.sau_sin6->sin6_addr);
	default:
		INVALID(sa->sa_family);
		/*NOTREACHED*/
		return (0);
	}
}

size_t
ss_addrlen(const struct sockaddr *sa)
{
	switch (sa->sa_family) {
	case AF_INET:
		return (sizeof (in_addr_t));
	case AF_INET6:
		return (sizeof (in6_addr_t));
	default:
		INVALID(sa->sa_family);
		/*NOTREACHED*/
		return (0);
	}
}

uint8_t
ss_addrbits(const struct sockaddr *sa)
{
	switch (sa->sa_family) {
	case AF_INET:
		return (IP_ABITS);
	case AF_INET6:
		return (IPV6_ABITS);
	default:
		INVALID(sa->sa_family);
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

	if (spi != 0)
		(void) snprintf(buf, sizeof (buf), "0x%016" PRIX64, spi);
	else
		(void) strlcpy(buf, "0x0", sizeof (buf));

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
key_add_addr(const char *name, const struct sockaddr *addr)
{
	const void *ptr = NULL;
	int af = addr->sa_family;
	uint32_t port = 0;
	char addrbuf[INET6_ADDRSTRLEN];

	ptr = ss_addr(addr);
	port = ss_port(addr);

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
		(void) snprintf(buf, sizeof (buf), "%s:%" PRIu32, addrbuf,
		    port);
		break;
	case AF_INET6:
		(void) snprintf(buf, sizeof (buf), "[%s]:%" PRIu32, addrbuf,
		    port);
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
sockaddr_copy(const struct sockaddr *src, struct sockaddr_storage *dst,
    boolean_t copy_port)
{
	bcopy(src, dst, sizeof (*src));

	/* Take advantage of port being at the same offset */
	if (!copy_port)
		((struct sockaddr_in *)dst)->sin_port = 0;
}

/*
 * Compare two addresses.  NOTE: This only looks at the af + address, and
 * does NOT look at the port.
 */
int
sockaddr_cmp(const struct sockaddr *l, const struct sockaddr *r)
{
	const uint8_t *lp = ss_addr(l);
	const uint8_t *rp = ss_addr(r);
	size_t addrlen = ss_addrlen(l);
	int cmp = 0;

	if (l->sa_family < r->sa_family)
		return (-1);
	if (l->sa_family > r->sa_family)
		return (1);

	return (memcmp(lp, rp, addrlen));
}

boolean_t
addr_is_zero(const struct sockaddr *addr)
{
	const uint8_t *p = ss_addr(addr);
	size_t len = ss_addrlen(addr);

	for (size_t i = 0; i < len; i++) {
		if (p[i] != 0)
			return (B_FALSE);
	}

	if (ss_port(addr) != 0)
		return (B_FALSE);

	return (B_TRUE);
}

/* XXX: Might these (possibly renamed) be better moved to libumem? */
char *
ustrdup(const char *src, int umflag)
{
	size_t len = strlen(src) + 1;
	char *str = umem_alloc(len, umflag);

	if (str != NULL)
		(void) strlcpy(str, src, len);

	return (str);
}

void
ustrfree(char *str)
{
	if (str == NULL)
		return;

	size_t len = strlen(str) + 1;

	umem_free(str, len);
}
