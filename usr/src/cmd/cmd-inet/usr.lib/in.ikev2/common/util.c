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

#include <dlfcn.h>
#include <inttypes.h>
#include <port.h>
#include <string.h>
#include <sys/socket.h>
#include <thread.h>
#include <umem.h>
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
		INVALID("ss->ss_family");
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
		INVALID("ss->ss_family");
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
		INVALID("ss->ss_family");
		/*NOTREACHED*/
		return (0);
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
