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
	char	afstr[6];	/* ushort_t */
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

	PTH(thr_keycreate_once(&strbuf_key, buf_fini));
	PTH(thr_getspecific(strbuf_key, (void **)&buf));
	if (buf == NULL) {
		buf = umem_alloc(sizeof (*buf), UMEM_DEFAULT);
		if (buf == NULL)
			NOMEM;
		PTH(thr_setspecific(strbuf_key, buf));
	}
	return (buf);
}

const char *
symstr(void *addr)
{
	struct strbuf_s *buf = getbuf();
	Dl_info_t dlinfo = { 0 };

	if (dladdr(addr, &dlinfo) == 0) {
		(void) snprintf(buf->symstr, sizeof (buf->symstr), "0x%p",
		    addr);
	} else {
		(void) strlcpy(buf->symstr, dlinfo.dli_sname,
		    sizeof (buf->symstr));
	}

	return (buf->symstr);
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

	(void) snprintf(buf->evtstr, sizeof (buf->evtstr), "%d", evt);
	return (buf->evtstr);
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

	struct strbuf_s *buf = getbuf();

	(void) snprintf(buf->portstr, sizeof (buf->portstr), "%hhu", src);
	return (buf->portstr);
}
#undef STR

/* inline parking lot */
extern uint32_t ss_port(const struct sockaddr_storage *);
extern const void *ss_addr(const struct sockaddr_storage *);
extern int ss_bunyan(const struct sockaddr_storage *);

extern void ilist_create(ilist_t *, size_t, size_t);
extern void ilist_destroy(ilist_t *);
extern void ilist_insert_after(ilist_t *, void *, void *);
extern void ilist_insert_before(ilist_t *, void *, void *);
extern void ilist_insert_head(ilist_t *, void *);
extern void ilist_insert_tail(ilist_t *, void *);
extern void ilist_remove(ilist_t *, void *);
extern void *ilist_remove_head(ilist_t *);
extern void *ilist_remove_tail(ilist_t *);
extern void *ilist_head(ilist_t *);
extern void *ilist_tail(ilist_t *);
extern void *ilist_next(ilist_t *, void *);
extern void *ilist_prev(ilist_t *, void *);
extern void ilist_move_tail(ilist_t *, ilist_t *);
extern int ilist_is_empty(ilist_t *);
extern size_t ilist_size(ilist_t *);
