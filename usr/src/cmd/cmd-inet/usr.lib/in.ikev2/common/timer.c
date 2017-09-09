/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */

/*
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright 2017 Jason King.
 * Copyright (c) 2017 Joyent, Inc.
 */

#include <errno.h>
#include <ipsec_util.h>
#include <locale.h>
#include <note.h>
#include <pthread.h>
#include <stddef.h>
#include <string.h>
#include <sys/debug.h>
#include <sys/types.h>
#include <ucontext.h>
#include <umem.h>

#include "defs.h"
#include "ilist.h"
#include "timer.h"
#include "worker.h"

struct tevent_s;

typedef struct tevent_s {
	list_node_t		te_node;

	hrtime_t		te_time;	/* When does the event go off */
	te_event_t		te_type;	/* Event type */
	tevent_cb_fn		te_fn;
	void			*te_arg;
} tevent_t;

static umem_cache_t	*evt_cache;

static int te_compare(const void *, const void *, void *);

static tevent_t *tevent_alloc(te_event_t, hrtime_t, tevent_cb_fn, void *);
static void tevent_free(tevent_t *);
static int evt_ctor(void *, void *, int);
static const char *te_str(te_event_t);
static void tevent_log(bunyan_logger_t *restrict, bunyan_level_t,
    const char *restrict, const tevent_t *restrict);

void
ike_timer_init(void)
{
	/* better be single threaded here! */
	ASSERT(pthread_self() == 1);

	evt_cache = umem_cache_create("timer events", sizeof (tevent_t), 0,
	    evt_ctor, NULL, NULL, NULL, NULL, 0);
	if (evt_cache == NULL)
		errx(EXIT_FAILURE, "Unable to allocate memory for timer event "
		    "entries");
}

void
ike_timer_worker_init(worker_t *w)
{
	ilist_create(&w->w_timers, sizeof (tevent_t),
	    offsetof(tevent_t, te_node));
}

void
ike_timer_worker_fini(void)
{
	VERIFY(IS_WORKER);
	ilist_destroy(&worker->w_timers);
}

void
process_timer(timespec_t **tsp)
{
	VERIFY(IS_WORKER);

	ilist_t		*events = &worker->w_timers;
	tevent_t	*te = NULL;
	hrtime_t	now = gethrtime();
	hrtime_t	delta = 0;
	size_t		dispcount = 0;

	(void) bunyan_trace(worker->w_log, "Checking for timeout events",
	    BUNYAN_T_END);

	/*
	 * Only look at events that expired when we started. It is
	 * possible more events may be ready by the time we finish.
	 * If that happens, they will be processed the next time
	 * we are called so that other things can proceed in the
	 * current thread.
	 *
	 * This list is sorted in ascending time, so we can stop
	 * either when it's empty or we see an event later scheduled
	 * later than 'now'.
	 */
	while ((te = ilist_head(events)) != NULL && te->te_time < now) {
		(void) ilist_remove_head(events);

		tevent_log(worker->w_log, BUNYAN_L_TRACE,
		    "Dispatching timer event", te);
		te->te_fn(te->te_type, te->te_arg);
		dispcount++;

		tevent_free(te);
	}

	if (te != NULL) {
		timespec_t ts = { 0 };

		if ((delta = te->te_time - gethrtime()) < 0)
			delta = 0;

		(*tsp)->tv_sec = NSEC2SEC(delta);
		(*tsp)->tv_nsec = delta % NANOSEC;
	} else {
		*tsp = NULL;
	}

	(void) bunyan_trace(worker->w_log, "Finished dispatching events",
	    BUNYAN_T_UINT32, "dispcount", (uint32_t)dispcount,
	    BUNYAN_T_UINT32, "numqueued", (uint32_t)ilist_size(events),
	    BUNYAN_T_UINT64, "next_evt_ms", NSEC2MSEC(delta),
	    BUNYAN_T_END);
}

size_t
cancel_timeout(te_event_t type, void *restrict arg, bunyan_logger_t *l)
{
	VERIFY(IS_WORKER);

	ilist_t *events = &worker->w_timers;
	tevent_t *te = ilist_head(events);
	size_t count = 0;

	(void) bunyan_trace(l, "Cancelling timeouts",
	    BUNYAN_T_STRING, "event", te_str(type),
	    BUNYAN_T_POINTER, "arg", arg, BUNYAN_T_END);

	while (te != NULL) {
		tevent_t *tnext = ilist_next(events, te);

		if ((te->te_arg == arg || arg == NULL) &&
		    (te->te_type == type || te->te_type == TE_ANY)) {
			tevent_log(l, BUNYAN_L_DEBUG, "Cancelled timeout", te);

			ilist_remove(events, te);
			count++;
			tevent_free(te);
		}

		te = tnext;
	}

	return (count);
}

boolean_t
schedule_timeout(te_event_t type, tevent_cb_fn fn, void *arg, hrtime_t val,
    bunyan_logger_t *l)
{
	VERIFY(IS_WORKER);

	ilist_t *events = &worker->w_timers;
	tevent_t *te = tevent_alloc(type, val, fn, arg);
	tevent_t *tnode = ilist_head(events);

	VERIFY3S(type, !=, TE_ANY);

	if (te == NULL)
		return (B_FALSE);

	while (tnode != NULL && tnode->te_time < te->te_time)
		tnode = ilist_next(events, tnode);

	ilist_insert_before(events, tnode, te);
	tevent_log(l, BUNYAN_L_TRACE, "Created new timeout", te);
	return (B_TRUE);
}

static tevent_t *
tevent_alloc(te_event_t type, hrtime_t dur, tevent_cb_fn fn, void *arg)
{
	tevent_t *te = umem_cache_alloc(evt_cache, UMEM_DEFAULT);

	if (te == NULL)
		return (NULL);

	te->te_time = gethrtime() + dur;
	te->te_type = type;
	te->te_fn = fn;
	te->te_arg = arg;

	return (te);
}

static void
tevent_free(tevent_t *te)
{
	if (te == NULL)
		return;

	evt_ctor(te, NULL, 0);
	umem_cache_free(evt_cache, te);
}

static void
tevent_log(bunyan_logger_t *restrict l, bunyan_level_t level,
    const char *restrict msg, const tevent_t *restrict te)
{
	hrtime_t now = gethrtime();
	uint64_t when = NSEC2MSEC(te->te_time - now);

	/* XXX: Get the function name, would dladdr(3C) be better? */
	(void) getlog(level)(l, msg,
	    BUNYAN_T_STRING, "event", te_str(te->te_type),
	    BUNYAN_T_UINT32, "event num", (uint32_t)te->te_type,
	    BUNYAN_T_UINT64, "ms", when,
	    BUNYAN_T_POINTER, "fn", te->te_fn,
	    BUNYAN_T_STRING, "fnname", symstr(te->te_fn),
	    BUNYAN_T_POINTER, "arg", te->te_arg,
	    BUNYAN_T_END);
}

static int
evt_ctor(void *buf, void *cb, int flags)
{
	tevent_t *te = buf;

	(void) memset(te, 0, sizeof (*te));
	list_link_init(&te->te_node);
	return (0);
}

static const char *
te_str(te_event_t te)
{
#define	STR(x) case x: return (#x)
	switch (te) {
	STR(TE_ANY);
	STR(TE_P1_SA_EXPIRE);
	STR(TE_TRANSMIT);
	STR(TE_PFKEY);
	}
	return ("UNKNOWN");
}
