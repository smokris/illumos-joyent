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
 * Copyright 2017 Joyent, Inc.
 */

#include <pthread.h>
#include <errno.h>
#include <port.h>
#include <string.h>
#include <sys/types.h>
#include <sys/debug.h>
#include <umem.h>
#include <stddef.h>
#include <locale.h>
#include <libuutil.h>
#include <ipsec_util.h>
#include <note.h>

#include "defs.h"
#include "timer.h"

typedef struct tevent_s {
	uu_list_node_t	node;

	hrtime_t	time;	/* When does the event go off */
	te_event_t	type;	/* Event type */

	tevent_cb_fn	fn;
	void		*arg;
} tevent_t;

static uu_list_pool_t 		*timer_pools;
static pthread_key_t		timer_key = PTHREAD_ONCE_KEY_NP;
static umem_cache_t		*evt_cache;

static int te_compare(const void *,const void *, void *);

static tevent_t *tevent_alloc(te_event_t, hrtime_t, tevent_cb_fn, void *);
static void timer_fini(void *);
static void tevent_free(tevent_t *);
static int evt_ctor(void *, void *, int);
static void evt_dtor(void *, void *);

void
ike_timer_init(void)
{

	uint32_t flg = 0;

#ifdef DEBUG
	flg |= UU_LIST_POOL_DEBUG;
#endif

	/* better be single threaded here! */
	ASSERT(pthread_self() == 1);

	timer_pools = uu_list_pool_create("timer_event_list",
	    sizeof (tevent_t), offsetof(tevent_t, node), te_compare,
	    flg);
	if (timer_pools == NULL)
		errx(EXIT_FAILURE, "Unable to allocate memory for timer event "
		    "lists");

	evt_cache = umem_cache_create("timer events", sizeof (tevent_t), 0,
	    evt_ctor, evt_dtor, NULL, NULL, NULL, 0);
	if (evt_cache == NULL)
		errx(EXIT_FAILURE, "Unable to allocate memory for timer event "
		    "entries");

	PTH(pthread_key_create_once_np(&timer_key, timer_fini));
}

/*
 * Called for each new worker thread
 */
void
ike_timer_thread_init(void)
{
	uu_list_t *list = NULL;
	uint32_t flg = UU_LIST_SORTED;

#ifdef DEBUG
	flg |= UU_LIST_DEBUG;
#endif

	if ((list = uu_list_create(timer_pools, NULL, flg)) == NULL)
		errx(EXIT_FAILURE, "Unable to allocate timer event lists");

	PTH(pthread_setspecific(timer_key, list));
}

static int dispatch_cb(void *, void *);

static inline uu_list_t *
timer_list(void)
{
	return (pthread_getspecific(timer_key));
}

static inline tevent_t *
timer_head(void)
{
	return (uu_list_first(timer_list()));
}

void
process_timer(timespec_t *next_time)
{
	tevent_t *te;
	hrtime_t now;

	ASSERT(timer_is_init);
	ASSERT(timer_thr_is_init);

	while (1) {
		/*
		 * since dispatching takes a non-zero amount of time, it is
		 * possible that by the time we're done dispatching, new
		 * events are due.  Eventually the list will either drain
		 * or we are left with an event far enough in the future
		 * that it's still pending after we're done dispatching
		 */
		now = gethrtime();

		if ((te = timer_head()) == NULL) {
			next_time->tv_sec = 0;
			next_time->tv_nsec = 0;
			return;
		}

		if (te->time > now) {
			/* no events to run */
			hrtime_t delta = te->time - now;

			next_time->tv_sec = NSEC2SEC(delta);
			next_time->tv_nsec = delta % (hrtime_t)NANOSEC;
			return;
		}

		/* dispatch timeouts */
		uu_list_walk(timer_list(), dispatch_cb, &now, UU_WALK_ROBUST);
	}
}

static int
dispatch_cb(void *elem, void *arg)
{
	tevent_t *te = (tevent_t *)elem;
	const hrtime_t *now = (const hrtime_t *)arg;

	if (te->time > *now)
		return (UU_WALK_DONE);

	te->fn(te->type, te->arg);
	uu_list_remove(timer_list(), elem);
	tevent_free(te);

	return (UU_WALK_NEXT);	
}

typedef struct cancel_arg_s {
	te_event_t	type;
	void		*arg;
	size_t		n;
} cancel_arg_t;

static int cancel_cb(void *, void *);

int
cancel_timeout(te_event_t type, void *arg)
{
	cancel_arg_t carg;

	ASSERT(timer_is_init);
	ASSERT(timer_thr_is_init);

	carg.type = type;
	carg.arg = arg;
	carg.n = 0;

	(void) uu_list_walk(timer_list(), cancel_cb, &carg, UU_WALK_ROBUST);
	return (carg.n);
}

static int
cancel_cb(void *elem, void *arg)
{
	tevent_t *te = (tevent_t *)elem;
	cancel_arg_t *carg = (cancel_arg_t *)arg;

	if (carg->type == TE_ANY ||
	    ((carg->type == te->type) && (carg->arg == te->arg))) {
		uu_list_remove(timer_list(), elem);
		tevent_free(te);
		carg->n++;
	}
	return (UU_WALK_NEXT);
}

boolean_t
schedule_timeout(te_event_t type, tevent_cb_fn fn, void *arg, hrtime_t val)
{
	uu_list_t *list = timer_list();
	tevent_t *te = tevent_alloc(type, val, fn, arg);
	uu_list_index_t idx;

	ASSERT(timer_is_init);
	ASSERT(timer_thr_is_init);

	VERIFY(te != TE_ANY);

	if ((te = tevent_alloc(type, val, fn, arg)) == NULL)
		return (B_FALSE);

	(void) uu_list_find(list, te, NULL, &idx);
	uu_list_insert(list, te, idx);
	return (B_TRUE);
}

static int
te_compare(const void *la, const void *ra, void *dummy)
{
	NOTE(ARGUNUSED(dummy))
	const tevent_t *l = (tevent_t *)la;
	const tevent_t *r = (tevent_t *)ra;

	if (l->time > r->time)
		return (1);
	if (l->time < r->time)
		return (-1);
	return (0);
}

static tevent_t *
tevent_alloc(te_event_t type, hrtime_t dur, tevent_cb_fn fn, void *arg)
{
	tevent_t *te = umem_cache_alloc(evt_cache, UMEM_DEFAULT);

	if (te == NULL)
		return (NULL);

	te->time = gethrtime() + dur;
	te->type = type;
	te->fn = fn;
	te->arg = arg;

	return (te);
}

static void
timer_fini(void *arg)
{
	uu_list_t *list = arg;

	(void) cancel_timeout(TE_ANY, NULL);
	uu_list_destroy(list);
}

static void
tevent_free(tevent_t *te)
{
	if (te == NULL)
		return;

	evt_dtor(te, NULL);
	evt_ctor(te, NULL, 0);
	umem_cache_free(evt_cache, te);
}

static int
evt_ctor(void *buf, void *cb, int flags)
{
	tevent_t *te = (tevent_t *)buf;

	(void) memset(te, 0, sizeof (*te));
	uu_list_node_init(buf, &te->node, timer_pools);
	return (0);
}

static void
evt_dtor(void *buf, void *cb)
{
	tevent_t *te = (tevent_t *)buf;

	uu_list_node_fini(buf, &te->node, timer_pools);
}
