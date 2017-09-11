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
#include <err.h>
#include <thread.h>
#include <string.h>
#include <synch.h>
#include <sys/debug.h>
#include <sys/list.h>
#include <time.h>
#include <umem.h>
#include "defs.h"
#include "ikev2_proto.h"
#include "ikev2_sa.h"
#include "pkcs11.h"
#include "pkt.h"
#include "timer.h"
#include "worker.h"

/*
 * Workers handle all the heavy lifting (including crypto) in in.ikev2d.
 * An event port (port) waits for packets from our UDP sockets (IPv4, IPv6,
 * and IPv4 NAT) as well as for pfkey messages.  For UDP messages, some
 * minimal sanity checks (such as verifying payload lengths) occur, an IKEv2
 * SA is located for the message (or if appropriate, a larval IKEv2 SA is
 * created), and then the packet is handed off to a worker thread to do the
 * rest of the work.  Currently dispatching works by merely taking the local
 * IKEv2 SA SPI modulo the number of worker threads.  Since we control
 * the local IKEv2 SA SPI value (and is randomly chosen), this should prevent
 * a single connection from saturating the process by making all IKEv2
 * processing for a given IKEv2 SA occur all within the same thread (it also
 * simplifies some of the synchronization requirements for manipulating
 * IKEv2 SAs).  Obviously this does not address a DOS with spoofed source
 * addresses.  Cookies are used to mitigate such threats (to the extent it
 * can by dropping inbound packets without valid cookie values when enabled).
 */

#define	WQ_EMPTY(_wq) ((_wq)->wq_start == (_wq)->wq_end)
#define	WQ_FULL(_wq) ((((_wq)->wq_end + 1) % queuelen) == (_wq)->wq_start)

__thread worker_t *worker = NULL;

/* The following group of variables are protected by worker_lock */
static rwlock_t worker_lock = DEFAULTRWLOCK;
size_t		nworkers;
static worker_t	**workers;
static size_t	workers_alloc;
static size_t	queuelen;

static volatile uint_t nsuspended;
static mutex_t suspend_lock;	/* init in worker_init() */
static cond_t suspend_cv = DEFAULTCV;

static worker_t *worker_init_one(size_t, size_t);
static void *worker_main(void *);
static const char *worker_cmd_str(worker_cmd_t);
static const char *worker_msg_str(worker_msg_t);
static void worker_pkt_inbound(pkt_t *);

/*
 * Create a pool of worker threads with the given queue depth.
 * Workers are left suspended under the assumption they will be
 * resumed once main_loop() starts.
 */
void
worker_init(size_t n_workers, size_t queue_sz)
{
	size_t len;

	VERIFY3S(mutex_init(&suspend_lock, LOCK_ERRORCHECK, NULL), ==, 0);

	/* Oh to have a gcc with overflow checks... */
	len = n_workers * sizeof (worker_t *);
	VERIFY3U(len, >, n_workers);
	VERIFY3U(len, >, sizeof (worker_t *));

	workers = umem_zalloc(len, UMEM_DEFAULT);
	if (workers == NULL)
		err(EXIT_FAILURE, "out of memory");

	nworkers = workers_alloc = n_workers;

	len = queue_sz * sizeof (worker_item_t *);
	VERIFY3U(len, >, queue_sz);
	VERIFY3U(len, >, sizeof (worker_item_t *));
	queuelen = queue_sz;

	for (size_t i = 0; i < nworkers; i++) {
		worker_t *w = worker_init_one(len, i);

		if (w == NULL)
			err(EXIT_FAILURE, "out of memory");

		workers[i] = w;
	}

	for (size_t i = 0; i < nworkers; i++) {
		worker_t *w = workers[i];
		int rc;

		rc = thr_create(NULL, 0, worker_main, w, 0, &w->w_tid);
		if (rc != 0) {
			bunyan_fatal(log, "Cannot create worker thread",
			    BUNYAN_T_STRING, "errmsg", strerror(rc),
			    BUNYAN_T_INT32, "errno", (int32_t)rc,
			    BUNYAN_T_STRING, "file", __FILE__,
			    BUNYAN_T_INT32, "line", (int)__LINE__,
			    BUNYAN_T_STRING, "func", __func__,
			    BUNYAN_T_END);
			exit(EXIT_FAILURE);
		}
	}

	bunyan_trace(log, "Worker threads created",
	    BUNYAN_T_UINT32, "numworkers", (uint32_t)nworkers,
	    BUNYAN_T_END);
}

/* Allocate and init a worker_t -- but does not create the thread for it */
static worker_t *
worker_init_one(size_t qlen, size_t n)
{
	worker_t *w = NULL;
	size_t len = qlen * sizeof (worker_item_t);

	if ((w = umem_zalloc(sizeof (*w), UMEM_DEFAULT)) == NULL)
		return (NULL);

	/* We assume any overflow checks on queue length have been done */
	if ((w->w_queue.wq_items = umem_zalloc(len, UMEM_DEFAULT)) == NULL) {
		umem_free(w, sizeof (*w));
		return (NULL);
	}

/* XXX Remove one OS-6341 is fixed */
#ifdef BUNYAN_FIXED
	if (bunyan_child(log, &w->w_log,
	    BUNYAN_T_UINT32, "worker", (uint32_t)n, BUNYAN_T_END) != 0) {
		umem_free(w, sizeof (*w));
		return (NULL);
	}
#else
	if (bunyan_child(log, &w->w_log, BUNYAN_T_END) != 0) {
		umem_free(w, sizeof (*w));
		return (NULL);
	}

	if (bunyan_key_add(w->w_log, BUNYAN_T_UINT32, "worker", (uint32_t)n,
	    BUNYAN_T_END) != 0) {
		bunyan_fini(w->w_log);
		umem_free(w, sizeof (*w));
		return (NULL);
	}
#endif

	w->w_queue.wq_cmd = WC_NONE;
	VERIFY3S(mutex_init(&w->w_queue.wq_lock, LOCK_ERRORCHECK, NULL), ==, 0);
	VERIFY3S(cond_init(&w->w_queue.wq_cv, NULL, NULL), ==, 0);

	ike_timer_worker_init(w);

	ilist_create(&w->w_sas, sizeof (ikev2_sa_t),
	    offsetof(ikev2_sa_t, i2sa_wnode));
	return (w);
}

static void
worker_free(worker_t *w)
{
	size_t len = queuelen * sizeof (worker_item_t);

	if (w == NULL)
		return;

	umem_free(w->w_queue.wq_items, len);
	bunyan_fini(w->w_log);
	mutex_destroy(&w->w_queue.wq_lock);
	cond_destroy(&w->w_queue.wq_cv);
	ilist_destroy(&w->w_timers);
	ilist_destroy(&w->w_sas);
	umem_free(w, sizeof (*w));
}

static boolean_t
worker_send_cmd(size_t n, worker_cmd_t cmd)
{
	ASSERT3U(n, <=, nworkers);
	ASSERT(RW_LOCK_HELD(&worker_lock));

	worker_t *w = workers[n];
	worker_queue_t *wq = &w->w_queue;

	mutex_enter(&wq->wq_lock);
	if (w->w_queue.wq_cmd != WC_NONE) {
		mutex_exit(&wq->wq_lock);
		return (B_FALSE);
	}

	w->w_queue.wq_cmd = cmd;
	PTH(cond_signal(&wq->wq_cv));
	mutex_exit(&wq->wq_lock);

	return (B_TRUE);
}

void
worker_suspend(void)
{
	PTH(rw_wrlock(&worker_lock));
	for (size_t i = 0; i < nworkers; i++) {
		worker_t *w = workers[i];
		worker_queue_t *wq = &w->w_queue;

		mutex_enter(&wq->wq_lock);
		w->w_queue.wq_cmd = WC_SUSPEND;
		PTH(cond_signal(&wq->wq_cv));
		mutex_exit(&wq->wq_lock);
	}
	PTH(rw_unlock(&worker_lock));

	mutex_enter(&suspend_lock);
	while (nsuspended != nworkers)
		PTH(cond_wait(&suspend_cv, &suspend_lock));
	mutex_exit(&suspend_lock);
}

static void
worker_do_suspend(worker_t *w)
{
	worker_queue_t *wq = &w->w_queue;

	VERIFY(MUTEX_HELD(&wq->wq_lock));
	mutex_exit(&wq->wq_lock);

	mutex_enter(&suspend_lock);
	if (++nsuspended == nworkers) {
		bunyan_trace(w->w_log, "Last one in, signaling", BUNYAN_T_END);
		PTH(cond_signal(&suspend_cv));
	}
	mutex_exit(&suspend_lock);

	mutex_enter(&wq->wq_lock);
	while (wq->wq_cmd == WC_SUSPEND)
		PTH(cond_wait(&wq->wq_cv, &wq->wq_lock));

	bunyan_debug(w->w_log, "Worker resuming", BUNYAN_T_END);
	/* leave wq->wq_lock locked */
}

void
worker_resume(void)
{
	PTH(rw_wrlock(&worker_lock));
	for (size_t i = 0; i < nworkers; i++) {
		worker_t *w = workers[i];
		worker_queue_t *wq = &w->w_queue;

		bunyan_trace(log, "Waking up worker",
		    BUNYAN_T_UINT32, "worker", (uint32_t)i,
		    BUNYAN_T_END);

		mutex_enter(&wq->wq_lock);
		wq->wq_cmd = WC_NONE;
		mutex_exit(&wq->wq_lock);
		PTH(cond_broadcast(&wq->wq_cv));
	}
	PTH(rw_unlock(&worker_lock));

	bunyan_trace(log, "Finished resuming workers", BUNYAN_T_END);
}

boolean_t
worker_dispatch(worker_msg_t msg, void *data, size_t n)
{
	worker_t *w = NULL;
	worker_queue_t *wq = NULL;
	worker_item_t *wi = NULL;

	PTH(rw_rdlock(&worker_lock));
	VERIFY3U(n, <, nworkers);
	w = workers[n];
	wq = &w->w_queue;
	mutex_enter(&wq->wq_lock);

	if (WQ_FULL(wq)) {
		mutex_exit(&wq->wq_lock);
		PTH(rw_unlock(&worker_lock));

		(void) bunyan_debug(log, "dispatch failed (queue full)",
		    BUNYAN_T_UINT32, "worker", (uint32_t)n,
		    BUNYAN_T_STRING, "event", worker_msg_str(msg),
		    BUNYAN_T_POINTER, "data", data,
		    BUNYAN_T_END);
		return (B_FALSE);
	}

	wi = &wq->wq_items[wq->wq_end++];
	wi->wi_msgtype = msg;
	wi->wi_data = data;
	wq->wq_end %= queuelen;

	PTH(cond_signal(&wq->wq_cv));
	mutex_exit(&wq->wq_lock);
	PTH(rw_unlock(&worker_lock));

	(void) bunyan_debug(w->w_log, "Dispatching message to worker",
	    BUNYAN_T_UINT32, "worker", (uint32_t)n,
	    BUNYAN_T_STRING, "msgtype", worker_msg_str(msg),
	    BUNYAN_T_POINTER, "data", data,
	    BUNYAN_T_END);
	return (B_TRUE);
}

static void *
worker_main(void *arg)
{
	worker_t *w = arg;
	worker_queue_t *wq = &w->w_queue;
	timespec_t ts = { 0 };
	boolean_t done = B_FALSE;

	worker = w;
	(void) bunyan_trace(w->w_log, "Worker starting", BUNYAN_T_END);

	mutex_enter(&wq->wq_lock);

	/*CONSTCOND*/
	while (1) {
		timespec_t *pts = &ts;
		int rc = 0;

		process_timer(&pts);

		if (pts != NULL)
			rc = cond_reltimedwait(&wq->wq_cv, &wq->wq_lock, pts);
		else
			rc = cond_wait(&wq->wq_cv, &wq->wq_lock);

		if (rc != 0 && rc != ETIME) {
			(void) bunyan_fatal(w->w_log,
			    "Unexpected cond_timedwait return value",
			    BUNYAN_T_STRING, "errmsg", strerror(rc),
			    BUNYAN_T_INT32, "errno", (int32_t)rc,
			    BUNYAN_T_STRING, "file", __FILE__,
			    BUNYAN_T_INT32, "line", (int32_t)__LINE__,
			    BUNYAN_T_STRING, "func", __func__,
			    BUNYAN_T_END);
			abort();
		}

		if (wq->wq_cmd != WC_NONE)
			(void) bunyan_info(w->w_log, "Received command",
			    BUNYAN_T_STRING, "cmd", worker_cmd_str(wq->wq_cmd),
			    BUNYAN_T_UINT32, "cmdval", (uint32_t)wq->wq_cmd,
			    BUNYAN_T_END);

		switch (wq->wq_cmd) {
		case WC_NONE:
			break;
		case WC_SUSPEND:
			bunyan_debug(w->w_log, "Suspending worker",
			    BUNYAN_T_END);
			worker_do_suspend(w);
			VERIFY(MUTEX_HELD(&wq->wq_lock));
			continue;			
		case WC_QUIT:
			done = B_TRUE;
			break;
		default:
			INVALID("wq->wq_cmd");
		}

		if (done)
			break;

		while (!WQ_EMPTY(wq)) {
			const worker_item_t *src = &wq->wq_items[wq->wq_start];
			worker_item_t wi = {
				.wi_msgtype = src->wi_msgtype,
				.wi_data = src->wi_data
			};

			wq->wq_items[wq->wq_start].wi_msgtype = WMSG_NONE;
			wq->wq_items[wq->wq_start].wi_data = NULL;

			wq->wq_start++;
			wq->wq_start %= queuelen;
			mutex_exit(&wq->wq_lock);

			switch (wi.wi_msgtype) {
			case WMSG_NONE:
				INVALID("wi.wi_event");
				break;
			case WMSG_PACKET:
				worker_pkt_inbound(wi.wi_data);
				break;
			case WMSG_PFKEY:
				/* TODO */
				break;
			case WMSG_START:
				ikev2_sa_init_outbound(wi.wi_data, NULL, 0,
				    IKEV2_DH_NONE, NULL, 0);
				break;
			case WMSG_START_P1_TIMER:
				ikev2_sa_start_timer(wi.wi_data);
				break;
			}

			mutex_enter(&wq->wq_lock);
		}
	}

	w->w_done;
	PTH(cond_signal(&wq->wq_cv));
	mutex_exit(&wq->wq_lock);
	return (w);
}

static void
worker_pkt_inbound(pkt_t *pkt)
{
	switch (IKE_GET_MAJORV(pkt->pkt_header.version)) {
	case 1:
		/* XXX: ikev1_inbound(pkt); */
		break;
	case 2:
		ikev2_inbound(pkt);
		break;
	default:
		/* XXX: log? */
		pkt_free(pkt);
	}
}

boolean_t
worker_add(void)
{
	worker_t **new_workers = NULL;
	worker_t *w = NULL;
	size_t new_workers_alloc = 0;
	size_t len = 0, qlen = 0;
	int rc = 0;

	(void) bunyan_trace(log, "Creating new worker", BUNYAN_T_END);

	if (workers_alloc == nworkers) {
		new_workers_alloc = workers_alloc + 1;
		len = new_workers_alloc * sizeof (worker_t *);
		VERIFY3U(len, >, new_workers_alloc);
		VERIFY3U(len, >, sizeof (worker_t *));

		if ((new_workers = umem_zalloc(len, UMEM_DEFAULT)) == NULL)
			return (B_FALSE);

	} else {
		new_workers = workers;
		new_workers_alloc = workers_alloc;
	}

	qlen = queuelen * sizeof (pkt_t *);
	VERIFY3U(qlen, >, queuelen);
	VERIFY3U(qlen, >, sizeof (pkt_t *));

	if ((w = worker_init_one(qlen, nworkers + 1)) == NULL) {
		umem_free(new_workers, len);
		return (B_FALSE);
	}

	rc = thr_create(NULL, 0, worker_main, w, 0, &w->w_tid);
	if (rc != 0) {
		bunyan_fatal(log, "Cannot create additional worker thread",
		    BUNYAN_T_STRING, "errmsg", strerror(rc),
		    BUNYAN_T_INT32, "errno", (int32_t)rc,
		    BUNYAN_T_STRING, "file", __FILE__,
		    BUNYAN_T_INT32, "line", (int32_t)__LINE__,
		    BUNYAN_T_STRING, "func", __func__,
		    BUNYAN_T_END);
		umem_free(new_workers, len);
		worker_free(w);
		return (B_FALSE);
	}

	PTH(rw_wrlock(&worker_lock));
	workers = new_workers;
	workers_alloc = new_workers_alloc;

	VERIFY3U(workers_alloc, >, nworkers);
	workers[nworkers++] = w;

	PTH(rw_unlock(&worker_lock));

	(void) bunyan_debug(w->w_log, "Worker created", BUNYAN_T_END);
	thr_continue(w->w_tid);
	return (B_TRUE);
}

void
worker_del(void)
{
}

#define	STR(x) case x: return (#x)
static const char *
worker_cmd_str(worker_cmd_t wc)
{
	switch (wc) {
	STR(WC_NONE);
	STR(WC_SUSPEND);
	STR(WC_QUIT);
	}

	INVALID(wc);
	return (NULL);
}

static const char *
worker_msg_str(worker_msg_t msg)
{
	switch (msg) {
	STR(WMSG_NONE);
	STR(WMSG_PACKET);
	STR(WMSG_PFKEY);
	STR(WMSG_START);
	STR(WMSG_START_P1_TIMER);
	}

	INVALID(msg);
	return (NULL);
}
#undef STR
