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
#define	WQ_FULL(_wq) ((((_wq)->wq_end + 1) % wk_queuelen) == (_wq)->wq_start)

__thread worker_t *worker = NULL;

/*
 * The following group of variables are protected by worker_lock.  Generally
 * this is used to update the global array of data on workers.  In general,
 * one should grab the wk_worker_lock prior obtaining w_lock.
 */
static rwlock_t wk_worker_lock = DEFAULTRWLOCK;
size_t		wk_nworkers;
static worker_t	**wk_workers;
static size_t	wk_workers_alloc;
static size_t	wk_queuelen;

static volatile uint_t wk_nsuspended;
static mutex_t wk_suspend_lock = ERRORCHECKMUTEX;
static cond_t wk_suspend_cv = DEFAULTCV;

static worker_t *worker_new(size_t);
static void worker_free(worker_t *);
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
worker_init(size_t nworkers, size_t queuelen)
{
	wk_workers = calloc(nworkers, sizeof (worker_t *));
	if (wk_workers == NULL)
		err(EXIT_FAILURE, "out of memory");

	wk_nworkers = wk_workers_alloc = nworkers;
	wk_queuelen = queuelen;

	for (size_t i = 0; i < nworkers; i++) {
		worker_t *w = worker_new(i);

		if (w == NULL)
			err(EXIT_FAILURE, "Out of memory");

		wk_workers[i] = w;
	}

	for (size_t i = 0; i < nworkers; i++) {
		worker_t *w = wk_workers[i];
		int rc;

		rc = thr_create(NULL, 0, worker_main, w, 0, &w->w_tid);
		if (rc != 0) {
			(void) bunyan_fatal(log, "Cannot create worker thread",
			    BUNYAN_T_STRING, "errmsg", strerror(rc),
			    BUNYAN_T_INT32, "errno", (int32_t)rc,
			    BUNYAN_T_STRING, "file", __FILE__,
			    BUNYAN_T_INT32, "line", (int)__LINE__,
			    BUNYAN_T_STRING, "func", __func__,
			    BUNYAN_T_END);
			exit(EXIT_FAILURE);
		}
	}

	(void) bunyan_trace(log, "Worker threads created",
	    BUNYAN_T_UINT32, "numworkers", (uint32_t)nworkers,
	    BUNYAN_T_END);
}

/* Allocate a worker_t -- but does not create the thread for it */
static worker_t *
worker_new(size_t n)
{
	worker_t *w = calloc(1, sizeof (worker_t));

	if (w == NULL)
		return (NULL);

	VERIFY0(mutex_init(&w->w_queue.wq_lock, LOCK_ERRORCHECK, NULL));
	VERIFY0(cond_init(&w->w_queue.wq_cv, NULL, NULL));
	ike_timer_worker_init(w);

	w->w_queue.wq_items = calloc(wk_queuelen, sizeof (worker_item_t));
	if (w->w_queue.wq_items == NULL)
		goto fail;

	if (bunyan_child(log, &w->w_log,
	    BUNYAN_T_UINT32, "worker", (uint32_t)n, BUNYAN_T_END) != 0)
		goto fail;

	if ((w->w_p11 = pkcs11_new_session()) == CK_INVALID_HANDLE)
		goto fail;

	w->w_queue.wq_cmd = WC_NONE;
	return (w);

fail:
	worker_free(w);
	return (NULL);
}

static void
worker_free(worker_t *w)
{
	if (w == NULL)
		return;

	free(w->w_queue.wq_items);
	if (w->w_log != NULL)
		bunyan_fini(w->w_log);
	pkcs11_session_free(w->w_p11);	
	mutex_destroy(&w->w_queue.wq_lock);
	cond_destroy(&w->w_queue.wq_cv);
	ilist_destroy(&w->w_timers);
	free(w);
}

/*
 * Pause all the workers.  The current planned use is when we need to resize
 * the IKE SA hashes -- it's far simpler to make sure all the workers are
 * quiesced and rearrange things then restart.
 */
void
worker_suspend(void)
{
	VERIFY0(rw_wrlock(&wk_worker_lock));
	for (size_t i = 0; i < wk_nworkers; i++) {
		worker_t *w = wk_workers[i];
		worker_queue_t *wq = &w->w_queue;

		mutex_enter(&wq->wq_lock);
		w->w_queue.wq_cmd = WC_SUSPEND;
		VERIFY0(cond_signal(&wq->wq_cv));
		mutex_exit(&wq->wq_lock);
	}
	VERIFY0(rw_unlock(&wk_worker_lock));

	mutex_enter(&wk_suspend_lock);
	while (wk_nsuspended != wk_nworkers)
		VERIFY0(cond_wait(&wk_suspend_cv, &wk_suspend_lock));
	mutex_exit(&wk_suspend_lock);
}

static void
worker_do_suspend(worker_t *w)
{
	worker_queue_t *wq = &w->w_queue;

	VERIFY(MUTEX_HELD(&wq->wq_lock));
	mutex_exit(&wq->wq_lock);

	mutex_enter(&wk_suspend_lock);
	if (++wk_nsuspended == wk_nworkers) {
		bunyan_trace(w->w_log, "Last one in, signaling", BUNYAN_T_END);
		VERIFY0(cond_signal(&wk_suspend_cv));
	}
	mutex_exit(&wk_suspend_lock);

	mutex_enter(&wq->wq_lock);
	while (wq->wq_cmd == WC_SUSPEND)
		VERIFY0(cond_wait(&wq->wq_cv, &wq->wq_lock));

	mutex_enter(&wk_suspend_lock);
	--wk_nsuspended;
	mutex_exit(&wk_suspend_lock);

	bunyan_debug(w->w_log, "Worker resuming", BUNYAN_T_END);
	/* leave wq->wq_lock locked */
}

void
worker_resume(void)
{
	VERIFY0(rw_wrlock(&wk_worker_lock));
	for (size_t i = 0; i < wk_nworkers; i++) {
		worker_t *w = wk_workers[i];
		worker_queue_t *wq = &w->w_queue;

		bunyan_trace(log, "Waking up worker",
		    BUNYAN_T_UINT32, "worker", (uint32_t)i,
		    BUNYAN_T_END);

		mutex_enter(&wq->wq_lock);
		wq->wq_cmd = WC_NONE;
		mutex_exit(&wq->wq_lock);
		VERIFY0(cond_broadcast(&wq->wq_cv));
	}
	VERIFY0(rw_unlock(&wk_worker_lock));

	bunyan_trace(log, "Finished resuming workers", BUNYAN_T_END);
}

boolean_t
worker_dispatch(worker_msg_t msg, void *data, size_t n)
{
	worker_t *w = NULL;
	worker_queue_t *wq = NULL;
	worker_item_t *wi = NULL;

	VERIFY0(rw_rdlock(&wk_worker_lock));
	VERIFY3U(n, <, wk_nworkers);
	w = wk_workers[n];
	wq = &w->w_queue;
	mutex_enter(&wq->wq_lock);

	if (WQ_FULL(wq)) {
		mutex_exit(&wq->wq_lock);
		VERIFY0(rw_unlock(&wk_worker_lock));

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
	wq->wq_end %= wk_queuelen;

	VERIFY0(cond_signal(&wq->wq_cv));
	mutex_exit(&wq->wq_lock);
	VERIFY0(rw_unlock(&wk_worker_lock));

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
			wq->wq_start %= wk_queuelen;
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
	VERIFY0(cond_signal(&wq->wq_cv));
	mutex_exit(&wq->wq_lock);
	return (w);
}

static void
worker_pkt_inbound(pkt_t *pkt)
{
	switch (IKE_GET_MAJORV(pkt_header(pkt)->version)) {
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

	VERIFY0(rw_wrlock(&wk_worker_lock));
	if (wk_workers_alloc == wk_nworkers) {
		new_workers_alloc = wk_workers_alloc + 1;
		new_workers = recallocarray(wk_workers, wk_workers_alloc,
		    new_workers_alloc, sizeof (worker_t *));

		if (new_workers == NULL) {
			VERIFY0(rw_unlock(&wk_worker_lock));
			return (B_FALSE);
		}

		wk_workers = new_workers;
		wk_workers_alloc = new_workers_alloc;
	}

	if ((w = worker_new(wk_nworkers + 1)) == NULL) {
		VERIFY0(rw_unlock(&wk_worker_lock));
		return (B_FALSE);
	}

	wk_workers[wk_nworkers++] = w;

	rc = thr_create(NULL, 0, worker_main, w, 0, &w->w_tid);
	if (rc != 0) {
		bunyan_fatal(log, "Cannot create additional worker thread",
		    BUNYAN_T_STRING, "errmsg", strerror(rc),
		    BUNYAN_T_INT32, "errno", (int32_t)rc,
		    BUNYAN_T_STRING, "file", __FILE__,
		    BUNYAN_T_INT32, "line", (int32_t)__LINE__,
		    BUNYAN_T_STRING, "func", __func__,
		    BUNYAN_T_END);
		wk_workers[--wk_nworkers] = NULL;
		worker_free(w);
		VERIFY0(rw_unlock(&wk_worker_lock));
		return (B_FALSE);
	}

	VERIFY0(rw_unlock(&wk_worker_lock));
	(void) bunyan_debug(w->w_log, "Worker created", BUNYAN_T_END);
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
