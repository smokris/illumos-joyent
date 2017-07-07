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

#include <pthread.h>
#include <umem.h>
#include <err.h>
#include <sys/debug.h>
#include <bunyan.h>
#include <time.h>
#include "defs.h"
#include "worker.h"
#include "pkt.h"
#include "timer.h"
#include "pkcs11.h"

typedef enum worker_cmd {
	WC_NONE,
	WC_SUSPEND,
	WC_QUIT
} worker_cmd_t;

typedef struct worker_queue {
	pthread_mutex_t	wq_lock;
	pthread_cond_t	wq_cv;
	worker_cmd_t	wq_cmd;
	pkt_t		**wq_pkts;
	size_t		wq_start;
	size_t		wq_end;
} worker_queue_t;
#define	WQ_EMPTY(_wq) ((_wq)->wq_start == (_wq)->wq_end)
#define	WQ_FULL(_wq) ((((_wq)->wq_end + 1) % queuelen) == (_wq)->wq_start)

typedef struct worker {
	pthread_t	w_tid;
	bunyan_logger_t	*w_log;
	worker_queue_t	w_queue;
	boolean_t	w_done;
} worker_t;

static pthread_rwlock_t worker_lock = PTHREAD_RWLOCK_INITIALIZER;

size_t	nworkers;
static worker_t	**workers;
static size_t	workers_alloc;
static size_t	queuelen;

static worker_t *worker_init_one(size_t);
static void *worker(void *);
static const char *worker_cmd_str(worker_cmd_t);

void
worker_init(size_t n_workers, size_t queue_sz)
{
	size_t len;

	/* to have a gcc with overflow checks... */
	len = n_workers * sizeof (worker_t *);
	VERIFY3U(len, >, n_workers);
	VERIFY3U(len, >, sizeof (worker_t *));

	workers = umem_zalloc(len, UMEM_DEFAULT);
	if (workers == NULL)
		err(EXIT_FAILURE, "out of memory");

	nworkers = workers_alloc = n_workers;

	len = queue_sz * sizeof (pkt_t *);
	VERIFY3U(len, >, queue_sz);
	VERIFY3U(len, >, sizeof (pkt_t *));
	queuelen = queue_sz;

	for (size_t i = 0; i < nworkers; i++) {
		worker_t *w = worker_init_one(len);

		if (w == NULL)
			err(EXIT_FAILURE, "out of memory");

		bunyan_key_add(w->w_log, BUNYAN_T_UINT32, "worker",
		    (uint32_t)i);

		workers[i] = w;
	}

	for (size_t i = 0; i < nworkers; i++) {
		worker_t *w = workers[i];
		PTH(pthread_create(&w->w_tid, NULL, worker, w));
	}
}

static worker_t *
worker_init_one(size_t len)
{
	worker_t *w = NULL;

	if ((w = umem_zalloc(sizeof (*w), UMEM_DEFAULT)) == NULL)
		return (NULL);

	if ((w->w_queue.wq_pkts = umem_zalloc(len, UMEM_DEFAULT)) == NULL) {
		umem_free(w, sizeof (*w));
		return (NULL);
	}

	if (bunyan_child(log, &w->w_log, BUNYAN_T_END) != 0)
		return (NULL);

	PTH(pthread_mutex_init(&w->w_queue.wq_lock, NULL));
	PTH(pthread_cond_init(&w->w_queue.wq_cv, NULL));

	return (w);
}

static boolean_t
worker_send_cmd(size_t n, worker_cmd_t cmd)
{
	ASSERT3U(n, <=, nworkers);
	ASSERT(RW_LOCK_HELD(&worker_lock));

	worker_t *w = workers[n];
	worker_queue_t *wq = &w->w_queue;

	PTH(pthread_mutex_lock(&wq->wq_lock));
	if (w->w_queue.wq_cmd != WC_NONE) {
		PTH(pthread_mutex_unlock(&wq->wq_lock));
		return (B_FALSE);
	}

	w->w_queue.wq_cmd = cmd;
	PTH(pthread_cond_signal(&wq->wq_cv));
	PTH(pthread_mutex_unlock(&wq->wq_lock));

	return (B_TRUE);
}

void
worker_suspend(void)
{

}

void
worker_resume(void)
{

}

boolean_t
worker_dispatch(pkt_t *pkt, size_t n)
{
	worker_t *w = NULL;
	worker_queue_t *wq = NULL;

	PTH(pthread_rwlock_rdlock(&worker_lock));
	VERIFY3U(n, <, nworkers);
	w = workers[n];
	wq = &w->w_queue;
	PTH(pthread_mutex_lock(&wq->wq_lock));

	if (WQ_FULL(wq)) {
		PTH(pthread_mutex_unlock(&wq->wq_lock));
		PTH(pthread_rwlock_unlock(&worker_lock));

		(void) bunyan_debug(log, "dispatch failed (queue full)",
		    BUNYAN_T_UINT32, "worker", (uint32_t)n,
		    BUNYAN_T_POINTER, "pkt", pkt,
		    BUNYAN_T_END);
		return (B_FALSE);
	}

	wq->wq_pkts[wq->wq_end++] = pkt;
	wq->wq_end %= queuelen;

	PTH(pthread_cond_signal(&wq->wq_cv));
	PTH(pthread_mutex_unlock(&wq->wq_lock));
	PTH(pthread_rwlock_unlock(&worker_lock));

	(void) bunyan_debug(w->w_log, "Dispatching packet to worker",
	    BUNYAN_T_UINT32, "worker", (uint32_t)n,
	    BUNYAN_T_POINTER, "pkt", pkt,
	    BUNYAN_T_END);
	return (B_TRUE);
}

static void *
worker(void *arg)
{
	worker_t *w = arg;
	worker_queue_t *wq = &w->w_queue;
	timespec_t ts = { 0 };
	boolean_t done = B_FALSE;

	ike_timer_thread_init();

	(void) bunyan_trace(w->w_log, "Worker starting", BUNYAN_T_END);

	PTH(pthread_mutex_lock(&wq->wq_lock));

	/*CONSTCOND*/
	while (1) {
		wq->wq_cmd = WC_NONE;
		process_timer(&ts, w->w_log);

		if (ts.tv_sec == 0 && ts.tv_nsec == 0) {
			PTH(pthread_cond_wait(&wq->wq_cv, &wq->wq_lock));
		} else {
			int rc;
			rc = pthread_cond_timedwait(&wq->wq_cv, &wq->wq_lock,
			    &ts);
			VERIFY(rc == 0 || rc == ETIMEDOUT);
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
			/* XXX: todo */
			break;
		case WC_QUIT:
			done = B_TRUE;
			break;
		default:
			INVALID("wq->wq_cmd");
		}

		if (done)
			break;

		while (!WQ_EMPTY(wq)) {
		}
	}

	w->w_done;
	PTH(pthread_cond_signal(&wq->wq_cv));
	PTH(pthread_mutex_unlock(&wq->wq_lock));
	return (w);
}

boolean_t
worker_add(void)
{
	worker_t **new_workers = NULL;
	worker_t *w = NULL;
	size_t new_workers_alloc = 0;
	size_t len = 0, qlen = 0;

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

	if ((w = worker_init_one(qlen)) == NULL) {
		umem_free(new_workers, len);
		return (B_FALSE);
	}

	PTH(pthread_create(&w->w_tid, NULL, worker, w));

	PTH(pthread_rwlock_wrlock(&worker_lock));
	workers = new_workers;
	workers_alloc = new_workers_alloc;

	VERIFY3U(workers_alloc, >, nworkers);
	workers[nworkers++] = w;

	PTH(pthread_rwlock_unlock(&worker_lock));

	(void) bunyan_debug(w->w_log, "Worker created", BUNYAN_T_END);

	return (B_TRUE);
}

void
worker_del(void)
{
}

static const char *
worker_cmd_str(worker_cmd_t wc)
{
#define	STR(x) case x: return (#x)
	switch (wc) {
	STR(WC_NONE);
	STR(WC_SUSPEND);
	STR(WC_QUIT);
	default:
		return ("UNKNOWN");
	}
#undef STR
}
