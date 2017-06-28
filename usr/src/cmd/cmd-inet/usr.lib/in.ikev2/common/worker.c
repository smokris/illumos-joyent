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
#include <timer.h>
#include "worker.h"
#include "pkt.h"

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

static worker_t	*workers;
static size_t	nworkers;
static size_t	queuelen;

static boolean_t worker_init_one(worker_t *, size_t);
static void *worker(void *);

void
worker_init(size_t n_workers, size_t queue_sz)
{
	size_t len;

	/* to have a gcc with overflow checks... */
	len = n_workers * sizeof (worker_t);
	VERIFY3U(len, >, n_workers);
	VERIFY3U(len, >, sizeof (worker_t));

	workers = umem_zalloc(len, UMEM_DEFAULT);
	if (workers == NULL)
		err(EXIT_FAILURE, "out of memory");

	nworkers = n_workers;

	len = queue_sz * sizeof (queue_item_t);
	VERIFY3U(len, >, queue_sz);
	VERIFY3U(len, >, sizeof (queue_item_t));
	queuelen = queue_sz;

	for (size_t i = 0; i < nworkers; i++) {
		if (!worker_init_one(&workers[i], len))
			err(EXIT_FAILURE, "out of memory");
	}

	for (size_t i = 0; i < nworkers; i++) {
		worker_t *w = &workers[i];
		PTH(pthread_create(&w->w_tid, NULL, worker, w));
	}
}

static boolean_t
worker_init_one(worker_t *w, size_t len)
{
	if ((w->w_queue.wq_items = umem_zalloc(len, UMEM_DEFAULT)) == NULL)
		return (B_FALSE);

	if (bunyan_child(log, &w->w_log, BUNYAN_T_END) != 0)
		return (B_FALSE);

	w->w_queue.wq_lock = PTHREAD_MUTEX_INITIALIZER;
	w->w_queue.wq_cv = PTHREAD_COND_INITIALIZER;

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

static size_t
worker_hash(pkt_t *pkt)
{
	return (0);
}

boolean_t
worker_dispatch(pkt_t *pkt)
{
	worker_t *w = NULL;
	worker_queue_t *wq = NULL;

	PTH(pthread_rwlock_rdlock(&worker_lock));
	w = &workers[worker_hash(pkt)];
	wq = &w->w_queue;
	PTH(pthread_mutex_lock(&wq->wq_lock));

	if (WQ_FULL(wq)) {
		PTH(pthread_mutex_unlock(&wq->wq_lock));
		PTH(pthread_rwlock_unlock(&w->worker_lock));
		return (B_FALSE);
	}

	wq->wq_pkts[wq->wq_end++] = pkt;
	wq->wq_end %= queuelen;

	PTH(pthread_cond_signal(&w->wq_cv));
	PTH(pthread_mutex_unlock(&w->wq_lock));
	PTH(pthread_rwlock_unlock(&w->worker_lock));

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

	PTH(pthread_mutex_lock(&wq->wq_lock));
	while (!done) {
		process_timer(&ts);

		if (ts.tv_sec == 0 && ts.tv_nsec == 0) {
			PTH(pthread_cond_wait(&wq->wq_cv, &wq->wq_lock));
		} else {
			int rc;
			rc = pthread_cond_timedwait(&wq->cv, &wq->wq_lock, &ts);
			VEFIFY(rc == 0 || rc == ETIMEDOUT);
		}

		while (!WQ_EMPTY(wq)) {
		}
	}	

	return (NULL);
}
