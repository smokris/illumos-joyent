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
 * Copyright 2018, Joyent, Inc.
 */

#include <bunyan.h>
#include <err.h>
#include <errno.h>
#include <libperiodic.h>
#include <port.h>
#include <string.h>
#include <synch.h>
#include <sys/debug.h>
#include <sys/list.h>
#include <thread.h>
#include <time.h>
#include <umem.h>
#include "defs.h"
#include "ikev2_proto.h"
#include "ikev2_sa.h"
#include "pkcs11.h"
#include "pkt.h"
#include "worker.h"
#include "util.h"

/*
 * Virtually all work in in.ikev2d is done via a pool of worker threads.
 * Each worker in the worker pool has an event loop that broadly waits for
 * an event to arrive on the event port, gets it, and processes the event.
 * Events can be things like inbound IKE/ISAKMP datagrams, SADB messages
 * from our pfkey socket, timer events, or administrative requests.
 *
 * Each worker thread has a number of items allocated for it during thread
 * creation (the members of worker_t).  These items are things that for
 * debugging purposes, or things where we don't want to worry about allocation
 * failures during processing (such as a PKCS#11 session handle).
 */

/* The state of the worker pool */
typedef enum worker_state {
	WS_NORMAL = 0,
	WS_SUSPENDING,
	WS_SUSPENDED,
	WS_RESUMING,
	WS_QUITTING,
} worker_state_t;

typedef enum worker_alert {
	WA_NONE,
	WA_SUSPEND,
} worker_alert_t;

/* Our per-worker thread items */
__thread worker_t *worker = NULL;

uint64_t wk_initial_nworkers = DEFAULT_NUM_WORKERS;
int wk_evport = -1;
size_t wk_nworkers = 0;
periodic_handle_t *wk_periodic = NULL;

/*
 * worker_lock protects access to workers, worker_state- and wk_nsuspended.
 *
 * NOTE: workers itself is largely a diagnostic construct to make it easier to
 * see the per-worker values of things in worker_t.  Once a worker_t has been
 * assigned to a worker thread, no other threads should access the values of
 * another thread's worker_t.
 */
static mutex_t worker_lock = ERRORCHECKMUTEX;
static cond_t worker_cv = DEFAULTCV; /* used to coordinate suspend/resume */
static list_t workers;
/* Global state of all workers */
static worker_state_t worker_state;
static volatile uint_t wk_nsuspended;

static void worker_free(worker_t *);
static void *worker_main(void *);
static const char *worker_cmd_str(worker_cmd_t);

static void do_alert(int, void *);
static void do_user(int, void *);

/*
 * Create a pool of worker threads with the given number of threads.
 */
void
worker_init(size_t n)
{
	if ((wk_evport = port_create()) == -1)
		err(EXIT_FAILURE, "port_create() failed");

	wk_periodic = periodic_init(wk_evport, NULL, CLOCK_MONOTONIC);
	if (wk_periodic == NULL)
		err(EXIT_FAILURE, "could not create periodic");

	mutex_enter(&worker_lock);
	list_create(&workers, sizeof (worker_t), offsetof(worker_t, w_node));
	mutex_exit(&worker_lock);

	for (size_t i = 0; i < n; i++) {
		if (!worker_add())
			err(EXIT_FAILURE, "Unable to create workers");
	}

	(void) bunyan_trace(log, "Worker threads created",
	    BUNYAN_T_UINT32, "numworkers", (uint32_t)wk_nworkers,
	    BUNYAN_T_END);
}

void
worker_fini(void)
{
	periodic_fini(wk_periodic);
	(void) close(wk_evport);
}

boolean_t
worker_add(void)
{
	worker_t *w = NULL;
	int rc;

	VERIFY(!IS_WORKER);

	/*
	 * Lock out any other global activity until after the add has
	 * succeeded or failed.
	 */
	mutex_enter(&worker_lock);
	while (worker_state != WS_NORMAL && worker_state != WS_QUITTING)
		VERIFY0(cond_wait(&worker_cv, &worker_lock));

	/* If we're shutting down, don't bother creating the worker */
	if (worker_state == WS_QUITTING)
		goto fail;

	if ((w = umem_zalloc(sizeof (worker_t), UMEM_DEFAULT)) == NULL)
		goto fail;

	if (bunyan_child(main_log, &w->w_log, BUNYAN_T_END) != 0)
		goto fail;

	if ((w->w_p11 = pkcs11_new_session()) == CK_INVALID_HANDLE)
		goto fail;

again:
	rc = thr_create(NULL, 0, worker_main, w, 0, &w->w_tid);
	switch (rc) {
	case 0:
		break;
	case EAGAIN:
		goto again;
	case ENOMEM:
		TSTDERR(rc, warn, "No memory to create worker");
		goto fail;
	default:
		TSTDERR(rc, fatal, "Cannot create additional worker thread");
		abort();
	}

	list_insert_tail(&workers, w);
	VERIFY0(cond_broadcast(&worker_cv));
	wk_nworkers++;
	mutex_exit(&worker_lock);

	return (B_TRUE);

fail:
	worker_free(w);
	mutex_enter(&worker_lock);
	VERIFY0(cond_broadcast(&worker_cv));
	mutex_exit(&worker_lock);
	return (B_FALSE);
}

static void
worker_free(worker_t *w)
{
	if (w == NULL)
		return;

	if (w->w_log != NULL)
		bunyan_fini(w->w_log);

	pkcs11_session_free(w->w_p11);
	umem_free(w, sizeof (*w));
}

/*
 * Pause all the workers.  The current planned use is when we need to resize
 * the IKE SA hashes -- it's far simpler to make sure all the workers are
 * quiesced and rearrange things then restart.
 */
void
worker_suspend(void)
{
	/*
	 * We currently do not support workers suspending all the workers.
	 * This must be called from a non-worker thread such as the main thread.
	 */
	VERIFY(!IS_WORKER);

	mutex_enter(&worker_lock);

again:
	switch (worker_state) {
	case WS_NORMAL:
		break;
	/* No point in suspending if we are quitting */
	case WS_QUITTING:
	/*
	 * Ignore additional attempts to suspend if already in progress or
	 * already suspended.
	 */
	case WS_SUSPENDING:
	case WS_SUSPENDED:
		mutex_exit(&worker_lock);
		return;
	/* If we're resuming, wait until it's finished and retry */
	case WS_RESUMING:
		VERIFY0(cond_wait(&worker_cv, &worker_lock));
		goto again;
	}

	VERIFY(MUTEX_HELD(&worker_lock));

	worker_state = WS_SUSPENDING;
	(void) bunyan_debug(log, "Suspending workers", BUNYAN_T_END);

	if (port_alert(wk_evport, PORT_ALERT_SET, WA_SUSPEND, NULL) == -1) {
		/*
		 * While EBUSY (alert mode already set) can in some instances
		 * not be a fatal error, we never intentionally try set a port
		 * into alert mode once it is already there.  If we encounter
		 * that, something has gone wrong, so treat it as a fatal
		 * condition.
		 */
		STDERR(fatal, "port_alert() failed");
		abort();
	}

	while (wk_nsuspended != wk_nworkers)
		VERIFY0(cond_wait(&worker_cv, &worker_lock));

	worker_state = WS_SUSPENDED;

	if (port_alert(wk_evport, PORT_ALERT_SET, WC_NONE, NULL) == -1) {
		STDERR(fatal, "port_alert() failed");
		abort();
	}

	VERIFY0(cond_broadcast(&worker_cv));
	mutex_exit(&worker_lock);

	(void) bunyan_trace(log, "Finished suspending workers", BUNYAN_T_END);
}

static void
worker_do_suspend(void)
{
	VERIFY(IS_WORKER);

	(void) bunyan_debug(log, "Worker suspending", BUNYAN_T_END);

	mutex_enter(&worker_lock);
	if (++wk_nsuspended == wk_nworkers) {
		(void) bunyan_trace(log, "Last one in, signaling",
		    BUNYAN_T_END);
		VERIFY0(cond_broadcast(&worker_cv));
	}
	mutex_exit(&worker_lock);

	mutex_enter(&worker_lock);
	while (worker_state != WS_RESUMING)
		VERIFY0(cond_wait(&worker_cv, &worker_lock));

	VERIFY3U(wk_nsuspended, >, 0);
	if (--wk_nsuspended == 0)
		VERIFY0(cond_broadcast(&worker_cv));

	mutex_exit(&worker_lock);

	(void) bunyan_debug(log, "Worker resuming", BUNYAN_T_END);
}

void
worker_resume(void)
{
	/* Similar to worker_suspend(), can not be called from a worker */
	VERIFY(!IS_WORKER);

	mutex_enter(&worker_lock);

again:
	switch (worker_state) {
	case WS_NORMAL:
	case WS_RESUMING:
	case WS_QUITTING:
		mutex_exit(&worker_lock);
		return;
	case WS_SUSPENDING:
		VERIFY0(cond_wait(&worker_cv, &worker_lock));
		goto again;
	case WS_SUSPENDED:
		break;
	}

	(void) bunyan_debug(log, "Resuming workers", BUNYAN_T_END);

	worker_state = WS_RESUMING;

	while (wk_nsuspended > 0)
		VERIFY0(cond_wait(&worker_cv, &worker_lock));

	worker_state = WS_NORMAL;
	VERIFY0(cond_broadcast(&worker_cv));
	mutex_exit(&worker_lock);

	(void) bunyan_trace(log, "Finished resuming workers", BUNYAN_T_END);
}

static void *
worker_main(void *arg)
{
	worker_t *w = arg;

	worker = w;
	log = w->w_log;

	(void) bunyan_trace(log, "Worker starting", BUNYAN_T_END);

	while (!w->w_quit) {
		port_event_t pe = { 0 };

		log_reset_keys();

		if (port_get(wk_evport, &pe, NULL) == -1) {
			if (errno == EINTR) {
				/*
				 * This should not happen, but if it does,
				 * we can just ignore it, but at least make note
				 * of it.
				 */
				(void) bunyan_warn(log,
				    "port_get() failed with EINTR",
				    BUNYAN_T_END);
				continue;
			}

			STDERR(fatal, "port_get() failed");
			abort();
		}

		(void) bunyan_trace(log, "Received event",
		    BUNYAN_T_INT32, "evport", (int32_t)wk_evport,
		    BUNYAN_T_STRING, "source",
		    port_source_str(pe.portev_source),
		    BUNYAN_T_INT32, "events", (int32_t)pe.portev_events,
		    BUNYAN_T_UINT64, "object", (uint64_t)pe.portev_object,
		    BUNYAN_T_POINTER, "cookie", pe.portev_user,
		    BUNYAN_T_END);

		switch (pe.portev_source) {
		case PORT_SOURCE_TIMER:
			periodic_fire(wk_periodic);
			continue;
		case PORT_SOURCE_FD: {
			char buf[20] = { 0 };

			void (*fn)(int) = (void (*)(int))pe.portev_user;
			int fd = (int)pe.portev_object;

			(void) bunyan_trace(log,
			    "Dispatching fd event to handler",
			    BUNYAN_T_INT32, "fd", (int32_t)fd,
			    BUNYAN_T_STRING, "handler",
			    symstr((void *)fn, buf, sizeof (buf)),
			    BUNYAN_T_END);

			fn(fd);
			continue;
		}
		case PORT_SOURCE_USER:
			do_user(pe.portev_events, pe.portev_user);
			continue;
		case PORT_SOURCE_ALERT:
			do_alert(pe.portev_events, pe.portev_user);
			continue;
		}
	}

	mutex_enter(&worker_lock);
	list_remove(&workers, w);
	wk_nworkers--;
	VERIFY0(cond_broadcast(&worker_cv));
	mutex_exit(&worker_lock);

	worker = NULL;
	worker_free(w);
	return (NULL);
}

static void
do_alert(int events, void *user)
{
	NOTE(ARGUNUSED(user))

	VERIFY(IS_WORKER);

	switch ((worker_alert_t)events) {
	case WA_NONE:
		return;
	case WA_SUSPEND:
		worker_do_suspend();
		return;
	}
}

static void
do_user(int events, void *user)
{
	VERIFY(IS_WORKER);

	(void) bunyan_trace(log, "Received user event",
	    BUNYAN_T_STRING, "event", worker_cmd_str(events),
	    BUNYAN_T_POINTER, "arg", user,
	    BUNYAN_T_END);

	switch ((worker_cmd_t)events) {
	case WC_NONE:
		return;
	case WC_QUIT:
		/*
		 * Unless we are shutting down, must always have at least
		 * one worker running.
		 */
		mutex_enter(&worker_lock);
		if (worker_state == WS_QUITTING || wk_nworkers > 1)
			worker->w_quit = B_TRUE;
		mutex_exit(&worker_lock);
		return;
	case WC_PFKEY:
		ikev2_pfkey(user);
		return;
	case WC_START:
		ikev2_sa_init_cfg(user);
		return;
	}
}

boolean_t
worker_send_cmd(worker_cmd_t cmd, void *arg)
{
again:
	if (port_send(wk_evport, (int)cmd, arg) == 0)
		return (B_TRUE);

	switch (errno) {
	case EAGAIN:
		/* This shouldn't happen, but if it does, we can try again */
		STDERR(warn, "port_send() failed with EAGAIN",
		    BUNYAN_T_STRING, "cmd", worker_cmd_str(cmd),
		    BUNYAN_T_POINTER, "arg", arg);
		goto again;
	case ENOMEM:
		STDERR(warn, "Out of memory trying to send command",
		    BUNYAN_T_STRING, "cmd", worker_cmd_str(cmd),
		    BUNYAN_T_POINTER, "arg", arg);
		break;
	default:
		STDERR(fatal,
		    "Unexpected error trying to send command",
		    BUNYAN_T_STRING, "cmd", worker_cmd_str(cmd),
		    BUNYAN_T_POINTER, "arg", arg);
		abort();
	}

	return (B_FALSE);
}

boolean_t
worker_del(void)
{
	return (worker_send_cmd(WC_QUIT, NULL));
}

#define	STR(x) case x: return (#x)
static const char *
worker_cmd_str(worker_cmd_t wc)
{
	switch (wc) {
	STR(WC_NONE);
	STR(WC_QUIT);
	STR(WC_START);
	STR(WC_PFKEY);
	}

	INVALID(wc);
	return (NULL);
}
#undef STR
