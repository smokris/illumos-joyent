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

#ifndef _WORKER_H
#define	_WORKER_H

#include <bunyan.h>
#include <thread.h>
#include <security/cryptoki.h>
#include <stddef.h>
#include <synch.h>
#include "ilist.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum worker_msg_e {
	WMSG_NONE,
	WMSG_PACKET,
	WMSG_PFKEY,
	WMSG_START,		/* Temp. for testing */
	WMSG_START_P1_TIMER,
} worker_msg_t;

typedef enum worker_cmd_e {
	WC_NONE,
	WC_SUSPEND,
	WC_QUIT
} worker_cmd_t;

/*
 * The full lifetime of the wi_data argument depends on the type of message
 * associated with it.  For every message type however, it can be assumed
 * that the worker itself will handle any deallocation and the caller need
 * not concern themselves with it unless dispatching fails.
 */
typedef struct worker_item_s {
	worker_msg_t	wi_msgtype;
	void		*wi_data;
} worker_item_t;

typedef struct worker_queue_s {
	mutex_t		wq_lock;
	cond_t		wq_cv;
	worker_cmd_t	wq_cmd;
	worker_item_t	*wq_items;
	size_t		wq_start;
	size_t		wq_end;
} worker_queue_t;

typedef struct worker_s {
	thread_t		w_tid;
	bunyan_logger_t		*w_log;
	worker_queue_t		w_queue;
	ilist_t			w_timers;
	boolean_t		w_done;
	CK_SESSION_HANDLE	w_p11;
} worker_t;

extern __thread worker_t *worker;
#define	IS_WORKER	(worker != NULL)

extern size_t wk_nworkers;

void worker_init(size_t, size_t);
void worker_suspend(void);
void worker_resume(void);
boolean_t worker_add(void);
void worker_del(void);
void worker_stop(void);
boolean_t worker_dispatch(worker_msg_t, void *, size_t);

#ifdef __cplusplus
}
#endif

#endif /* _WORKER_H */
