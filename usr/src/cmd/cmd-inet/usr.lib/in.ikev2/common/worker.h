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

#include <inttypes.h>
#include <thread.h>
#include <security/cryptoki.h>
#include <sys/list.h>
#include "pkt.h"

#ifdef __cplusplus
extern "C" {
#endif

#define	DEFAULT_NUM_WORKERS	4U

struct bunyan_logger;
struct periodic_handle;

typedef enum worker_cmd {
	WC_NONE = 0,
	WC_QUIT,
	WC_PFKEY,
	WC_START,
} worker_cmd_t;

typedef struct worker {
	list_node_t		w_node;
	thread_t		w_tid;
	struct bunyan_logger	*w_log;
	CK_SESSION_HANDLE	w_p11;
	boolean_t		w_quit;
				/*
				 * We create a per-worker buffer for inbound
				 * datagrams so we are always guaranteed we
				 * can receive the datagram and drain it
				 * from the kernel's queue and if we're lucky
				 * be able to log information about it, even
				 * if we have to discard it due to allocation
				 * failures.
				 */
	uint64_t		w_buf[SADB_8TO64(MAX_PACKET_SIZE)];
} worker_t;

extern __thread worker_t *worker;
#define	IS_WORKER	(worker != NULL)

extern struct periodic_handle *wk_periodic;
extern uint64_t wk_initial_nworkers;
extern size_t wk_nworkers;
extern int wk_evport;

void worker_init(size_t);
void worker_suspend(void);
void worker_resume(void);
boolean_t worker_add(void);
boolean_t worker_del(void);
boolean_t worker_send_cmd(worker_cmd_t, void *);

#ifdef __cplusplus
}
#endif

#endif /* _WORKER_H */
