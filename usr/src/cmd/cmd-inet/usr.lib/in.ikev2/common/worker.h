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

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum worker_evt {
	EVT_NONE,
	EVT_PACKET,
	EVT_PFKEY,
	EVT_START	/* Temp. for testing */
} worker_evt_t;

extern size_t nworkers;

void worker_init(size_t, size_t);
void worker_suspend(void);
void worker_resume(void);
boolean_t worker_add(void);
void worker_del(void);
void worker_stop(void);
boolean_t worker_dispatch(worker_evt_t, void *, size_t);

#ifdef __cplusplus
}
#endif

#endif /* _WORKER_H */
