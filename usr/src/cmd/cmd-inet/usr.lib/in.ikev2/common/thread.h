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
 * Copyright 2014 Jason King.
 */

#ifndef _IKEV2_THREAD_H
#define	_IKEV2_THREAD_H

#include <sys/types.h>
#include <pthread.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum ike_thread_e {
	TT_UNUSED,
	TT_MAIN,		/* main thread */
	TT_SIGNAL,		/* signal handler */
	TT_INBOUND,		/* inbound socket */
	TT_PFKEY,		/* pfkey worker */
	TT_WORKER		/* ike worker */
} ike_thread_t;

typedef struct thread_map_s {
	pthread_t	tid;
	ike_thread_t	type;
} thread_map_t;

extern thread_map_t	*thread_map;
extern size_t		nthreads;

#ifdef __cplusplus
}
#endif

#endif /* _IKEV2_THREAD_H */
