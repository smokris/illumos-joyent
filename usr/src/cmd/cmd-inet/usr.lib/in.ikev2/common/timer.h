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
/*
 * Timer events are sorted into a single mutex-protected list.
 * They are insertion-sorted by next-to-expire.
 */

#ifndef _IKEV2_TIMER_H
#define _IKEV2_TIMER_H

#include <bunyan.h>
#include <sys/types.h>

#ifdef  __cplusplus
extern "C" {
#endif

typedef enum {
        TE_TEST = -1,   /* For code testing only, arg == NULL */
        TE_ANY,         /* MUST NOT be passed to schedule_timeout() */
        TE_SA_EXPIRE,   /* SA expiration */
        TE_COOKIE_GEN,  /* Cookie generation */
        TE_TRANSMIT,    /* Transmit timeout */
        TE_PFKEY        /* pfkey timeout */
} te_event_t;

typedef void (*tevent_cb_fn)(te_event_t, void *);

extern void		process_timer(timespec_t *, bunyan_logger_t *);
extern int		cancel_timeout(te_event_t, void *, bunyan_logger_t *);
extern boolean_t	schedule_timeout(te_event_t, tevent_cb_fn, void *,
    hrtime_t);

extern void ike_timer_init(void);
extern void ike_timer_thread_init(void);

#ifdef  __cplusplus
}
#endif

#endif  /* _IKEV2_TIMER_H */
