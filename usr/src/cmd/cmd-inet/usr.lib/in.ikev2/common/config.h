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
 * Copyright 2017 Joyent, Inc.
 */
#ifndef _CONFIG_H
#define	_CONFIG_H

#include <sys/types.h>
#include <sys/time.h>

#ifdef __cplusplus
extern "C" {
#endif

extern volatile hrtime_t cfg_retry_max;
extern volatile hrtime_t cfg_retry_init;

#ifdef __cplusplus
}
#endif

#endif /* _CONFIG_H */
