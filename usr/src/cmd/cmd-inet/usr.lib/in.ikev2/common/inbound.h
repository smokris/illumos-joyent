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
 * Copyright 2015 Jason King.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _INBOUND_H
#define	_INBOUND_H

#ifdef __cplusplus
extern "C" {
#endif

extern int ikesock4, ikesock6, nattsock;

void inbound_init(void);

#ifdef __cplusplus
}
#endif

#endif /* _INBOUND_H */
