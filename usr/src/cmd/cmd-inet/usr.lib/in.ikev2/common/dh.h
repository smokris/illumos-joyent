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
 * Copyright 2014 Jason King.  All rights reserved.
 */

#ifndef _DH_H
#define	_DH_H

#include <sys/types.h>
#include <security/cryptoki.h>
#include "ikev2.h"

#ifdef __cplusplus
extern "C" {
#endif

struct bunyan_logger;

size_t dh_keysize(ikev2_dh_t);
boolean_t dh_genpair(ikev2_dh_t, CK_OBJECT_HANDLE_PTR restrict,
    CK_OBJECT_HANDLE_PTR restrict, struct bunyan_logger *restrict);
boolean_t dh_derivekey(CK_OBJECT_HANDLE, uint8_t *restrict, size_t,
    CK_OBJECT_HANDLE_PTR restrict, struct bunyan_logger *restrict);

#ifdef __cplusplus
}
#endif

#endif /* _DH_H */
