
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
 */

#ifndef _IKEV2D_DEFS_H
#define _IKEV2D_DEFS_H

#include <sys/types.h>
#include <sys/socket.h>

#if 0
#include <ikedoor.h>
#include <cryptoutil.h>
#endif

#include <security/cryptoki.h>
#include <stdio.h>
#include <assert.h>
#include <umem.h>

#ifdef  __cplusplus
extern "C" {
#endif

#ifndef SOCKADDR_U_T
#define	SOCKADDR_U_T
typedef union sockaddr_u_s {
	struct sockaddr_storage *sau_ss;
	struct sockaddr_in	*sau_sin;
	struct sockaddr_in6	*sau_sin6;
} sockaddr_u_t;
#endif /* SOCKADDR_U_T */

#ifdef  __cplusplus
}
#endif

#endif  /* _IKEV2D_DEFS_H */

