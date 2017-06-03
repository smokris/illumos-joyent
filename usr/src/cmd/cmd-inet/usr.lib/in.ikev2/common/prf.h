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
 * Copyright 2014 Jason King
 */

#ifndef _PRF_H
#define	_PRF_H

#include <sys/types.h>
#include <security/cryptoki.h>

#include "buf.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifndef _PRFP_T
#define	_PRFP_T
struct prfp_s {
	CK_OBJECT_HANDLE	key;
	int			i2alg;
	buf_t			tbuf[2];
	buf_t			seed;
	buf_t			prf_arg[3];
	size_t			pos;
	uint8_t			n;
};
typedef struct prfp_s prfp_t;
#endif /* _PRFP_T */

/* These are internal to in.ikev2d, so don't bother with ugly !C99 compat */
CK_RV	prf_key(CK_MECHANISM_TYPE, buf_t *restrict, size_t,
	    CK_OBJECT_HANDLE_PTR restrict);

CK_RV	prf(int, CK_OBJECT_HANDLE, buf_t *restrict, size_t, buf_t *restrict);

CK_RV	prfplus_init(prfp_t *restrict, int, CK_OBJECT_HANDLE,
	    const buf_t *restrict);
void	prfplus_fini(prfp_t *);
CK_RV	prfplus(prfp_t *restrict, buf_t *restrict);

size_t	ikev2_prf_keylen(int);

#ifdef __cplusplus
}
#endif

#endif /* _PRF_H */
