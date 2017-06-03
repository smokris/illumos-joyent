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
	CK_MECHANISM		alg;
	uchar_t			*buf;
	uchar_t			*tbuf;
	size_t			tpos;
	size_t			buflen;
	size_t			tlen;
	uint8_t			*tp;
};
typedef struct prfp_s prfp_t;
#endif /* _PRFP_T */

CK_RV prf_key(CK_MECHANISM_TYPE, const uchar_t *, size_t, CK_OBJECT_HANDLE_PTR);

CK_RV	prfplus_init(prfp_t *, int, CK_OBJECT_HANDLE, const uchar_t *, size_t);
void	prfplus_fini(prfp_t *);
/* this is an internal .h file, no need for ugly _RESTRICT_KYWD */
CK_RV	prfplus(prfp_t *, uchar_t * restrict, size_t * restrict);

#ifdef __cplusplus
}
#endif

#endif /* _PRF_H */
