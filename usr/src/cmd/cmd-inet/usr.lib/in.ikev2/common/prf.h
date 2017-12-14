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
 * Copyright 2017 Jason King
 * Copyright (c) 2017, Joyent, Inc.
 */

#ifndef _PRF_H
#define	_PRF_H

#include <sys/types.h>
#include <security/cryptoki.h>
#include "ikev2.h"

#ifdef __cplusplus
extern "C" {
#endif

#define	PRFP_NUM_TBUF	(2)
typedef struct prfp_s {
	CK_OBJECT_HANDLE	prfp_key;
	ikev2_prf_t		prfp_alg;
	uint8_t			*prfp_tbuf[PRFP_NUM_TBUF];
	size_t			prfp_tbuflen;
	uint8_t			*prfp_seed;
	size_t			prfp_seedlen;
	size_t			prfp_pos;
	uint8_t			prfp_n;
} prfp_t;

boolean_t prf(ikev2_prf_t, CK_OBJECT_HANDLE, uint8_t *restrict, size_t, ...);
boolean_t prfplus_init(prfp_t *restrict, ikev2_prf_t, CK_OBJECT_HANDLE, ...);
void prfplus_fini(prfp_t *);
boolean_t prfplus(prfp_t *restrict, uint8_t *restrict, size_t);

boolean_t prf_to_p11key(prfp_t *restrict, const char *restrict,
    CK_MECHANISM_TYPE, size_t, CK_OBJECT_HANDLE_PTR restrict);

CK_MECHANISM_TYPE ikev2_prf_to_p11(ikev2_prf_t);
size_t	ikev2_prf_keylen(ikev2_prf_t);
size_t	ikev2_prf_outlen(ikev2_prf_t);

#ifdef __cplusplus
}
#endif

#endif /* _PRF_H */
