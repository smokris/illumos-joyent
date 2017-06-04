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
 * Copyright 2014 Jason King.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _PKCS11_H
#define	_PKCS11_H

#include <sys/types.h>
#include <security/cryptoki.h>
#include "defs.h"
#include "ikev2.h"
#include "buf.h"

#ifdef __cplusplus
extern "C" {
#endif

/* XXX: Temporary definitions until AES_[GC]CM support is putback */

#define	CKM_AES_CCM	0x80000001
#define	CKM_AES_GCM	0x80000002

/* BEGIN CSTYLED */
typedef struct CK_CCM_PARAMS {
    CK_ULONG    ulDataLen;
    CK_BYTE_PTR pNonce;
    CK_ULONG    ulNonceLen;
    CK_BYTE_PTR pAAD;
    CK_ULONG    ulAADLen;
    CK_ULONG    ulMACLen;
} CK_CCM_PARAMS;

typedef struct CK_GCM_PARAMS {
    CK_BYTE_PTR pIv;
    CK_ULONG    ulIvLen;
    CK_BYTE_PTR pAAD;
    CK_ULONG    ulAADLen;
    CK_ULONG    ulTagBits;
} CK_GCM_PARAMS;

typedef CK_CCM_PARAMS * CK_CCM_PARAMS_PTR;
typedef CK_GCM_PARAMS * CK_GCM_PARAMS_PTR;
/* END CSTYLED */

typedef struct {
	ikev2_xf_encr_t		i2_encr;
	CK_MECHANISM_TYPE	p11_encr;
	size_t			block_sz;
	size_t			iv_len;
	size_t			key_min;
	size_t			key_max;
	size_t			key_default;
	size_t			key_incr;
} encr_param_t;
#define	KEYLEN_REQ(ep)		((ep)->key_default == 0)
#define	KEYLEN_EMPTY(ep)	((ep)->key_incr == 0)
#define	KEYLEN_OK(ep, len)	((len) >= (ep)->key_min && \
	(len) <= (ep)->key_max && \
	((a)->key_incr == 0 || (len) % (a)->key_incr == 0))

typedef struct {
	ikev2_xf_auth_t		i2_auth;
	CK_MECHANISM_TYPE	p11_auth;
	size_t			output_sz;
	size_t			trunc_sz;
	size_t			key_sz;
} auth_param_t;

/* PKCS#11 functions. */
void pkcs11_global_init(void);
void pkcs11_global_fini(void);

boolean_t pkcs11_worker_init(void);
void pkcs11_worker_fini(void *);

boolean_t pkcs11_digest(CK_MECHANISM_TYPE, const buf_t *restrict, size_t,
    buf_t *restrict, int);

void pkcs11_destroy_obj(const char *, CK_OBJECT_HANDLE_PTR, int);

encr_param_t *ikev2_get_encr_param(ikev2_xf_encr_t);
auth_param_t *ikev2_get_auth_param(ikev2_xf_auth_t);

#ifdef __cplusplus
}
#endif

#endif /* _PKCS11_H */
