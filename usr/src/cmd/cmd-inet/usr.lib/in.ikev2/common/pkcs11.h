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
 * Copyright (c) 2017, Joyent, Inc.
 */

#ifndef _PKCS11_H
#define	_PKCS11_H

#include <sys/types.h>
#include <security/cryptoki.h>
#include <bunyan.h>
#include "defs.h"
#include "ikev2.h"

#ifdef __cplusplus
extern "C" {
#endif

#define	PKCS11ERR(_lvl, _log, _p11f, _rv, ...)				\
	(void) bunyan_##_lvl((_log), "PKCS#11 call failed",		\
	BUNYAN_T_STRING, "func", _p11f,					\
	BUNYAN_T_UINT64, "errnum", (uint64_t)(_rv),			\
	BUNYAN_T_STRING, "err", pkcs11_strerror(_rv),			\
	## __VA_ARGS__,							\
	BUNYAN_T_END)

typedef enum encr_mode {
	MODE_NONE,
	MODE_CBC,
	MODE_CTR,
	MODE_CCM,
	MODE_GCM
} encr_modes_t;
#define	MODE_IS_COMBINED(m) ((m) == MODE_CCM || (m) == MODE_GCM)

extern CK_INFO pkcs11_info;

void pkcs11_init(void);
void pkcs11_fini(void);

CK_SESSION_HANDLE p11h(void);
void pkcs11_destroy_obj(const char *, CK_OBJECT_HANDLE_PTR, bunyan_logger_t *);

CK_MECHANISM_TYPE ikev2_encr_to_p11(ikev2_xf_encr_t);
encr_modes_t ikev2_encr_mode(ikev2_xf_encr_t);
size_t ikev2_encr_block_size(ikev2_xf_encr_t);
size_t ikev2_encr_iv_size(ikev2_xf_encr_t);
size_t ikev2_encr_keylen(ikev2_xf_encr_t, size_t);
size_t ikev2_auth_keylen(ikev2_xf_auth_t);
size_t ikev2_encr_saltlen(ikev2_xf_encr_t);

CK_MECHANISM_TYPE ikev2_auth_to_p11(ikev2_xf_auth_t);
size_t ikev2_auth_icv_size(ikev2_xf_encr_t, ikev2_xf_auth_t);

#ifdef __cplusplus
}
#endif

#endif /* _PKCS11_H */
