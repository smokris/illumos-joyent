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

#include <syslog.h>
#include <assert.h>
#include <string.h>
#include <ipsec_util.h>
#include <locale.h>
#include <security/cryptoki.h>
#include <pthread.h>
#include <sys/debug.h>
#include <note.h>
#include "pkcs11.h"
#include "defs.h"

#define	METASLOT_NAME "Sun Metaslot"

static CK_SLOT_ID	metaslot;

/*
 * PKCS#11 allows us to share public objects between sessions within
 * the same process.  However, when a session is closed, any objects
 * created by that session are destroyed.  This obviously would
 * create a problem for IKEv2 SAs if we shrink our thread pool size.
 *
 * To address this, we maintain a pool of free PKCS#11 sessions, and
 * attempt to allocate from that first, only calling C_CreateSession
 * if there are no sessions in the free pool.  Upon thread termination,
 * the session is returned to the free pool.
 */
static pthread_mutex_t		ses_free_lock = PTHREAD_MUTEX_INITIALIZER;
static CK_SESSION_HANDLE_PTR	ses_free_list;
static int			ses_nfree;
static int			ses_alloc;

static pthread_key_t		p11_key = PTHREAD_ONCE_KEY_NP;

#define	PKCS11_FUNC		"func"
#define	PKCS11_RC		"retcode"
#define	PKCS11_ERRMSG		"errmsg"

/*
 * Now using libcryptoutil's pkcs11_strerror().
 */
static void
pkcs11_error(CK_RV errval, char *func)
{
	bunyan_error(log, "PKCS#11 call failed",
	    BUNYAN_T_STRING, PKCS11_FUNC, func,
	    BUNYAN_T_UINT64, PKCS11_RC, (uint64_t)errval,
	    BUNYAN_T_STRING, PKCS11_ERRMSG, pkcs11_strerror(errval),
	    BUNYAN_T_END);
}

static CK_RV
pkcs11_callback_handler(CK_SESSION_HANDLE session, CK_NOTIFICATION surrender,
    void *context)
{
	_NOTE(ARGUNUSED(session, context));
	assert(surrender == CKN_SURRENDER);

	return (CKR_OK);
}

static boolean_t
is_metaslot(CK_SLOT_ID slot, void *args, CK_RV *rv)
{
	CK_SLOT_INFO info = { 0 };
	boolean_t *found = (boolean_t *)args;

	*rv = C_GetSlotInfo(slot, &info);
	if (*rv != CKR_OK)
		return (B_FALSE);

	if (strncmp(METASLOT_NAME, (const char *)info.slotDescription,
	    sizeof(METASLOT_NAME)) != 0)
		return (B_FALSE);

	metaslot = slot;
	*found = B_TRUE;
	return (B_TRUE);
}

/*
 * Locates the metaslot among the available slots.  If the metaslot
 * is inable to be located, we terminate.
 */
void
pkcs11_global_init(void)
{
	CK_SESSION_HANDLE p11h = CK_INVALID_HANDLE;
	CK_RV		rv = CKR_OK;
	boolean_t	found = B_FALSE;
	int		rc;

	/* Init PKCS#11, find the metaslot, and open an initial session */
	rv = pkcs11_GetCriteriaSession(is_metaslot, &found, &p11h);
	if (rv != CKR_OK) {
		bunyan_fatal(log, "PKCS#11 call failed",
		    BUNYAN_T_STRING, PKCS11_FUNC, "pkcs11_GetCriteriaSession",
		    BUNYAN_T_UINT64, PKCS11_RC, (uint64_t)rv,
		    BUNYAN_T_STRING, PKCS11_ERRMSG, pkcs11_strerror(rv),
		    BUNYAN_T_END);
		exit(1);
	}

	if (!found) {
		bunyan_fatal(log, "Unable to locate the metaslot",
		    BUNYAN_T_END);
		exit(1);
	}

	PTH(pthread_key_create_once_np(&p11_key, pkcs11_worker_fini));
	PTH(pthread_setspecific(p11_key, (const void *)p11h));
}

/*
 * Closes all open PKCS#11 Sessions.
 *
 * This assumes that all worker threads have terminated prior to being
 * invoked.  If not, some sessions may not be explicitly closed.
 */
void
pkcs11_global_fini(void)
{
	CK_RV rc;

	for (size_t i = 0; i < ses_nfree; i++) {
		if ((rc = C_CloseSession(ses_free_list[i])) != CKR_OK)
			pkcs11_error(rc, "C_CloseSession");
	}
}

/*
 * Create a PKCS#11 session for a worker thread.
 *
 * This will search the free list for an unused PKCS#11 session
 * and assign the session to the p11s TLS variable.  If no sessions
 * are on the free list, a new session will be created.  This is called
 * by the worker thread.
 *
 * On sucess, B_TRUE is returned.  Otherwise B_FALSE is returned.
 */
boolean_t
pkcs11_worker_init(void)
{
	CK_SESSION_HANDLE p11h = CK_INVALID_HANDLE;

	/*
	 * for simplicity, we push and pop sessions from the end
	 * of the list.
	 */
	PTH(pthread_mutex_lock(&ses_free_lock));
	if (ses_nfree > 0) {
		p11h = ses_free_list[--ses_nfree];
		PTH(pthread_mutex_unlock(&ses_free_lock));
		goto done;
	}
	PTH(pthread_mutex_unlock(&ses_free_lock));

	CK_RV rc = C_OpenSession(metaslot, CKF_SERIAL_SESSION, NULL,
	    pkcs11_callback_handler, &p11h);
	if (rc != CKR_OK) {
		pkcs11_error(rc, "C_OpenSession");
		return (B_FALSE);
	}

done:
	PTH(pthread_setspecific(p11_key, (const void *)p11h));
	return (B_TRUE);
}

/*
 * Append a PKCS#11 session into the free list and set the TLS session
 * handle p11s to CK_INVALID_SESSION.  Called when a worker thread is
 * terminated.
 */

#define	SES_FREE_CHUNK 8	/* Used when expanding the session free list */
void
pkcs11_worker_fini(void *arg)
{
	CK_SESSION_HANDLE p11h = (CK_SESSION_HANDLE)arg;

	PTH(pthread_mutex_lock(&ses_free_lock));
	if (ses_nfree + 1 > ses_alloc) {
		size_t nelem = ses_alloc + SES_FREE_CHUNK;
		size_t nsize = nelem * sizeof (CK_SESSION_HANDLE);

		/*
		 * we would almost definitely error out creating a PKCS#11
		 * session before we could possibly overflow the free list,
		 * however to be absolutely safe, we bail horribly if we do.
		 */
		VERIFY3U(nsize, >, nelem);
		VERIFY3U(nsize, >, sizeof (CK_SESSION_HANDLE));

		CK_SESSION_HANDLE *temp = realloc(ses_free_list, nsize);

		if (temp == NULL)
			err(EXIT_FAILURE, "out of memory");

		ses_free_list = temp;
		ses_alloc = nelem;
	}

	ses_free_list[ses_nfree++] = p11h;
	PTH(pthread_mutex_unlock(&ses_free_lock));
}

CK_SESSION_HANDLE
p11s(void)
{
	return ((CK_SESSION_HANDLE)pthread_getspecific(p11_key));
}

static auth_param_t auth_params[] = {
	{
		.i2_auth = IKEV2_AUTH_NONE,
		.p11_auth = 0,
		.output_sz = 0,
		.trunc_sz = 0,
		.key_sz = 0,
	},
	{
		.i2_auth = IKEV2_AUTH_HMAC_MD5_96,
		.p11_auth = CKM_MD5_HMAC,
		.output_sz = 16,
		.trunc_sz = 12,
		.key_sz = 16
	},
	{
		.i2_auth = IKEV2_AUTH_HMAC_SHA1_96,
		.p11_auth = CKM_SHA_1_HMAC,
		.output_sz = 20,
		.trunc_sz = 12,
		.key_sz = 20,
	},
	{
		.i2_auth = IKEV2_AUTH_DES_MAC,
		.p11_auth = CKM_DES_MAC,
		.output_sz = 8,
		.trunc_sz = 8,
		.key_sz = 8,
	},
	{
		.i2_auth = IKEV2_AUTH_KPDK_MD5,
		.p11_auth = 0,
		.output_sz = 0,
		.trunc_sz = 0,
		.key_sz = 0
	},
	{
		.i2_auth = IKEV2_AUTH_AES_XCBC_96,
		.p11_auth = 0,
		.output_sz = 16,
		.trunc_sz = 12,
		.key_sz = 16
	},
	{
		.i2_auth = IKEV2_AUTH_HMAC_MD5_128,
		.p11_auth = CKM_MD5_HMAC,
		.output_sz = 16,
		.trunc_sz = 16,
		.key_sz = 16
	},
	{
		.i2_auth = IKEV2_AUTH_HMAC_SHA1_160,
		.p11_auth = CKM_SHA_1_HMAC,
		.output_sz = 20,
		.trunc_sz = 20,
		.key_sz = 20,
	},
	{
		.i2_auth = IKEV2_AUTH_AES_CMAC_96,
		.p11_auth = 0,
		.output_sz = 16,
		.trunc_sz = 12,
		.key_sz = 16,
	},
	{
		.i2_auth = IKEV2_AUTH_HMAC_SHA2_256_128,
		.p11_auth = CKM_SHA256_HMAC,
		.output_sz = 32,
		.trunc_sz = 16,
		.key_sz = 32
	},
	{
		.i2_auth = IKEV2_AUTH_HMAC_SHA2_384_192,
		.p11_auth = CKM_SHA384_HMAC,
		.output_sz = 48,
		.trunc_sz = 24,
		.key_sz = 48
	},
	{
		.i2_auth = IKEV2_AUTH_HMAC_SHA2_512_256,
		.p11_auth = CKM_SHA512_HMAC,
		.output_sz = 64,
		.trunc_sz = 32,
		.key_sz = 64
	}
};

static encr_param_t encr_params[] = {
	{
		.i2_encr = IKEV2_ENCR_DES_IV64,
		.p11_encr = CKM_DES_CBC,
		.block_sz = 8,
		.iv_len = 8,
		.key_min = 64,
		.key_max = 64,
		.key_default = 64,
		.key_incr = 0,
	},
	{
		.i2_encr = IKEV2_ENCR_DES,
		.p11_encr = CKM_DES_CBC,
		.block_sz = 8,
		.iv_len = 0,
		.key_min = 64,
		.key_max = 64,
		.key_default = 64,
		.key_incr = 0,
	},
	{
		.i2_encr = IKEV2_ENCR_3DES,
		.p11_encr = CKM_DES3_CBC,
		.block_sz = 8,
		.iv_len = 8,
		.key_min = 192,
		.key_max = 192,
		.key_default = 192,
		.key_incr = 0,
	},
	{
		.i2_encr = IKEV2_ENCR_RC5,
		.p11_encr = CKM_RC5_CBC,
		.block_sz = 8,
		.iv_len = 8,
		.key_min = 40,
		.key_max = 2040,
		.key_default = 128,
		.key_incr = 1,
	},
	{
		.i2_encr = IKEV2_ENCR_IDEA,
		.p11_encr = CKM_IDEA_CBC,
		.block_sz = 8,
		.iv_len = 8,
		.key_min = 128,
		.key_max = 128,
		.key_default = 128,
		.key_incr = 0,
	},
	{
		.i2_encr = IKEV2_ENCR_CAST,
		.p11_encr = CKM_CAST5_CBC,
		.block_sz = 8,
		.iv_len = 8,
		.key_min = 40,
		.key_max = 128,
		.key_default = 128,
		.key_incr = 1,
	},
	{
		.i2_encr = IKEV2_ENCR_BLOWFISH,
		.p11_encr = CKM_BLOWFISH_CBC,
		.block_sz = 8,
		.iv_len = 8,
		.key_min = 40,
		.key_max = 448,
		.key_default = 128,
		.key_incr = 1,
	},
#if 0
	{
		.i2_encr = IKEV2_ENCR_3IDEA,
		.p11_encr = 0,
		.block_sz = 0,
		.iv_len = 0,
		.key_len = 0,
		.keylen_req = B_FALSE
	},
	{
		.i2_encr = IKEV2_ENCR_DES_IV32,
		.p11_encr = CKM_DES_CBC,
		.block_sz = 8,
		.iv_len = 4,
		.key_len = 8,
		.keylen_req = B_FALSE
	},
	{
		.i2_encr = 0,			/* Reserved */
		.p11_encr = 0,
		.block_sz = 0,
		.iv_len = 0,
		.key_len = 0,
		.keylen_req = B_FALSE
	},
	{
		.i2_encr = IKEV2_ENCR_NULL,
		.p11_encr = 0,
		.block_sz = 0,
		.iv_len = 0,
		.key_len = 0,
		.keylen_req = B_FALSE
	},
#endif
	{
		.i2_encr = IKEV2_ENCR_AES_CBC,
		.p11_encr = CKM_AES_CBC,
		.block_sz = 16,
		.iv_len = 16,
		.key_min = 128,
		.key_max = 256,
		.key_incr = 64,
		.key_default = 0,
	},
#if 0
	{
		.i2_encr = IKEV2_ENCR_AES_CTR,
		.p11_encr = CKM_AES_CTR,
		.block_sz = 16,
		.iv_len = 8,
		.key_len = 16,
		.keylen_req = B_FALSE
	},
#endif

	{
		.i2_encr = IKEV2_ENCR_AES_CCM_8,
		.p11_encr = CKM_AES_CCM,
		.block_sz = 16,
		.iv_len = 12,
		.key_min = 128,
		.key_max = 256,
		.key_incr = 64,
		.key_default = 0,
	},
	{
		.i2_encr = IKEV2_ENCR_AES_CCM_12,
		.p11_encr = CKM_AES_CCM,
		.block_sz = 16,
		.iv_len = 12,
		.key_min = 128,
		.key_max = 256,
		.key_incr = 64,
		.key_default = 0
	},
	{
		.i2_encr = IKEV2_ENCR_AES_CCM_16,
		.p11_encr = CKM_AES_CCM,
		.block_sz = 16,
		.iv_len = 12,
		.key_min = 128,
		.key_max = 256,
		.key_incr = 64,
		.key_default = 0
	},
#if 0
	{
		.i2_encr = 0,		/* Unassigned */
		.p11_encr = 0,
		.block_sz = 0,
		.iv_len = 0,
		.key_len = 0,
		.keylen_req = B_FALSE
	},
	{
		.i2_encr = IKEV2_ENCR_AES_GCM_ICV8,
		.p11_encr = 0, /* CKM_AES_GCM */
		.block_sz = 16,
		.iv_len = 8,
		.key_len = 16,
		.keylen_req = B_FALSE
	},
	{
		.i2_encr = IKEV2_ENCR_AES_GCM_ICV12,
		.p11_encr = 0, /* CKM_AES_GCM */
		.block_sz = 16,
		.iv_len = 12,
		.key_len = 16,
		.keylen_req = B_FALSE
	},
	{
		.i2_encr = IKEV2_ENCR_AES_GCM_ICV16,
		.p11_encr = 0, /* CKM_AES_GCM */
		.block_sz = 16,
		.iv_len = 16,
		.key_len = 16,
		.keylen_req = B_FALSE
	},
	{
		.i2_encr = IKEV2_ENCR_NULL_AUTH_AES_GMAC,
		.p11_encr = 0,
		.block_sz = 16,
		.iv_len = 0,
		.key_len = 16,
		.keylen_req = B_FALSE
	},
	{
		.i2_encr = IKEV2_ENCR_IEEE_P1619_XTS_AES,
		.p11_encr = 0,
		.block_sz = 0,
		.iv_len = 0,
		.key_len = 0,
		.keylen_req = B_FALSE
	},
	{
		.i2_encr = IKEV2_ENCR_CAMELLIA_CBC,
		.p11_encr = CKM_CAMELLIA_CBC,
		.block_sz = 0,
		.iv_len = 0,
		.key_len = 16,
		.keylen_req = B_FALSE
	},
	{
		.i2_encr = IKEV2_ENCR_CAMELLIA_CTR,
		.p11_encr = CKM_CAMELLIA_CTR,
		.block_sz = 0,
		.iv_len = 0,
		.key_len = 16,
		.keylen_req = B_FALSE
	},
	{
		.i2_encr = IKEV2_ENCR_CAMELLIA_CCM_8,
		.p11_encr = 0,
		.block_sz = 0,
		.iv_len = 0,
		.key_len = 16,
		.keylen_req = B_FALSE
	},
	{
		.i2_encr = IKEV2_ENCR_CAMELLIA_CCM_12,
		.p11_encr = 0,
		.block_sz = 0,
		.iv_len = 0,
		.key_len = 16,
		.keylen_req = B_FALSE
	},
	{
		.i2_encr = IKEV2_ENCR_CAMELLIA_CCM_16,
		.p11_encr = 0,
		.block_sz = 0,
		.iv_len = 0,
		.key_len = 16,
		.keylen_req = B_FALSE
	},
#endif
};

auth_param_t *
ikev2_get_auth_param(ikev2_xf_auth_t alg)
{
	int i;

	for (i = 0; i < sizeof (auth_params) / sizeof (auth_param_t); i++) {
		if (auth_params[i].i2_auth == alg)
			return (&auth_params[i]);
	}

	return (NULL);
}

encr_param_t *
ikev2_get_encr_param(ikev2_xf_encr_t alg)
{
	int i;

	for (i = 0; i < sizeof (encr_params) / sizeof (encr_param_t); i++) {
		if (encr_params[i].i2_encr == alg)
			return (&encr_params[i]);
	}

	return (NULL);
}

/*
 * Destroy a PKCS#11 object with nicer error messages in case of failure.
 */
void
pkcs11_destroy_obj(const char *name, CK_OBJECT_HANDLE_PTR objp, int level)
{
	CK_RV ret;

	if (objp == NULL || *objp == CK_INVALID_HANDLE)
		return;

	if ((ret = C_DestroyObject(p11s(), *objp)) != CKR_OK) {
		pkcs11_error(ret, "C_DestroyObject");
	} else {
		*objp = CK_INVALID_HANDLE;
	}
}

/*
 * Scatter/gather digest calculation.
 *
 * Upon failure, B_FALSE is returned.  If failure was due to out being
 * too small, out->iov_len will be set to the minimum size that was
 * required to write out the complete digest.
 */
boolean_t
pkcs11_digest(CK_MECHANISM_TYPE alg, const buf_t *restrict in, size_t n_in,
    buf_t *restrict out, int level)
{
	CK_MECHANISM	mech;
	CK_RV		ret;

	mech.mechanism = alg;
	mech.pParameter = NULL_PTR;
	mech.ulParameterLen = 0;

	if ((ret = C_DigestInit(p11s(), &mech)) != CKR_OK) {
		pkcs11_error(ret, "C_DigestInit");
		return (B_FALSE);
	}

	for (size_t i = 0; i < n_in; i++) {
		ret = C_DigestUpdate(p11s(), in[i].ptr, in[i].len);
		if (ret != CKR_OK) {
			pkcs11_error(ret, "C_DigestUpdate");
			return (B_FALSE);
		}
	}

	CK_ULONG len = out->len;

	ret = C_DigestFinal(p11s(), out->ptr, &len);
	out->len = (size_t)len;

	if (ret != CKR_OK) {
		pkcs11_error(ret, "C_DigestFinal");
		return (B_FALSE);
	}
	return (B_TRUE);
}
