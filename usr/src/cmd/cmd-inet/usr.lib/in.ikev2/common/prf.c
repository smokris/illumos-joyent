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
 */
#include <sys/debug.h>
#include <security/cryptoki.h>
#include <umem.h>
#include <limits.h>
#include <string.h>
#include "defs.h"
#include "ikev2.h"
#include "prf.h"
#include "pkcs11.h"

typedef struct prf_alg_s {
	int			i2alg;
	CK_MECHANISM_TYPE	hash;
	CK_MECHANISM_TYPE	hmac;
	size_t			inlen;	/* in bytes */
	size_t			outlen; /* in bytes */
	boolean_t		pad;
} prf_alg_t;

#define	MECHPAD(_i2, _p11, _in, _out) { 	\
	.i2alg = IKEV2_XFORMPRF_HMAC_ ## _i2,	\
	.hash = CKM_ ## _p11,			\
	.hmac = CKM_ ## _p11 ## _HMAC,		\
	.inlen = _in,				\
	.outlen = _out,				\
	.pad = B_TRUE				\
}

static const prf_alg_t prf_tbl[] = {
	MECHPAD(MD5, MD5, 64, 16),
	MECHPAD(SHA1, SHA_1, 64, 16),
	MECHPAD(SHA2_256, SHA256, 64, 32),
	MECHPAD(SHA2_384, SHA384, 128, 48),
	MECHPAD(SHA2_512, SHA512, 128, 64)
};
#define	N_PRF (sizeof (prf_tbl) / sizeof (prf_alg_t))

static const prf_alg_t	*get_alg(int);
static CK_RV		prfplus_update(prfp_t *);

/*
 * Create a PKCS11 key object that can be used in C_Sign* operations with
 * a scatter/gather-like listing of source input.
 *
 * Args:
 * 	alg	The PRF algorithm this will be used with
 * 	src	An array of buf_t's pointing to the source key
 * 	n	The number of buf_t's we have
 *	kp	Pointer to CK_OBJECT_HANDLE to write the resulting key
 *		object.
 * Returns:
 * 	CKR_OK	Success
 */
CK_RV
prf_genkey(int alg, buf_t *restrict src, size_t n,
    CK_OBJECT_HANDLE_PTR restrict kp)
{
	const prf_alg_t	*algp;

	CK_RV			rc;
	CK_OBJECT_CLASS		cls = CKO_SECRET_KEY;
	CK_KEY_TYPE		kt = CKK_GENERIC_SECRET;
	CK_BBOOL		false_v = CK_FALSE;
	CK_MECHANISM_TYPE	hmac;
	CK_ATTRIBUTE		template[] = {
		{ CKA_VALUE, NULL_PTR, 0 },	/* filled in later */
		{ CKA_CLASS, &cls, sizeof (cls) },
		{ CKA_KEY_TYPE, &kt, sizeof (kt) },
		/* XXX: is this actually needed? */
		{ CKA_ALLOWED_MECHANISMS, &hmac, sizeof (hmac) },
		{ CKA_MODIFIABLE, &false_v, sizeof (false_v) }
	};
	buf_t			key = { 0 };
	size_t			srclen;
	ulong_t			keylen = 0; /* actual length */

	rc = CKR_OK;

	VERIFY((algp = get_alg(alg)) != NULL);
	hmac = algp->hmac;

	srclen = 0;
	for (size_t i = 0; i < n; i++)
		srclen += buf_left(&src[i]);

	if (srclen < algp->inlen && algp->pad)
		keylen = algp->inlen;
	else
		keylen = srclen;

	if (!buf_alloc(&key, keylen)) {
		rc = CKR_HOST_MEMORY;
		goto done;
	}
	buf_set_write(&key);

	/*
	 * The HMAC standards specify what an implementation should do when
	 * the given key length doesn't match the preferred key length (either
	 * pad or run the digest alg on the key to yield a value of the desired
	 * length), so we should not need to worry about this.
	 */
	VERIFY3U(buf_copy(&key, src, n), <=, keylen);

	template[0].pValue = key.b_buf;
	template[0].ulValueLen = keylen;

	rc = C_CreateObject(p11h, template,
	    sizeof (template) / sizeof (CK_ATTRIBUTE), kp);

done:
	buf_free(&key);
	return (rc);
}

/*
 * Run the given PRF algorithm for the given key and seed and place
 * result into out.
 */
CK_RV
prf(int alg, CK_OBJECT_HANDLE key, buf_t *restrict seed, size_t nseed,
    buf_t *restrict out)
{
	const prf_alg_t		*algp;
	CK_MECHANISM		mech;
	CK_RV			rc = CKR_OK;
	CK_ULONG		len;

	VERIFY3P((algp = get_alg(alg)), !=, NULL);
	VERIFY3U(out->b_len, >=, algp->outlen);

	mech.mechanism = algp->hmac;
	mech.pParameter = NULL;
	mech.ulParameterLen = 0;

	if ((rc = C_SignInit(p11h, &mech, key)) != CKR_OK)
		return (rc);

	for (size_t i = 0; i < nseed; i++, seed) {
		BUF_IS_READ(seed);
		rc = C_SignUpdate(p11h, seed->b_ptr, buf_left(seed));
		/* XXX: should we still call C_SignFinal? */
		if (rc != CKR_OK)
			return (rc);
	}

	BUF_IS_WRITE(out);

	len = buf_left(out);
	rc = C_SignFinal(p11h, out->b_ptr, &len);
	if (rc == CKR_OK)
		VERIFY3U(len, ==, buf_left(out));

	buf_skip(out, len);
	return (rc);
}

/*
 * Inititalize a prf+ instance for the given algorithm, key, and seed.
 */
CK_RV
prfplus_init(prfp_t *restrict prfp, int alg, CK_OBJECT_HANDLE key,
    const buf_t *restrict seed)
{
	const prf_alg_t	*algp;
	CK_RV		rc = CKR_OK;

	(void) memset(prfp, 0, sizeof (*prfp));

	VERIFY((algp = get_alg(alg)) != NULL);

	if (!buf_alloc(&prfp->tbuf[0], algp->outlen) ||
	    !buf_alloc(&prfp->tbuf[1], algp->outlen) ||
	    !buf_alloc(&prfp->seed, buf_left(seed))) {
		rc = CKR_HOST_MEMORY;
		goto error;
	}

	/* stash our own copy of the seed */
	(void) buf_copy(&prfp->seed, seed, 1);
	VERIFY(!buf_eof(&prfp->seed));

	/*
	 * Per RFC5996 2.13, prf+(K, S) = T1 | T2 | T3 | T4 | ...
	 * 
	 * where:
	 * 	T1 = prf (K, S | 0x01)
	 * 	T2 = prf (K, T1 | S | 0x02)
	 * 	T3 = prf (K, T2 | S | 0x03)
	 * 	T4 = prf (K, T3 | S | 0x04)
	 *
	 * As such, we keep a list of buf_t's for each of the three components
	 * Since the last two never change location, they are set now, while
	 * the first points to either prfp->tbuf[0] or prfp->tbuf[1], based
	 * on the value of prfp->n
	 */
	prfp->prf_arg[1] = prfp->seed;
	prfp->prf_arg[2].b_ptr = prfp->prf_arg[2].b_buf = &prfp->n;
	prfp->prf_arg[2].b_len = sizeof (prfp->n);
	prfp->n = 1;

	buf_set_read(&prfp->prf_arg[1]);
	buf_set_read(&prfp->prf_arg[2]);

	/*
	 * Fill prfp->tbuf[1] with T1. T1 is defined as:
	 * 	T1 = prf (K, S | 0x01)
	 * Note that this is different from subsequent iterations, hence
	 * starting at prfp->prf_arg[1], not prfp->arg[0]
	 */
	rc = prf(alg, prfp->key, &prfp->prf_arg[1], 2, &prfp->tbuf[1]);
	return (rc);

error:
	prfplus_fini(prfp);
	return (rc);
}

/*
 * Fill out with the result of the prf+ function.
 */
CK_RV
prfplus(prfp_t *restrict prfp, buf_t *restrict out)
{
	const prf_alg_t	*algp;
	buf_t		t;
	buf_t		outcopy;
	CK_RV		rc = CKR_OK;

	algp = get_alg(prfp->i2alg);

	/* generate a local cache of out so we can manipulate the ptr and len */
	outcopy = *out;
	buf_set_write(&outcopy);

	while (buf_left(&outcopy) > 0) {
		size_t chunk;

		chunk = buf_left(&outcopy);

		if (prfp->n & 0x01)
			t = prfp->tbuf[1];
		else
			t = prfp->tbuf[0];

		t.b_ptr += prfp->pos;
		t.b_len -= prfp->pos;

		if (t.b_len == 0) {
			if ((rc = prfplus_update(prfp)) != CKR_OK)
				goto done;
			continue;
		}

		if (chunk > t.b_len)
			chunk = t.b_len;

		VERIFY(buf_copy(&outcopy, &t, chunk) == chunk);
		buf_skip(&outcopy, chunk);
		prfp->pos += chunk;
	}

done:
	return (rc);
}

/*
 * Perform a prf+ iteration
 */
static CK_RV
prfplus_update(prfp_t *prfp)
{
	buf_t	*dest;
	CK_RV	rc = CKR_OK;

	ASSERT(prfp->n >= 1);

	if (prfp->n == 0xff) {
		/* XXX: log error */
		return (CKR_GENERAL_ERROR);
	}

	if (++prfp->n & 0x01) {
		prfp->prf_arg[1] = prfp->tbuf[1];
		dest = &prfp->tbuf[0];
	} else {
		prfp->prf_arg[0] = prfp->tbuf[0];
		dest = &prfp->tbuf[1];
	}

	rc = prf(prfp->i2alg, prfp->key, prfp->prf_arg, 3, dest);
	prfp->pos = 0;
	return (rc);
}

void
prfplus_fini(prfp_t *prfp)
{
	if (prfp == NULL)
		return;

	buf_free(&prfp->tbuf[0]);
	buf_free(&prfp->tbuf[1]);
	buf_free(&prfp->seed);
	(void) memset(prfp, 0, sizeof (*prfp));
}

CK_MECHANISM_TYPE
ikev2_prf_to_p11(int prf)
{
	switch (prf) {
	case IKEV2_XFORMPRF_HMAC_MD5:
		return (CKM_MD5_HMAC);
	case IKEV2_XFORMPRF_HMAC_SHA1:
		return (CKM_SHA_1_HMAC);
	case IKEV2_XFORMPRF_HMAC_SHA2_256:
		return (CKM_SHA256_HMAC);
	case IKEV2_XFORMPRF_HMAC_SHA2_384:
		return (CKM_SHA384_HMAC);
	case IKEV2_XFORMPRF_HMAC_SHA2_512:
		return (CKM_SHA512_HMAC);
	}

	INVALID("invalid hmac value");

	/*NOTREACHED*/
	return (0);
}

size_t
ikev2_prf_keylen(int prf)
{
	return (get_alg(prf)->inlen);
}

/*
 * Get the information for a given algorithm, or NULL of not found
 */
static const prf_alg_t *
get_alg(int i2alg)
{
	for (int i = 0; i < N_PRF; i++) {
		if (prf_tbl[i].i2alg == i2alg)
			return (&prf_tbl[i]);
	}
	return (NULL);
}
