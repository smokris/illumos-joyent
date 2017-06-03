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

#include <alloca.h>
#include <sys/debug.h>

#include "ikev2.h"
#include "prf.h"

typedef struct mech_s {
	CK_MECHANISM_TYPE	mech;
	CK_MECHANISM_TYPE	hmech;
	boolean_t		pad;
	size_t			keysize;
	size_t			bsize;
} mech_t;

#define	MECHP(_alg, _halg, _ks, _bs) { 		\
	.mech = _alg,				\
	.hmech = _halg,				\
	.pad = B_TRUE,				\
	.keysize = _ks,				\
	.bsize = _bs				\
}

static const mech_t mechs[] = {
	MECHP(CKM_MD5_HMAC, CKM_MD5, 64, 16),
	MECHP(CKM_SHA1_HMAC, CKM_SHA_1, 64, 20),
	MECHP(CKM_SHA256_HMAC, CKM_SHA256, 64, 32),
	MECHP(CKM_SHA384_HMAC, CKM_SHA384, 128, 48),
	MECHP(CKM_SHA512_HMAC, CKM_SHA512, 128, 64)
};
#define	N_MECH (sizeof (mechs) / sizeof (mech_t))

static const mech_t *get_mech(CK_MECHANISM_TYPE);
static CK_RV prfplus_update(prfp_t *);

extern __thread CK_SESSION_HANDLE p11s;

/*
 * Create a PKCS11 key object that can be used in C_Sign* operations.
 * If the source data is too large, the supplied digest alg will
 * be performed on the source data before creating the key object.
 *
 * Args:
 * 	alg	The digest alg to use if the source data is too large.
 *	src	The source data.
 *	len	The length of the data.
 *	kp	Pointer to CK_OBJECT_HANDLE to write the resulting key
 *		object.
 * Returns:
 * 	CKR_OK	Success
 */
CV_RV
prf_genkey(CK_MECHANISM_TYPE alg, const uchar_t *src, size_t len,
    CK_OBJECT_HANDEL_PTR kp)
{
	const mech_t	*mech;

	CK_RV			rc;
	CK_OBJECT_CLASS		cls = CKO_SECRET_KEY;
	CK_KEY_TYPE		kt = CKK_GENERIC_SECRET;
	CK_BBOOL		false_v = CK_FALSE;
	CK_MECHANISM_TYPE	mech_type[] = { 0 };
	CK_ATTRIBUTE		template[] = {
		{ CKA_VALUE, NULL_PTR, 0 },	/* placeholder */
		{ CKA_CLASS, &cls, sizeof (cls) },
		{ CKA_KEY_TYPE, &kt, sizeof (kt) },
#if 0
		/* XXX: should this be set for extra safety? */
		{ CKA_ALLOWED_MECHANISMS, mech_type, sizeof (mech_type) },
#endif
		{ CKA_MODIFIABLE, &false_v, sizeof (false_v) }
	};
	uchar_t			*key = NULL;
	size_t			keylen = 0;
	size_t			keyalloc = 0;

	rc = CKR_OK;

	mech = get_mech(alg);

	/* grab enough memory no matter what */
	if (mech->keysize > mech->bsize)
		keyalloc = mech->keysize;
	else
		keyalloc = mech->bsize;

	if ((key = alloca(keyalloc)) == NULL)
		return (CKR_HOST_MEMORY);

	/*
	 * prefill with 0s so smaller keys are right padded with 0s
	 * if necessary
	 */
	(void) memset(key, 0, keyalloc);

	if (len > mech->keysize) {
		/* too big, take digest of key and use that */
		CK_MECHANISM hmech = { mech->hmech, NULL_PTR, 0 };

		keylen = keyalloc;
		rc = C_DigestInit(p11s, &hmech);
		if (rc != CKR_OK)
			goto done;

		rc = C_Digest(p11s, src, len, key, &keylen);
	} else {
		/* otherwise copy to our local buffer */
		ASSERT(len < keyalloc);

		(void) memcpy(key, src, len);
		if (mech->pad)
			keylen = mech->keysize;
		else
			keylen = len;
	}

	template[0].pValue = key;
	template[0].ulValueLen = keylen;
	mech_type[0] = mech->mech;

	rc = C_CreateObject(p11s, template,
	    sizeof (template) / sizeof (CK_ATTRIBUTE), kp);

done:
	/* make sure nothing lingers on the stack */
	(void) memset(key, 0, keyalloc);
	return (rc);
}

/*
 * Inititalize a prf+ instance for the given algorithm, key, and seed.
 */
CK_RV
prfplus_init(prfp_t *prp, int alg, CK_OBJECT_HANDLE key, const uchar_t *seed,
    size_t seedlen)
{
	const mech_t	*mech;
	int		p11_alg;

	(void) memset(prp, 0, sizeof (*prp));

	p11_alg = ikev2_prf_to_p11(alg);
	VERIFY((mech = get_mech(p11_alg)) != NULL);

	prp->alg.mechanism = p11_alg;
	prp->alg.pParameter = NULL;
	prp->alg.ulParameterLen = 0;

	prp->tlen = mech->bsize;
	prp->buflen = prp->tlen + seedlen + 1;

	if ((prp->buf = malloc(prp->buflen)) == NULL)
		goto error;
	if ((prp->tbuf = malloc(prp->tlen)) == NULL)
		goto error;

	/*
	 * RFC5996 defines prf+ as:
	 * prf+ (K, S) = T1 | T2 | T3 | T4 | ...
	 * where:
	 * T1 = prf (K, S | 0x01)
	 * T2 = prf (K, T1 | S | 0x02)
	 * T3 = prf (K, T2 | S | 0x03)
	 * ...
	 *
	 * prp->buf stores the the contents of the second argument
	 * to prf and is sized to be able to told Tn, S, and the iteration.
	 * 
	 * We copy the initial seed to it's location for T2 (and greater)
	 * and set prp->tp to the location of the iteration.
	 *
	 * For updates, we just copy the previous iteration's T into the
	 * front of the buffer and call the digest alg.
	 */
	(void) memset(prp->buf, 0, prp->buflen);
	(void) memcpy(prp->buf + prp->tlen, seed, seedlen); 
	prp->tp = prp->buf + prp->buflen - 1;
	*prp->tp = 1;

	/* Fill prp->tbuf with T1 */
	if ((rc = C_SignInit(p11s, &prp->alg, prfp->key)) != CKR_OK)
		goto error;

	/*
	 * T1 is defined as prf (K, S | 0x01).  Skip front of prp->buf
	 * that will hold T(n-1) for future iterations.
	 */
	if ((rc = C_Sign(p11s, prp->buf + prp->tlen, seedlen + 1, prp->tbuf,
	    &prp->tlen)) != CKR_OK)
		goto error;

	ASSERT(prp->tlen == mech->bsize);

	return (rc);

error:
	prfplus_fini(prp);
	return (rc);
}

/*
 * Write out *amt bytes from the prf+ function to buf.
 * *amt is set to the number of bytes actually written.
 */
static CK_RV
prfplus(prfp_t *prfp, uchar_t * restrict buf, size_t * restrict amt)
{
	size_t remaining = *amt;
	CK_RV rc = CKR_OK;

	*amt = 0;
	while (remaining > 0) {
		size_t avail = prfp->tlen - prfp->tpos;
		size_t chunk = remaining;

		if (avail == 0) {
			if ((rc = prfplus_update(prfp)) != CKR_OK)
				goto done;
			continue;
		}

		if (chunk > avail)
			chunk = avail;

		(void) memcpy(buf, prfp->tbuf + prfp->tpos, chunk);
		prfp->tpos += chunk;
		remaining -= chunk;
		*amt += chunk;
	}

done:
	return (rc);
}


static CK_RV
prfplus_update(prfp_t *prfp)
{
	CK_RV rc = CKR_OK;

	if (prfp->tp == 0xff) {
		/* XXX: log error */
		return (CKR_GENERAL_ERROR);
	}

	(void) memcpy(prfp->buf, prfp->tbuf, prfp->tlen);
	*prp->tp++;

	if ((rc = C_SignInit(p11s, &prfp->alg, prfp->key)) != CKR_OK)
		return (rc);
#ifdef DEBUG
	size_t tlen = prfp->tlen;
#endif

	if ((rc = C_Sign(p11s, prp->buf, prfp->buflen, prfp->tbuf,
	    &prfp->tlen)) != CKR_OK)
		return (rc);

	ASSERT(tlen == prfp->tlen);

	prfp->tpos = 0;
	return (rc);
}

void
prfplus_fini(prfp_t *prfp)
{
	if (prfp == NULL)
		return;

	if (prfp->buf != NULL) {
		(void) memset(prfp->buf, 0, prfp->buflen);
		free(prfp->buf);
	}
	if (prfp->tbuf != NULL) {
		(void) memset(prfp->tbuf, 0, prp->tlen);
		free(prfp->tbuf);
	}

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
	default:
		VERIFY(0);
	}
}

size_t
prf_keylen(CK_MECHANISM_TYPE mech)
{
	int i;

	for (i = 0; i < N_MECH; i++) {
		if (mechs[i].mech == mech)
			return (mechs[i].keysize);
	}

	VERIFY(0);
}

size_t
ikev2_prf_keylen(int prf)
{
	return (prf_keylen(ikev2_prf_to_p11(prf)));
}

/*
 * Get the information for a given algorithm, or NULL of not found
 */
static const mech_t *
get_mech(CK_MECHANISM_TYPE alg)
{
	for (int i = 0; i < N_MECH; i++) {
		if (mechs[i].mech == alg)
			return (&mechs[i]);
	}
	return (NULL);
}
