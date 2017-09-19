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
#include <stdarg.h>
#include <bunyan.h>
#include "defs.h"
#include "ikev2.h"
#include "prf.h"
#include "pkcs11.h"

/*
 * This implements the pseudo-random function (PRF) as well as the streaming
 * variant (prf+ or 'prfp plus') as described in RFC7296 2.13.  Briefly,
 * the nonces from both the initiator and responder as well as the shared
 * DH or ECC key from the IKE_SA_INIT are fed through the PRF function to
 * generate a seed value.   The prfp+ function starts with this seed value
 * and iteratively uses the previous values to generate new blocks of keying
 * material.  For child SAs (either AH, ESP, or an IKE SA rekey), some
 * additional inputs are mixed in.  RFC7206 secions 2.13 and 2.17 go into
 * the complete details of what inputs are used when.
 *
 * As both the PRF and prfp+ functions use multiple disparate inputs that
 * are concatented together to form the inputs to the functions, both prf()
 * and prfplus_init() take a variable number of arguments which should be a
 * sequence of uint8_t *, size_t pairs of parameters with a terminating NULL
 * value.  The prf() and prfplus_init() functions will then take care of
 * concatenating the inputs as required (generally the PCKS#11 C_*Update()
 * functions do all the dirty work here for us).
 *
 * This is run per IKE SA, so a given prfp_t instance should never be shared
 * between ikev2_sa_ts, and the caller must handle any synchronization of
 * potentially simultaneous prf* calls with the same prfp_t.  Since the
 * lifetime of any given prfp_t is currently always just the lifetime of the
 * calling function, this shouldn't make things difficult.
 */

/*
 * RFC7296 2.13 -- The prfp+ is only specified for 255 iterations of the
 * underlying PRF function.
 */
#define	PRFP_ITER_MAX	(255)
static boolean_t prfplus_update(prfp_t *);

/*
 * Run the given PRF algorithm for the given key and seed and place
 * result into out.  The seed is passed as a sequence of uint8_t *, size_t
 * pairs terminated by a final NULL
 */
boolean_t
prf(ikev2_prf_t alg, CK_OBJECT_HANDLE key, uint8_t *restrict out, size_t outlen,
    bunyan_logger_t *restrict l, ...)
{
	CK_SESSION_HANDLE	h = p11h();
	CK_MECHANISM		mech;
	CK_RV			rc = CKR_OK;
	CK_ULONG		len = outlen;
	uint8_t			*segp = NULL;
	va_list			ap;

	VERIFY3U(outlen, >=, ikev2_prf_outlen(alg));

	mech.mechanism = ikev2_prf_to_p11(alg);
	mech.pParameter = NULL;
	mech.ulParameterLen = 0;

	if ((rc = C_SignInit(h, &mech, key)) != CKR_OK) {
		PKCS11ERR(error, l, "C_SignInit", rc);
		return (B_FALSE);
	}

	va_start(ap, l);
	while ((segp = va_arg(ap, uint8_t *)) != NULL) {
		size_t seglen = va_arg(ap, size_t);

		rc = C_SignUpdate(h, segp, seglen);
		if (rc != CKR_OK) {
			/* XXX: should we still call C_SignFinal? */
			PKCS11ERR(error, l, "C_SignUpdate", rc);
			return (B_FALSE);
		}
	}
	va_end(ap);

	rc = C_SignFinal(h, out, &len);
	if (rc != CKR_OK) {
		PKCS11ERR(error, l, "C_SignFinal", rc,
		    (rc == CKR_DATA_LEN_RANGE) ? BUNYAN_T_UINT64 : BUNYAN_T_END,
		    "desiredlen", (uint64_t)len, BUNYAN_T_END);
		return (B_FALSE);
	}

	return (B_TRUE);
}

/*
 * Inititalize a prf+ instance for the given algorithm, key, and seed.
 */
boolean_t
prfplus_init(prfp_t *restrict prfp, ikev2_prf_t alg, CK_OBJECT_HANDLE key,
    bunyan_logger_t *restrict l, ...)
{
	uint8_t		*p = NULL;
	size_t		len = 0;
	va_list		ap;

	(void) memset(prfp, 0, sizeof (*prfp));

	prfp->prfp_alg = alg;
	prfp->prfp_key = key;
	prfp->prfp_tbuflen = ikev2_prf_outlen(alg);

	va_start(ap, l);
	while (va_arg(ap, uint8_t *) != NULL)
		prfp->prfp_seedlen += va_arg(ap, size_t);
	va_end(ap);

	prfp->prfp_tbuf[0] = umem_zalloc(prfp->prfp_tbuflen, UMEM_DEFAULT);
	prfp->prfp_tbuf[1] = umem_zalloc(prfp->prfp_tbuflen, UMEM_DEFAULT);
	prfp->prfp_seed = umem_zalloc(prfp->prfp_seedlen, UMEM_DEFAULT);
	if (prfp->prfp_tbuf[0] == NULL || prfp->prfp_tbuf[1] == NULL ||
	    prfp->prfp_seed == NULL) {
		(void) bunyan_error(l, "Could not allocate memory for PRF+",
		    BUNYAN_T_END);
		goto fail;
	}

	va_start(ap, l);
	while ((p = va_arg(ap, uint8_t *)) != NULL) {
		size_t seglen = va_arg(ap, size_t);

		(void) memcpy(prfp->prfp_seed + len, p, seglen);
		len += seglen;
	}
	va_end(ap);

	/*
	 * Per RFC7296 2.13, prf+(K, S) = T1 | T2 | T3 | T4 | ...
	 *
	 * where:
	 * 	T1 = prf (K, S | 0x01)
	 * 	T2 = prf (K, T1 | S | 0x02)
	 * 	T3 = prf (K, T2 | S | 0x03)
	 * 	T4 = prf (K, T3 | S | 0x04)
	 *
	 * Since the next iteration uses the previous iteration's output (plus
	 * the seed and iteration number), we keep a copy of the output of the
	 * current iteration as well as the previous iteration.  We use the
	 * low bit of the current iteration number to index into prfp_tbuf
	 * (and effectively flip flow between the two buffers).
	 */
	prfp->prfp_n = 1;

	/*
	 * Fill prfp->tbuf[1] with T1. T1 is defined as:
	 * 	T1 = prf (K, S | 0x01)
	 *
	 * Note that this is different from subsequent iterations, hence
	 * starting at prfp->prfp_arg[1], not prfp->arg[0]
	 */
	if (!prf(prfp->prfp_alg, prfp->prfp_key,
	    prfp->prfp_tbuf[1], prfp->prfp_tbuflen,		/* output */
	    prfp->prfp_log,
	    prfp->prfp_seed, prfp->prfp_seedlen,		/* S */
	    &prfp->prfp_n, sizeof (prfp->prfp_n), NULL))	/* 0x01 */
		goto fail;

	return (B_TRUE);
fail:
	prfplus_fini(prfp);
	return (B_FALSE);
}

/*
 * Fill buffer with output of prf+ function.  If outlen == 0, it's explicitly
 * a no-op.
 */
boolean_t
prfplus(prfp_t *restrict prfp, uint8_t *restrict out, size_t outlen)
{
	size_t n = 0;
	while (n < outlen) {
		uint8_t *t = prfp->prfp_tbuf[prfp->prfp_n & 0x01];
		size_t tlen = prfp->prfp_tbuflen - prfp->prfp_pos;
		size_t amt = 0;

		if (tlen == 0) {
			if (!prfplus_update(prfp))
				return (B_FALSE);

			t = prfp->prfp_tbuf[prfp->prfp_n & 0x01];
			tlen = prfp->prfp_tbuflen - prfp->prfp_pos;
		}

		amt = MIN(outlen - n, tlen);
		(void) memcpy(out + n, t + prfp->prfp_pos, amt);
		prfp->prfp_pos += amt;
		n += amt;
	}
	return (B_TRUE);
}

/*
 * Perform a prf+ iteration
 */
static boolean_t
prfplus_update(prfp_t *prfp)
{
	uint8_t *t = NULL, *told = NULL;
	size_t tlen = prfp->prfp_tbuflen;

	/* The sequence (T##) starts with 1 */
	VERIFY3U(prfp->prfp_n, >, 0);

	if (prfp->prfp_n == PRFP_ITER_MAX) {
		bunyan_error(prfp->prfp_log,
		    "prf+ iteration count reached max (0xff)", BUNYAN_T_END);
		return (B_FALSE);
	}

	told = prfp->prfp_tbuf[prfp->prfp_n++ & 0x1];
	t = prfp->prfp_tbuf[prfp->prfp_n & 0x1];

	if (!prf(prfp->prfp_alg, prfp->prfp_key,
	    t, tlen, prfp->prfp_log,				/* out */
	    told, tlen,						/* Tn-1 */
	    prfp->prfp_seed, prfp->prfp_seedlen,		/* S */
	    &prfp->prfp_n, sizeof (prfp->prfp_n), NULL))	/* 0xnn */
		return (B_FALSE);

	prfp->prfp_pos = 0;
	return (B_TRUE);
}

void
prfplus_fini(prfp_t *prfp)
{
	if (prfp == NULL)
		return;

	for (size_t i = 0; i < PRFP_NUM_TBUF; i++) {
		if (prfp->prfp_tbuf[i] != NULL) {
			explicit_bzero(prfp->prfp_tbuf[i], prfp->prfp_tbuflen);
			umem_free(prfp->prfp_tbuf[i], prfp->prfp_tbuflen);
			prfp->prfp_tbuf[i] = NULL;
		}
	}
	prfp->prfp_tbuflen = 0;

	if (prfp->prfp_seed != NULL) {
		explicit_bzero(prfp->prfp_seed, prfp->prfp_seedlen);
		umem_free(prfp->prfp_seed, prfp->prfp_seedlen);
	}

	prfp->prfp_seed = NULL;
	prfp->prfp_seedlen = 0;
}

/*
 * Take 'len' bytes from the prf+ output stream and create a PKCS#11 object
 * for use with the given mechanism.  A descriptive name (e.g. 'SK_i') is
 * passed for debugging purposes.
 */
boolean_t
prf_to_p11key(prfp_t *restrict prfp, const char *restrict name, int alg,
    size_t len, CK_OBJECT_HANDLE_PTR restrict objp)
{
	CK_RV rc = CKR_OK;
	uint8_t buf[len];

	if (len == 0)
		return (B_TRUE);

	if (!prfplus(prfp, buf, len))
		return (B_FALSE);

	rc = SUNW_C_KeyToObject(p11h(), alg, buf, len, objp);
	explicit_bzero(buf, len);

	/*
	 * XXX: Might it be worth setting the object label attribute to 'name'
	 * for diagnostic purposes?
	 */
	if (rc != CKR_OK) {
		PKCS11ERR(error, prfp->prfp_log, "SUNW_C_KeyToObject", rc,
		    BUNYAN_T_STRING, "objname", name);
	}

	return ((rc == CKR_OK) ? B_TRUE : B_FALSE);
}

CK_MECHANISM_TYPE
ikev2_prf_to_p11(ikev2_prf_t prf)
{
	switch (prf) {
	case IKEV2_PRF_HMAC_MD5:
		return (CKM_MD5_HMAC);
	case IKEV2_PRF_HMAC_SHA1:
		return (CKM_SHA_1_HMAC);
	case IKEV2_PRF_HMAC_SHA2_256:
		return (CKM_SHA256_HMAC);
	case IKEV2_PRF_HMAC_SHA2_384:
		return (CKM_SHA384_HMAC);
	case IKEV2_PRF_HMAC_SHA2_512:
		return (CKM_SHA512_HMAC);
	case IKEV2_PRF_AES128_CMAC:
		return (CKM_AES_CMAC);
	case IKEV2_PRF_HMAC_TIGER:
	case IKEV2_PRF_AES128_XCBC:
		return (0);
	}

	INVALID("invalid PRF value");

	/*NOTREACHED*/
	return (0);
}

size_t
ikev2_prf_keylen(ikev2_prf_t prf)
{
	switch (prf) {
	case IKEV2_PRF_HMAC_MD5:
	case IKEV2_PRF_HMAC_SHA1:
	case IKEV2_PRF_HMAC_SHA2_256:
	case IKEV2_PRF_HMAC_SHA2_384:
	case IKEV2_PRF_HMAC_SHA2_512:
		/*
		 * RFC7296 2.12 -- For PRFs based on HMAC, preferred key size is
		 * equal to the output of the underlying hash function.
		 */
		return (ikev2_prf_outlen(prf));
	case IKEV2_PRF_AES128_CMAC:
	case IKEV2_PRF_AES128_XCBC:
		return (16);
	case IKEV2_PRF_HMAC_TIGER:
		return (0);
	}
	INVALID("Invalid PRF value");

	/*NOTREACHED*/
	return (0);
}

size_t
ikev2_prf_outlen(ikev2_prf_t prf)
{
	switch (prf) {
	case IKEV2_PRF_HMAC_MD5:
	case IKEV2_PRF_HMAC_SHA1:
		return (16);
	case IKEV2_PRF_HMAC_SHA2_256:
		return (32);
	case IKEV2_PRF_HMAC_SHA2_384:
		return (48);
	case IKEV2_PRF_HMAC_SHA2_512:
		return (64);
	case IKEV2_PRF_AES128_CMAC:
	case IKEV2_PRF_AES128_XCBC:
	case IKEV2_PRF_HMAC_TIGER:
		return (0);
	}

	INVALID("Invalid PRF value");
	/*NOTREACHED*/
	return (0);
}
