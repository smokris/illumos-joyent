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
 * Copyright 2017 Jason King.
 * Copyright 2018, Joyent, Inc.
 */

#include <sys/debug.h>
#include <sys/types.h>
#include <security/cryptoki.h>
#include <strings.h>
#include <bunyan.h>
#include "dh.h"
#include "dh_impl.h"
#include "ikev2_enum.h"
#include "pkcs11.h"

#define	EC_POINT_FORM_UNCOMPRESSED 0x04

static boolean_t dh_genpair(pkgroup_t *, CK_OBJECT_HANDLE_PTR,
    CK_OBJECT_HANDLE_PTR);
static boolean_t ecc_genpair(pkgroup_t *, CK_OBJECT_HANDLE_PTR,
    CK_OBJECT_HANDLE_PTR);

static pkgroup_t *
pk_getgroup(ikev2_dh_t id)
{
	for (size_t i = 0; i < pk_ngroups; i++) {
		if (pk_groups[i].pk_id == id)
			return (&pk_groups[i]);
	}
	return (NULL);
}

boolean_t
gen_keypair(ikev2_dh_t group, CK_OBJECT_HANDLE_PTR restrict pub,
    CK_OBJECT_HANDLE_PTR restrict priv)
{
	pkgroup_t *pk = NULL;

	if (group == IKEV2_DH_NONE) {
		(void) bunyan_debug(log,
		    "Skipping creation of DH pair due to no DH group specified",
		    BUNYAN_T_END);
		return (B_TRUE);
	}

	if (*pub != CK_INVALID_HANDLE && *priv != CK_INVALID_HANDLE) {
		(void) bunyan_debug(log,
		    "Skipping creation of DH pair due to pair already created",
		    BUNYAN_T_END);
		return (B_TRUE);
	}

	if ((pk = pk_getgroup(group)) == NULL) {
		(void) bunyan_error(log, "Invalid DH group",
		    BUNYAN_T_STRING, "dhgrp", ikev2_dh_str(group),
		    BUNYAN_T_INT32, "val", (int32_t)group,
		    BUNYAN_T_END);
		return (B_FALSE);
	}

	switch (pk->pk_type) {
	case PK_DH:
		if (!dh_genpair(pk, pub, priv))
			return (B_FALSE);
		break;
	case PK_ECC:
		if (!ecc_genpair(pk, pub, priv))
			return (B_FALSE);
		break;
	}

	(void) bunyan_trace(log, "Created DH keypair",
	    BUNYAN_T_STRING, "group", ikev2_dh_str(group),
	    BUNYAN_T_UINT64, "pub_handle", (uint64_t)*pub,
	    BUNYAN_T_UINT64, "priv_handle", (uint64_t)*priv,
	    BUNYAN_T_END);

	return (B_TRUE);
}

static boolean_t
dh_genpair(pkgroup_t *dh, CK_OBJECT_HANDLE_PTR pub, CK_OBJECT_HANDLE_PTR priv)
{
	CK_MECHANISM mech = {
		.mechanism = CKM_DH_PKCS_KEY_PAIR_GEN,
		.pParameter = NULL_PTR,
		.ulParameterLen = 0
	};
	CK_BBOOL trueval = CK_TRUE;
	CK_ATTRIBUTE pub_template[2] = {
	    { CKA_PRIME, dh->pk_prime, dh->pk_primelen },
	    { CKA_BASE, dh->pk_generator, dh->pk_genlen }
	};
	CK_ATTRIBUTE priv_template[1] = {
	    CKA_DERIVE, &trueval, sizeof (trueval)
	};
	CK_RV rv = CKR_OK;

	VERIFY3S(dh->pk_type, ==, PK_DH);

	rv = C_GenerateKeyPair(p11h(), &mech,
	    pub_template, ARRAY_SIZE(pub_template),
	    priv_template, ARRAY_SIZE(priv_template),
	    pub, priv);

	if (rv != CKR_OK) {
		PKCS11ERR(error, "C_GenerateKeyPair", rv);
		return (B_FALSE);
	}

	return (B_TRUE);
}

static boolean_t
ecc_genpair(pkgroup_t *ecc, CK_OBJECT_HANDLE_PTR pub,
    CK_OBJECT_HANDLE_PTR priv)
{
	CK_MECHANISM mech = {
		.mechanism = CKM_EC_KEY_PAIR_GEN,
		.pParameter = NULL_PTR,
		.ulParameterLen = 0
	};
	CK_ATTRIBUTE template[1] = {
	    CKA_EC_PARAMS, ecc->pk_oid, ecc->pk_oidlen
	};
	CK_RV rv = CKR_OK;

	VERIFY3S(ecc->pk_type, ==, PK_ECC);

	rv = C_GenerateKeyPair(p11h(), &mech, template, 1, template, 1,
	    pub, priv);

	if (rv != CKR_OK) {
		PKCS11ERR(error, "C_GenerateKeyPair", rv);
		return (B_FALSE);
	}

	return (B_TRUE);
}

static boolean_t
dh_derivekey(CK_OBJECT_HANDLE priv, uint8_t *restrict pub, size_t len,
    CK_OBJECT_HANDLE_PTR restrict secretp)
{
	CK_OBJECT_CLASS key_class = CKO_SECRET_KEY;
	CK_KEY_TYPE key_type = CKK_GENERIC_SECRET;
	CK_BBOOL trueval = CK_TRUE;
	CK_MECHANISM mech = { CKM_DH_PKCS_DERIVE, pub, len };
	CK_ATTRIBUTE template[] = {
		{ CKA_CLASS, &key_class, sizeof (key_class) },
		{ CKA_KEY_TYPE, &key_type, sizeof (key_type) },
		{ CKA_ENCRYPT, &trueval, sizeof (trueval) },
		{ CKA_DECRYPT, &trueval, sizeof (trueval) }
	};
	CK_RV rv;

	rv = C_DeriveKey(p11h(), &mech, priv, template, ARRAY_SIZE(template),
	    secretp);
	if (rv != CKR_OK) {
		PKCS11ERR(error, "C_DeriveKey", rv);
		return (B_FALSE);
	}
	return (B_TRUE);
}

static boolean_t
ecc_derivekey(CK_OBJECT_HANDLE priv, uint8_t *restrict pub, size_t publen,
    CK_OBJECT_HANDLE_PTR restrict secretp)
{
	CK_OBJECT_CLASS key_class = CKO_SECRET_KEY;
	CK_KEY_TYPE key_type = CKK_GENERIC_SECRET;
	CK_BBOOL trueval = CK_TRUE;
	CK_ECDH1_DERIVE_PARAMS ecc_params = {
		.kdf = CKD_NULL,
		.pSharedData = NULL_PTR,
		.ulSharedDataLen = 0,
	};
	CK_MECHANISM mech = {
		.mechanism = CKM_ECDH1_DERIVE,
		.pParameter = &ecc_params,
		.ulParameterLen = sizeof (ecc_params)
	};
	CK_ATTRIBUTE template[] = {
		{ CKA_CLASS, &key_class, sizeof (key_class) },
		{ CKA_KEY_TYPE, &key_type, sizeof (key_type) },
		{ CKA_ENCRYPT, &trueval, sizeof (trueval) },
		{ CKA_DECRYPT, &trueval, sizeof (trueval) }
	};
	uint8_t *curve = umem_alloc(publen + 1, UMEM_DEFAULT);
	CK_RV rv;

	if (curve == NULL) {
		(void) bunyan_error(log, "No memory to perform key exchange",
		    BUNYAN_T_END);
		return (B_FALSE);
	}

	curve[0] = EC_POINT_FORM_UNCOMPRESSED;
	bcopy(curve + 1, pub, publen);
	ecc_params.pPublicData = pub;
	ecc_params.ulPublicDataLen = publen + 1;

	rv = C_DeriveKey(p11h(), &mech, priv, template, ARRAY_SIZE(template),
	    secretp);
	umem_free(pub, publen + 1);

	if (rv != CKR_OK) {
		PKCS11ERR(error, "C_DeriveKey", rv);
		return (B_FALSE);
	}

	return (B_TRUE);
}

boolean_t
derivekey(ikev2_dh_t group, CK_OBJECT_HANDLE priv, uint8_t *restrict pub,
    size_t publen, CK_OBJECT_HANDLE_PTR restrict secretp)
{
	pkgroup_t *pk = pk_getgroup(group);

	/* We should never negotiate a group we don't support */
	VERIFY3S(pk, !=, NULL);

	switch (pk->pk_type) {
	case PK_DH:
		return (dh_derivekey(priv, pub, publen, secretp));
	case PK_ECC:
		return (ecc_derivekey(priv, pub, publen, secretp));
	}

	/*NOTREACHED*/
	return (B_FALSE);
}
