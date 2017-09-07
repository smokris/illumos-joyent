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

#include <syslog.h>
#include <assert.h>
#include <string.h>
#include <ipsec_util.h>
#include <locale.h>
#include <security/cryptoki.h>
#include <pthread.h>
#include <sys/debug.h>
#include <note.h>
#include <stdarg.h>
#include "pkcs11.h"
#include "defs.h"

/*
 * per usr/src/lib/pkcs11/libpkcs11/common/metaGlobal.h, the metaslot
 * is always slot 0
 */
#define	METASLOT_ID	(0)

CK_INFO			pkcs11_info = { 0 };
static pthread_key_t	pkcs11_key = PTHREAD_ONCE_KEY_NP;
static CK_SESSION_HANDLE	*handles;
static size_t			nhandles;
static size_t			handlesz;

#define	PKCS11_FUNC		"func"
#define	PKCS11_RC		"errnum"
#define	PKCS11_ERRMSG		"err"

static void pkcs11_free(void *);
static void fmtstr(char *, size_t, CK_UTF8CHAR *, size_t);
static CK_RV pkcs11_callback_handler(CK_SESSION_HANDLE, CK_NOTIFICATION,
    void *);
static void log_slotinfo(CK_SLOT_ID);

/*
 * Entries with 0 for the PKCS#11 mechanism are ones that aren't supported
 * by PKCS#11, so their values aren't used beyond the stringified name.
 */
encr_data_t encr_data[IKEV2_ENCR_MAX + 1] = {
	/* p11, desc, mode, min, max, incr, default, blocksz, iv, icv */
	{ 0, "NONE", MODE_NONE, 0, 0, 0, 0, 0, 0, 0, 0 },
	{ CKM_DES_CBC, "DES_IV64", MODE_CBC, 64, 64, 0, 64, 8, 8, 0, 0 },
	{ CKM_DES_CBC, "DES", MODE_CBC, 64, 64, 0, 64, 64, 8, 0, 0 },
	{ CKM_DES3_CBC, "3DES", MODE_CBC, 192, 192, 0, 192, 8, 8, 0, 0 },
	{ CKM_RC5_CBC, "RC5", MODE_CBC, 40, 2040, 1, 128, 8, 8, 0, 0 },
	{ CKM_IDEA_CBC, "IDEA", MODE_CBC, 128, 128, 0, 128, 8, 8, 0, 0 },
	{ CKM_CAST5_CBC, "CAST", MODE_CBC, 40, 128, 1, 128, 8, 8, 0, 0 },
	{ CKM_BLOWFISH_CBC, "BLOWFISH", MODE_CBC, 40, 448, 1, 128, 8, 8, 0, 0 },
	{ 0, "3IDEA", MODE_CBC, 128, 128, 0, 16, 8, 8, 0, 0 },
	{ CKM_DES_CBC, "DES_IV32", MODE_CBC, 64, 64, 0, 64, 8, 4, 0, 0 },
	{ CKM_RC4, "RC4", MODE_CBC, 0, 0, 0, 0, 0, 0, 0, 0 },
	{ CKM_AES_CBC, "AES_CBC", MODE_CBC, 128, 256, 64, 0, 16, 16, 0, 0 },
	{ CKM_AES_CTR, "AES_CTR", MODE_CTR,  128, 256, 64, 0, 16, 16, 0, 0 },
	{ CKM_AES_CCM, "AES_CCM_8", MODE_CCM, 128, 256, 64, 0, 16, 16, 8, 3 },
	{ CKM_AES_CCM, "AES_CCM_12", MODE_CCM, 128, 256, 64, 0, 16, 16, 12, 3 },
	{ CKM_AES_CCM, "AES_CCM_12", MODE_CCM, 128, 256, 64, 0, 16, 16, 16, 3 },
	{ CKM_AES_GCM, "AES_GCM_8", MODE_GCM, 128, 256, 64, 0, 16, 16, 8, 4 },
	{ CKM_AES_GCM, "AES_GCM_12", MODE_GCM, 128, 256, 64, 0, 16, 16, 12, 4 },
	{ CKM_AES_GCM, "AES_GCM_16", MODE_GCM, 128, 256, 64, 0, 16, 16, 16, 4 },
	{ 0, "NULL_AES_GMAC", MODE_NONE, 128, 256, 64, 0, 16, 16, 16, 0 },
	{ 0, "AES_XTS_AES", MODE_NONE, 128, 256, 64, 0, 0, 0, 0, 0 },
	{ CKM_CAMELLIA_CBC, "CAMELLIA_CBC", MODE_CBC,
	    128, 256, 64, 0, 16, 16, 0, 0 },
	{ CKM_CAMELLIA_CTR, "CAMELLIA_CTR", MODE_CTR,
	    128, 256, 64, 0, 16, 16, 0, 0 },
	{ 0, "CAMELLIA_CCM_8", MODE_CCM, 128, 256, 64, 0, 16, 16, 8, 3 },
	{ 0, "CAMELLIA_CCM_12", MODE_CCM, 128, 256, 64, 0, 16, 16, 12, 3 },
	{ 0, "CAMELLIA_CCM_16", MODE_CCM, 128, 256, 64, 0, 16, 16, 16, 3 },
};

auth_data_t auth_data[] = {
	{ 0, "NONE", 0, 0, 0 },
	{ CKM_MD5_HMAC, "HMAC_MD5_96", 16, 16, 12 },
	{ CKM_SHA_1_HMAC, "HMAC_SHA1_96", 20, 20, 12 },
	{ CKM_DES_MAC, "DES_MAC", 0, 0, 0 },
	{ 0, "KPDK_MD5", 0, 0, 0 },
	{ CKM_AES_XCBC_MAC_96, "AES_XCBC_96", 16, 16, 12 },
	{ CKM_MD5_HMAC, "HMAC_MD5_128", 16, 16, 16 },
	{ CKM_SHA_1_HMAC, "HMAC_SHA1_160", 20, 20, 20 },
	{ CKM_AES_CMAC, "AES_CMAC_96", 16, 16, 12 },

	/*
 	 * These three aren't specified for IKE, just AH and ESP, so
 	 * their key length, etc. aren't needed.
 	 */
	{ CKM_AES_GMAC, "AES_128_GMAC", 16, 0, 0 },
	{ CKM_AES_GMAC, "AES_192_GMAC", 24, 0, 0 },
	{ CKM_AES_GMAC, "AES_256_GMAC", 32, 0, 0 },

	{ CKM_SHA256_HMAC, "HMAC_SHA2_256_128", 32, 32, 16 },
	{ CKM_SHA384_HMAC, "HMAC_SHA2_384_192", 48, 48, 24 },
	{ CKM_SHA512_HMAC, "HMAC_SHA2_512_256", 64, 64, 32 },
};

/*
 * Locates the metaslot among the available slots.  If the metaslot
 * is inable to be located, we terminate.
 */
void
pkcs11_init(void)
{
	CK_RV			rv = CKR_OK;
	CK_ULONG 		nslot = 0;
	CK_C_INITIALIZE_ARGS	args = {
		NULL_PTR,		/* CreateMutex */
		NULL_PTR,		/* DestroyMutex */
		NULL_PTR,		/* LockMutex */
		NULL_PTR,		/* UnlockMutex */
		CKF_OS_LOCKING_OK,	/* flags */
		NULL_PTR		/* reserved */
	};

	PTH(pthread_key_create_once_np(&pkcs11_key, pkcs11_free));

	if ((rv = C_Initialize(&args)) != CKR_OK) {
		PKCS11ERR(fatal, log, "C_Initialize", rv);
		exit(1);
	}

	if ((rv = C_GetInfo(&pkcs11_info)) != CKR_OK) {
		PKCS11ERR(fatal, log, "C_Info", rv);
		exit(1);
	}

	if ((rv = C_GetSlotList(CK_FALSE, NULL, &nslot)) != CKR_OK) {
		PKCS11ERR(fatal, log, "C_GetSlotList", rv);
		exit(1);
	}

	CK_SLOT_ID slots[nslot];

	if ((rv = C_GetSlotList(CK_FALSE, slots, &nslot)) != CKR_OK) {
		PKCS11ERR(fatal, log, "C_GetSlotList", rv);
		exit(1);
	}

	{
		char manf[33];
		char libdesc[33];

		fmtstr(manf, sizeof (manf), pkcs11_info.manufacturerID,
		    sizeof (pkcs11_info.manufacturerID));
		fmtstr(libdesc, sizeof (libdesc),
		    pkcs11_info.libraryDescription,
		    sizeof (pkcs11_info.libraryDescription));

		(void) bunyan_debug(log, "PKCS#11 provider info",
		    BUNYAN_T_STRING, "manufacturer", manf,
		    BUNYAN_T_UINT32, "version.major",
		    (uint32_t)pkcs11_info.cryptokiVersion.major,
		    BUNYAN_T_UINT32, "version.minor",
		    (uint32_t)pkcs11_info.cryptokiVersion.minor,
		    BUNYAN_T_UINT64, "flags",
		    (uint64_t)pkcs11_info.flags,
		    BUNYAN_T_STRING, "library", libdesc,
		    BUNYAN_T_UINT32, "lib.major",
		    (uint32_t)pkcs11_info.libraryVersion.major,
		    BUNYAN_T_UINT32, "lib.minor",
		    (uint32_t)pkcs11_info.libraryVersion.minor,
		    BUNYAN_T_UINT32, "numslots", nslot,
		    BUNYAN_T_END);
	}

	for (size_t i = 0; i < nslot; i++)
		log_slotinfo(slots[i]);
}

static void
log_slotinfo(CK_SLOT_ID slot)
{
	CK_SLOT_INFO info = { 0 };
	char manuf[33]; /* sizeof info.manufacturerID NUL */
	CK_RV rv;

	rv = C_GetSlotInfo(slot, &info);
	if (rv != CKR_OK) {
		PKCS11ERR(error, log, "C_GetSlotInfo", rv);
		return;
	}

	{
		char desc[65];	/* sizeof info.description + NUL */
		fmtstr(desc, sizeof (desc), info.slotDescription,
		    sizeof (info.slotDescription));
		fmtstr(manuf, sizeof (manuf), info.manufacturerID,
		    sizeof (info.manufacturerID));

		(void) bunyan_debug(log, "PKCS#11 slot Info",
		    BUNYAN_T_UINT64, "slot", (uint64_t)slot,
		    BUNYAN_T_STRING, "desc", desc,
		    BUNYAN_T_STRING, "manufacturer", manuf,
		    BUNYAN_T_UINT32, "hwversion.major",
		    (uint32_t)info.hardwareVersion.major,
		    BUNYAN_T_UINT32, "hwversion.minor",
		    (uint32_t)info.hardwareVersion.minor,
		    BUNYAN_T_UINT32, "fwversion.major",
		    (uint32_t)info.firmwareVersion.major,
		    BUNYAN_T_UINT32, "fwversion.minor",
		    (uint32_t)info.firmwareVersion.minor,
		    BUNYAN_T_UINT64, "flags", (uint64_t)info.flags,
		    BUNYAN_T_BOOLEAN, "present",
		    !!(info.flags & CKF_TOKEN_PRESENT),
		    BUNYAN_T_BOOLEAN, "removable",
		    !!(info.flags & CKF_REMOVABLE_DEVICE),
		    BUNYAN_T_BOOLEAN, "hwslot", !!(info.flags & CKF_HW_SLOT),
		    BUNYAN_T_END);
	}

	if (!(info.flags & CKF_TOKEN_PRESENT))
		return;

	CK_TOKEN_INFO tinfo = { 0 };
	rv = C_GetTokenInfo(slot, &tinfo);
	if (rv != CKR_OK)
		PKCS11ERR(error, log, "C_GetTokenInfo", rv);

	char label[33];		/* sizeof tinfo.label + NUL */
	char model[17];		/* sizeof tinfo.model + NUL */
	char serial[17];	/* sizeof tinfo.serialNumber + NUL */
	char utctime[17];	/* sizeof tinfo.utsTime + NUL */

	fmtstr(manuf, sizeof (manuf), tinfo.manufacturerID,
	    sizeof (tinfo.manufacturerID));
	fmtstr(label, sizeof (label), tinfo.label, sizeof (tinfo.label));
	fmtstr(model, sizeof (model), tinfo.model, sizeof (tinfo.model));
	fmtstr(serial, sizeof (serial), tinfo.serialNumber,
	    sizeof (tinfo.serialNumber));
	fmtstr(utctime, sizeof (utctime), tinfo.utcTime,
	    sizeof (tinfo.utcTime));

#define	F(_inf, _flg) BUNYAN_T_BOOLEAN, #_flg, ((_inf).flags & (_flg))
	char flagstr[19];
	(void) snprintf(flagstr, sizeof (flagstr), "0x%lu", info.flags);

	(void) bunyan_debug(log, "PKCS#11 token info",
	    BUNYAN_T_UINT32, "slot", (uint32_t)slot,
	    BUNYAN_T_STRING, "label", label,
	    BUNYAN_T_STRING, "manuf", manuf,
	    BUNYAN_T_STRING, "model", model,
	    BUNYAN_T_STRING, "serial", serial,
	    BUNYAN_T_STRING, "flags", flagstr,
	    F(info, CKF_RNG),
	    F(info, CKF_WRITE_PROTECTED),
	    F(info, CKF_LOGIN_REQUIRED),
	    F(info, CKF_USER_PIN_INITIALIZED),
	    F(info, CKF_RESTORE_KEY_NOT_NEEDED),
	    F(info, CKF_CLOCK_ON_TOKEN),
	    F(info, CKF_PROTECTED_AUTHENTICATION_PATH),
	    F(info, CKF_DUAL_CRYPTO_OPERATIONS),
	    F(info, CKF_TOKEN_INITIALIZED),
	    F(info, CKF_SECONDARY_AUTHENTICATION),
	    F(info, CKF_USER_PIN_COUNT_LOW),
	    F(info, CKF_USER_PIN_FINAL_TRY),
	    F(info, CKF_USER_PIN_LOCKED),
	    F(info, CKF_USER_PIN_TO_BE_CHANGED),
	    F(info, CKF_SO_PIN_COUNT_LOW),
	    F(info, CKF_SO_PIN_FINAL_TRY),
	    F(info, CKF_SO_PIN_LOCKED),
	    F(info, CKF_SO_PIN_TO_BE_CHANGED),
	    F(info, CKF_ERROR_STATE),
	    BUNYAN_T_END);
#undef F
}

void
pkcs11_fini(void)
{
	CK_RV rv;

	for (size_t i = 0; i < nhandles; i++) {
		rv = C_CloseSession(handles[i]);
		if (rv != CKR_OK)
			PKCS11ERR(error, log, "C_CloseSession", rv);
	}
	free(handles);
	handles = NULL;
	nhandles = 0;
	handlesz = 0;

	rv = C_Finalize(NULL_PTR);
	if (rv != CKR_OK)
		PKCS11ERR(error, log, "C_Finalize", rv);
}

size_t
ikev2_auth_icv_size(ikev2_xf_encr_t encr, ikev2_xf_auth_t auth)
{
	if (encr_data[encr].ed_icvlen != 0)
		return (encr_data[encr].ed_icvlen);
	return (auth_data[auth].ad_icvlen);
}

/*
 * Destroy a PKCS#11 object with nicer error messages in case of failure.
 */
void
pkcs11_destroy_obj(const char *name, CK_OBJECT_HANDLE_PTR objp,
    bunyan_logger_t *l)
{
	CK_RV ret;

	if (objp == NULL || *objp == CK_INVALID_HANDLE)
		return;

	if ((ret = C_DestroyObject(p11h(), *objp)) != CKR_OK) {
		PKCS11ERR(error, (l == NULL) ? log : l, "C_DestroyObject", ret,
		    BUNYAN_T_STRING, "objname", name);
	} else {
		*objp = CK_INVALID_HANDLE;
	}
}

static CK_RV
pkcs11_callback_handler(CK_SESSION_HANDLE session, CK_NOTIFICATION surrender,
    void *context)
{
	_NOTE(ARGUNUSED(session, context));
	VERIFY3U(surrender, ==, CKN_SURRENDER);

	return (CKR_OK);
}

#define	CHUNK_SZ (8)
static void
pkcs11_free(void *arg)
{
	CK_SESSION_HANDLE h = (CK_SESSION_HANDLE)arg;

	/*
	 * Per the PKCS#11 standard, multiple handles in the same process
	 * share any objects created.  However, when a particular handle is
	 * closed, any objects created by that handle are deleted.  Due to
	 * this behavior, we do not close any sessions and instead keep
	 * unused sessions around on a free list for re-use.
	 *
	 * It also means in the (hopefully) rare instance we cannot expand
	 * 'handles' to hold additional unused handles, we just leak them.
	 * In practice if we are so low on memory that we cannot expand
	 * 'handles', things are likely messed up enough we'll probably
	 * end up restarting things anyway.
	 */
	if (nhandles + 1 > handlesz) {
		CK_SESSION_HANDLE *nh = NULL;
		size_t newamt = handlesz + 8;
		size_t newsz = newamt * sizeof (CK_SESSION_HANDLE);

		if (newsz < newamt || newsz < sizeof (CK_SESSION_HANDLE))
			return;

		nh = realloc(handles, newsz);
		if (nh == NULL)
			return;

		handles = nh;
		handlesz = newamt;
	}

	handles[nhandles++] = h;
}

CK_SESSION_HANDLE
p11h(void)
{
	CK_SESSION_HANDLE h =
	    (CK_SESSION_HANDLE)pthread_getspecific(pkcs11_key);
	CK_RV ret;

	if (h != CK_INVALID_HANDLE)
		return (h);

	if (nhandles > 0) {
		h = handles[--nhandles];
		goto done;
	}

	ret = C_OpenSession(METASLOT_ID, CKF_SERIAL_SESSION, NULL,
	    pkcs11_callback_handler, &h);
	if (ret != CKR_OK) {
		PKCS11ERR(error, log, "C_OpenSession", ret);
		return (CK_INVALID_HANDLE);
	}

done:
	PTH(pthread_setspecific(pkcs11_key, (void *)h));
	return (h);
}

/*
 * Sadly, string fields in PKCS#11 structs are not NUL-terminated and
 * are space padded, so this converts it into a more traditional C-string
 * with quoting so space padding is evident
 */
static void
fmtstr(char *buf, size_t buflen, CK_UTF8CHAR *src, size_t srclen)
{
	ASSERT3U(srclen + 1, <=, buflen);

	(void) memset(buf, 0, buflen);
	(void) memcpy(buf, src, srclen);

	for (char *p = buf + strlen(buf) - 1; p >= buf && *p == ' '; p--)
		*p = '\0';
}
