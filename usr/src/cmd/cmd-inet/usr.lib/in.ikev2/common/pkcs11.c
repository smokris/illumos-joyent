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

#include <errno.h>
#include <ipsec_util.h>
#include <locale.h>
#include <note.h>
#include <security/cryptoki.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <synch.h>
#include <syslog.h>
#include <sys/debug.h>
#include <umem.h>
#include "defs.h"
#include "pkcs11.h"
#include "worker.h"

/*
 * This largely handles PKCS#11 session handles as well as providing information
 * and mapping from PKCS#11 mechanisms to their IKE equivalents.
 *
 * PKCS#11 session handles are somewhat quirky.  The documentation isn't
 * explicit, but strongly implies that a given session handle
 * (CK_SESSION_HANDLE) can only perform one crypto operation at a time.  As
 * such, we create a PKCS#11 session handle for each worker thread (in fact
 * worker.c`worker_init_one() guarantees that each worker thread has it's own
 * session handle at worker thread creation.  PKCS#11 states (in the
 * PKCS#11 Usage Guide) that all objects created on a given token are visible
 * to any other session handles within the same process.  It also states that
 * the PKCS#11 library is responsible for doing any necessary locking when
 * a PKCS#11 object is manipulated.
 *
 * One quirk of how PKCS#11 handles session, is that when a session handle
 * is destroyed, any non-presistent objects created by that session handle
 * are destroyed (though as stated above, the PKCS#11 library takes care
 * so that if one session is using an object in a PKCS#11 operation while
 * another session tries to the same object while it's in use, the destruction
 * will not intefere with the in-progress operation in the other session).
 * Because the PKCS#11 objects in.ikev2d creates are associated with an
 * IKE SA, the lifetime of the objects is tied to the lifetime of the IKE SA
 * and not necessairly that of the worker thread.  As such, any session
 * handles that are created need to be retained for the lifetime of the
 * in.ikev2d process.  To accomplish this, we maintain a 'free list' of
 * session handles.  Any worker threads that exit will have their
 * session handles placed on the free list, and any requests for a new
 * session handle will first try to grab a session handle from the
 * free list before attempting to create a new session.
 *
 * If in the future, we wish to allow the use of multiple tokens, this
 * will likely need to be reworked a bit.  Our pkcs11_softtoken allows
 * effectively unlimited sessions (bounded by memory), but a hardware
 * token may have a limit on the number of sessions that can be created,
 * which might require a more complicated method of managing PKCS#11
 * session handles.
 */

/*
 * Per usr/src/lib/pkcs11/libpkcs11/common/metaGlobal.h, the metaslot
 * is always slot 0
 */
#define	METASLOT_ID	(0)

/*
 * Unfortunately, the PKCS#11 header files don't define constants for the
 * string fields in the CK_SLOT_INFO and CK_TOKEN_INFO structures, so
 * we define them here based on their definitions in <security/pkcs11t.h>
 */

/* Sizes of CK_SLOT_INFO string fields + NUL */
#define	PKCS11_MANUF_LEN	(33)
#define	PKCS11_DESC_LEN		(65)

/* Sizes of CK_TOKEN_INFO string fields + NUL */
#define	PKCS11_LABEL_LEN	(33)
#define	PKCS11_MODEL_LEN	(17)
#define	PKCS11_SERIAL_LEN	(17)
#define	PKCS11_UTCTIME_LEN	(17)

/* pkcs11_init() sets this during startup and is never altered afterwards */
CK_INFO			pkcs11_info = { 0 };

static mutex_t			pkcs11_handle_lock;
static CK_SESSION_HANDLE	*pkcs11_handles;
static size_t			pkcs11_nhandles;
static size_t			pkcs11_handlesz;

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
#define	EALG(_name, _p11, _mode, _min, _max, _incr, _def, _bsz, _iv, _icv, _s) \
    { \
	.ed_i2id = IKEV2_ENCR_ ## _name, \
	.ed_p11id = _p11, \
	.ed_mode = _mode, \
	.ed_name = # _name, \
	.ed_keymin = _min, \
	.ed_keymax = _max, \
	.ed_keyincr = _incr, \
	.ed_keydefault = _def, \
	.ed_blocklen = _bsz, \
	.ed_ivlen = _iv, \
	.ed_icvlen = _icv, \
	.ed_saltlen = _s \
    }
static encr_data_t encr_tbl[IKEV2_ENCR_MAX + 1] = {
	/* p11, desc, mode, min, max, incr, default, blocksz, iv, icv, salt */
	EALG(NONE, 0, MODE_NONE, 0, 0, 0, 0, 0, 0, 0, 0),
	EALG(DES_IV64, CKM_DES_CBC, MODE_CBC, 64, 64, 0, 64, 8, 8, 0, 0),
	EALG(DES, CKM_DES_CBC, MODE_CBC, 64, 64, 0, 64, 64, 8, 0, 0),
	EALG(3DES, CKM_DES3_CBC, MODE_CBC, 192, 192, 0, 192, 8, 8, 0, 0),
	EALG(RC5, CKM_RC5_CBC, MODE_CBC, 40, 2040, 1, 128, 8, 8, 0, 0),
	EALG(IDEA, CKM_IDEA_CBC, MODE_CBC, 128, 128, 0, 128, 8, 8, 0, 0),
	EALG(CAST, CKM_CAST5_CBC, MODE_CBC, 40, 128, 1, 128, 8, 8, 0, 0),
	EALG(BLOWFISH, CKM_BLOWFISH_CBC, MODE_CBC, 40, 448, 1, 128, 8, 8, 0, 0),
	EALG(3IDEA, 0, MODE_CBC, 128, 128, 0, 16, 8, 8, 0, 0),
	EALG(DES_IV32, CKM_DES_CBC, MODE_CBC, 64, 64, 0, 64, 8, 4, 0, 0),
	EALG(RC4, CKM_RC4, MODE_CBC, 0, 0, 0, 0, 0, 0, 0, 0),
	{ IKEV2_ENCR_NULL, 0, "NULL", MODE_NONE, 0, 0, 0, 0, 0, 0, 0 },
	EALG(AES_CBC, CKM_AES_CBC, MODE_CBC, 128, 256, 64, 0, 16, 16, 0, 0),
	EALG(AES_CTR, CKM_AES_CTR, MODE_CTR,  128, 256, 64, 0, 16, 16, 0, 0),
	EALG(AES_CCM_8, CKM_AES_CCM, MODE_CCM, 128, 256, 64, 0, 16, 8, 8, 24),
	EALG(AES_CCM_12, CKM_AES_CCM, MODE_CCM,
	    128, 256, 64, 0, 16, 8, 12, 24),
	EALG(AES_CCM_16, CKM_AES_CCM, MODE_CCM,
	    128, 256, 64, 0, 16, 8, 16, 24),
	EALG(AES_GCM_8, CKM_AES_GCM, MODE_GCM, 128, 256, 64, 0, 16, 8, 8, 32),
	EALG(AES_GCM_12, CKM_AES_GCM, MODE_GCM,
	    128, 256, 64, 0, 16, 8, 12, 32),
	EALG(AES_GCM_16, CKM_AES_GCM, MODE_GCM,
	    128, 256, 64, 0, 16, 8, 16, 32),
	EALG(NULL_AES_GMAC, 0, MODE_NONE, 128, 256, 64, 0, 16, 16, 16, 0),
	EALG(XTS_AES, 0, MODE_NONE, 128, 256, 64, 0, 0, 0, 0, 0),
	EALG(CAMELLIA_CBC, CKM_CAMELLIA_CBC, MODE_CBC,
	    128, 256, 64, 0, 16, 16, 0, 0),
	EALG(CAMELLIA_CTR, CKM_CAMELLIA_CTR, MODE_CTR,
	    128, 256, 64, 0, 16, 16, 0, 0),
	EALG(CAMELLIA_CCM_8, 0, MODE_CCM, 128, 256, 64, 0, 16, 16, 8, 12),
	EALG(CAMELLIA_CCM_12, 0, MODE_CCM, 128, 256, 64, 0, 16, 16, 12, 12),
	EALG(CAMELLIA_CCM_16, 0, MODE_CCM, 128, 256, 64, 0, 16, 16, 16, 12),
};

static auth_data_t auth_tbl[IKEV2_XF_AUTH_MAX + 1] = {
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
	CK_ULONG		nslot = 0;
	CK_C_INITIALIZE_ARGS	args = {
		NULL_PTR,		/* CreateMutex */
		NULL_PTR,		/* DestroyMutex */
		NULL_PTR,		/* LockMutex */
		NULL_PTR,		/* UnlockMutex */
		CKF_OS_LOCKING_OK,	/* flags */
		NULL_PTR		/* reserved */
	};

	VERIFY0(mutex_init(&pkcs11_handle_lock, USYNC_THREAD|LOCK_ERRORCHECK,
	    NULL));

	if ((rv = C_Initialize(&args)) != CKR_OK) {
		PKCS11ERR(fatal, "C_Initialize", rv);
		exit(EXIT_FAILURE);
	}

	if ((rv = C_GetInfo(&pkcs11_info)) != CKR_OK) {
		PKCS11ERR(fatal, "C_Info", rv);
		exit(EXIT_FAILURE);
	}

	if ((rv = C_GetSlotList(CK_FALSE, NULL, &nslot)) != CKR_OK) {
		PKCS11ERR(fatal, "C_GetSlotList", rv);
		exit(EXIT_FAILURE);
	}

	CK_SLOT_ID slots[nslot];

	if ((rv = C_GetSlotList(CK_FALSE, slots, &nslot)) != CKR_OK) {
		PKCS11ERR(fatal, "C_GetSlotList", rv);
		exit(EXIT_FAILURE);
	}

	{
		char manf[PKCS11_MANUF_LEN];
		char libdesc[PKCS11_DESC_LEN];

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
	char manuf[PKCS11_MANUF_LEN];
	CK_RV rv;

	rv = C_GetSlotInfo(slot, &info);
	if (rv != CKR_OK) {
		PKCS11ERR(error, "C_GetSlotInfo", rv);
		return;
	}

	{
		char desc[PKCS11_DESC_LEN];
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
		PKCS11ERR(error, "C_GetTokenInfo", rv);

	char label[PKCS11_LABEL_LEN];
	char model[PKCS11_MODEL_LEN];
	char serial[PKCS11_SERIAL_LEN];
	char utctime[PKCS11_UTCTIME_LEN];

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

	for (size_t i = 0; i < pkcs11_nhandles; i++) {
		rv = C_CloseSession(pkcs11_handles[i]);
		if (rv != CKR_OK)
			PKCS11ERR(error, "C_CloseSession", rv);
	}
	free(pkcs11_handles);
	pkcs11_handles = NULL;
	pkcs11_nhandles = 0;
	pkcs11_handlesz = 0;

	rv = C_Finalize(NULL_PTR);
	if (rv != CKR_OK)
		PKCS11ERR(error, "C_Finalize", rv);
}

size_t
ikev2_auth_icv_size(ikev2_xf_encr_t encr, ikev2_xf_auth_t auth)
{
	const encr_data_t *ed = encr_data(encr);
	const auth_data_t *ad = auth_data(auth);

	VERIFY3P(ed, !=, NULL);
	VERIFY3P(ad, !=, NULL);

	if (ed->ed_icvlen != 0)
		return (ed->ed_icvlen);
	return (ad->ad_icvlen);
}

/*
 * Destroy a PKCS#11 object with nicer error messages in case of failure.
 */
void
pkcs11_destroy_obj(const char *name, CK_OBJECT_HANDLE_PTR objp)
{
	CK_RV ret;

	if (objp == NULL || *objp == CK_INVALID_HANDLE)
		return;

	if ((ret = C_DestroyObject(p11h(), *objp)) != CKR_OK) {
		PKCS11ERR(error, "C_DestroyObject", ret,
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
void
pkcs11_session_free(CK_SESSION_HANDLE h)
{
	if (h == CK_INVALID_HANDLE)
		return;

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
	mutex_enter(&pkcs11_handle_lock);
	if (pkcs11_nhandles + 1 > pkcs11_handlesz) {
		CK_SESSION_HANDLE *nh = NULL;
		size_t newamt = pkcs11_handlesz + CHUNK_SZ;

		pkcs11_handles = umem_reallocarray(pkcs11_handles,
		    pkcs11_handlesz, newamt, sizeof (CK_SESSION_HANDLE),
		    UMEM_NOFAIL);
		pkcs11_handlesz = newamt;
	}

	pkcs11_handles[pkcs11_nhandles++] = h;
	mutex_exit(&pkcs11_handle_lock);
}

CK_SESSION_HANDLE
p11h(void)
{
	/*
	 * When a worker is created, it must successfully create a
	 * PKCS#11 session handle, so this call can never fail or return
	 * CK_INVALID_HANDLE.
	 */
	return (worker->w_p11);
}

CK_SESSION_HANDLE
pkcs11_new_session(void)
{
	CK_SESSION_HANDLE h;
	CK_RV ret;

	mutex_enter(&pkcs11_handle_lock);
	if (pkcs11_nhandles > 0) {
		h = pkcs11_handles[--pkcs11_nhandles];
		mutex_exit(&pkcs11_handle_lock);
		VERIFY3U(h, !=, CK_INVALID_HANDLE);
		return (h);
	}
	mutex_exit(&pkcs11_handle_lock);

	ret = C_OpenSession(METASLOT_ID, CKF_SERIAL_SESSION, NULL,
	    pkcs11_callback_handler, &h);

	if (ret != CKR_OK) {
		PKCS11ERR(error, "C_OpenSession", ret);
		return (CK_INVALID_HANDLE);
	}

	return (h);
}

const encr_data_t *
encr_data(ikev2_xf_encr_t id)
{
	for (size_t i = 0; i < ARRAY_SIZE(encr_tbl); i++) {
		if (id == encr_tbl[i].ed_i2id)
			return (&encr_tbl[i]);
	}

	return (NULL);
}

const auth_data_t *
auth_data(ikev2_xf_auth_t id)
{
	if (id > ARRAY_SIZE(auth_tbl))
		return (NULL);

	return (&auth_tbl[id]);
}

boolean_t
encr_keylen_req(const encr_data_t *ed)
{
	return (encr_keylen_allowed(ed) || ed->ed_keydefault != 0);
}

boolean_t
encr_keylen_allowed(const encr_data_t *ed)
{
	return (ed->ed_keymin != ed->ed_keymax);
}

boolean_t
encr_keylen_ok(const encr_data_t *ed, size_t len)
{
	if (len < ed->ed_keymin || len > ed->ed_keymax)
		return (B_FALSE);

	/*
	 * If in range, value must also be a valid increment, e.g. for
	 * AES, 192 bits is ok, but 200 bits is not.
	 */
	if (((len - ed->ed_keymin) % ed->ed_keyincr) != 0)
		return (B_FALSE);

	return (B_TRUE);
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
