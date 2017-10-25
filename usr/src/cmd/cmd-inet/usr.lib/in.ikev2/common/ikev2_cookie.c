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
 * Copyright (c) 2017, Joyent, Inc.
 */

#include <err.h>
#include <errno.h>
#include <netinet/in.h>
#include <libperiodic.h>
#include <signal.h>
#include <string.h>
#include <synch.h>
#include <sys/debug.h>
#include <sys/random.h>
#include <sys/time.h>
#include <time.h>
#include <port.h>
#include "defs.h"
#include "ikev2_cookie.h"
#include "ikev2_pkt.h"
#include "ikev2_proto.h"
#include "pkcs11.h"
#include "worker.h"

#define	COOKIE_MECH		CKM_SHA_1
#define	COOKIE_SECRET_LEN	(64)
#define	COOKIE_LEN		(16 + 1)
#define	COOKIE_SECRET_LIFETIME	SEC2NSEC(60)
#define	COOKIE_GRACE		SEC2NSEC(5)

size_t ikev2_cookie_threshold = 128;

/*
 * For cookies, we follow the guidance in RFC7296 2.6 and generate cookies
 * such that:
 *
 *	Cookie = <VersionIDofSecret> | Hash(Ni | IPi | SPIi | <secret>)
 *
 * where <secret> is a random value of length COOKE_SECRET_LEN bytes,
 * hash is the hash algorithm designated by COOKIE_MECH (currently CKM_SHA_1),
 * and <VersionIDofSecret> is a monotonically increasing 8-bit unsigned
 * value that corresponds to a given value of <secret>.  Note that the remote
 * peer treats the cookie value as opaque and should not attempt to divine
 * any structure in the value -- it is merely meant as a reasonably hard to
 * predict value the remote peer must include in an IKE_SA_INIT exchange
 * (when we request it) to prevent a remote peer from being able to generate
 * large amounts of larval (half-open) IKE SAs.
 *
 * We create a new secret every COOKIE_SECRET_LIFETIME nanoseconds (currently
 * once a minute).  We retain the previous secret and allow it's use for up to
 * COOKIE_GRACE seconds after rotation to minimize excessive IKE_SA_INIT
 * exchanges if an exchange happens to occur near the end of the current
 * secret's lifetime.  This rotation is done to minimize the chances a remote
 * attacker will be able to determine the value of the secret (and thus
 * defeat it's purpose).  It should be noted that the cookie secret is not
 * used in deriving any key material -- only as a deterrent, as such having
 * old values persist in memory for a while after use is not a major concern.
 *
 * While we only choose 8 bits to hold the version number, with current the
 * current lifetime settings, the version number will wrap around about every
 * 4.5 hours.  Since we only concern ourselves at most with the current and
 * previous version numbers, the worst (and largely absurd) case is someone
 * could reply with a cookie derived from a 4.5 old secret.  In this instance,
 * the cookie check will fail, and things will proceed in the same manner as
 * if the cookie wasn't present (i.e. an error response with a cookie derived
 * from the current secret will be sent, and processing will not proceed until
 * a response with the current cookie is received).  This seems like a
 * reasonable tradeoff as long as the peers doing the exchange reside on the
 * same planet.
 *
 * We currently only start sending cookies in responses once we hit a threshold
 * of larval (half-open) IKE SAs (as indicated by the i2c_enabled variable).
 * However, we are always updating the cookie secret at all times, even while
 * it is not being used.  The impact is minimal, and it makes things simpler.
 *
 * One may note that the threat of a DOS attack from a single host is far
 * less likely these days than a DDOS, and that cookies are not as effective
 * in mitigating such attacks.  Such an observer would be correct, however
 * this is still a SHOULD recommendation in the RFC, it's not particularly
 * complex, and we MUST support responding to a responder who sends us
 * cookies -- so it's not really doing much harm.
 */
static struct secret_s {
	uint8_t s_val[COOKIE_SECRET_LEN];
	hrtime_t s_birth;
} i2c_secret[2];
#define	SECRET(v) i2c_secret[(v) & 0x1].s_val
#define	SECRET_BIRTH(v) i2c_secret[(v) & 0x1].s_birth
#define	SECRET_AGE(v) (gethrtime() - SECRET_BIRTH(v))

static rwlock_t i2c_lock = DEFAULTRWLOCK;
static volatile uint8_t i2c_version;
static boolean_t i2c_enabled;
static periodic_id_t cookie_timer_id;

static void cookie_update_secret(void *);

void
ikev2_cookie_enable(void)
{
	VERIFY0(rw_wrlock(&i2c_lock));
	i2c_enabled = B_TRUE;
	VERIFY0(rw_unlock(&i2c_lock));
}

void
ikev2_cookie_disable(void)
{
	VERIFY0(rw_wrlock(&i2c_lock));
	i2c_enabled = B_FALSE;
	VERIFY0(rw_unlock(&i2c_lock));
}

static boolean_t
cookie_calc(uint8_t v, uint8_t *restrict nonce, size_t noncelen,
    const struct sockaddr_storage *restrict ip, uint64_t spi,
    uint8_t *out, CK_ULONG outlen)
{
	VERIFY(IS_WORKER);

	CK_SESSION_HANDLE h = p11h();
	CK_MECHANISM mech = { COOKIE_MECH, NULL_PTR, 0 };
	CK_ULONG iplen = 0;
	CK_RV rc = CKR_OK;

	rc = C_DigestInit(h, &mech);
	if (rc != CKR_OK) {
		PKCS11ERR(error,"C_DigestInit", rc);
		goto done;
	}

	rc = C_DigestUpdate(h, nonce, noncelen);
	if (rc != CKR_OK) {
		PKCS11ERR(error, "C_DigestUpdate", rc);
		goto done;
	}

	switch (ip->ss_family) {
	case AF_INET:
		iplen = sizeof (in_addr_t);
		break;
	case AF_INET6:
		iplen = sizeof (in6_addr_t);
		break;
	default:
		INVALID("ss_family");
	}
	rc = C_DigestUpdate(h, (CK_BYTE_PTR)ss_addr(ip), iplen);
	if (rc != CKR_OK) {
		PKCS11ERR(error, "C_DigestUpdate", rc);
		goto done;
	}

	rc = C_DigestUpdate(h, (CK_BYTE_PTR)&spi, sizeof (spi));
	if (rc != CKR_OK) {
		PKCS11ERR(error, "C_DigestUpdate", rc);
		goto done;
	}

	rc = C_DigestUpdate(h, SECRET(v), COOKIE_SECRET_LEN);
	if (rc != CKR_OK) {
		PKCS11ERR(error, "C_DigestUpdate", rc);
		goto done;
	}

	rc = C_DigestFinal(h, out, &outlen);
	if (rc != CKR_OK) {
		PKCS11ERR(error, "C_DigestFinal", rc);
		goto done;
	}

done:
	return ((rc == CKR_OK) ? B_TRUE : B_FALSE);
}

static void
send_cookie(pkt_t *restrict pkt,
    const struct sockaddr_storage *restrict raddr)
{
	pkt_payload_t *nonce = pkt_get_payload(pkt, IKEV2_PAYLOAD_NONCE, NULL);
	pkt_t *resp = ikev2_pkt_new_response(pkt);
	uint8_t buf[COOKIE_LEN] = { 0 };

	if (resp == NULL || nonce == NULL)
		return;

	buf[0] = i2c_version;
	if (!cookie_calc(i2c_version, nonce->pp_ptr, nonce->pp_len, raddr,
	    pkt->pkt_raw[0], buf + 1, sizeof (buf) - 1)) {
		ikev2_pkt_free(resp);
		return;
	}

	if (!ikev2_add_notify(resp, IKEV2_PROTO_IKE, 0, IKEV2_N_COOKIE, buf,
	    sizeof (buf))) {
		ikev2_pkt_free(resp);
		return;
	}

	(void) ikev2_send(resp, B_TRUE);
}

static boolean_t
cookie_compare(uint8_t *restrict nonce, size_t noncelen,
    const struct sockaddr_storage *restrict ip, uint64_t spi,
    uint8_t *restrict cmp, size_t cmplen)
{
	uint8_t buf[COOKIE_LEN] = { 0 };

	VERIFY3U(cmplen, ==, sizeof (buf));

	buf[0] = cmp[0];
	if (!cookie_calc(cmp[0], nonce, noncelen, ip, spi, buf + 1,
	    sizeof (buf) - 1))
		return (B_FALSE);
	return (!!(memcmp(buf, cmp, cmplen) == 0));
}

/*
 * If cookies are enabled, perform cookie check and response. Return B_TRUE
 * if cookie check succeeds.
 * If cookies aren't enabled, just return B_TRUE to continue processing.
 */
boolean_t
ikev2_cookie_check(pkt_t *restrict pkt,
    const struct sockaddr_storage *restrict raddr)
{
	pkt_notify_t *cookie = pkt_get_notify(pkt, IKEV2_N_COOKIE, NULL);
	pkt_payload_t *nonce = pkt_get_payload(pkt, IKEV2_PAYLOAD_NONCE, NULL);
	boolean_t ok = B_TRUE;

	VERIFY0(rw_rdlock(&i2c_lock));
	if (!i2c_enabled)
		goto done;

	if (cookie == NULL) {
		ok = B_FALSE;
		send_cookie(pkt, raddr);
		goto done;
	}

	if (cookie->pn_len != COOKIE_LEN) {
		ok = B_FALSE;
		goto done;
	}

	if (cookie->pn_ptr[0] != i2c_version &&
	    (cookie->pn_ptr[0] != i2c_version - 1 ||
	    SECRET_AGE(i2c_version - 1) > COOKIE_GRACE)) {
		ok = B_FALSE;
		goto done;
	}

	ok = cookie_compare(nonce->pp_ptr, nonce->pp_len, raddr,
	    pkt->pkt_raw[0], cookie->pn_ptr, cookie->pn_len);

done:
	VERIFY0(rw_unlock(&i2c_lock));
	return (ok);
}

/*ARGSUSED*/
static void
cookie_update_secret(void *dummy)
{
	uint32_t version = 0;

	VERIFY0(rw_wrlock(&i2c_lock));

	if (SECRET_BIRTH(i2c_version) != 0)
		i2c_version++;

	version = i2c_version;

	arc4random_buf(SECRET(i2c_version), COOKIE_SECRET_LEN);
	SECRET_BIRTH(i2c_version) = gethrtime();

	VERIFY0(rw_unlock(&i2c_lock));

	(void) bunyan_debug(log, "Created new cookie secret",
	    BUNYAN_T_UINT32, "version", version, BUNYAN_T_END);
}

void
ikev2_cookie_init(void)
{
	cookie_update_secret(NULL);

	if (periodic_schedule(wk_periodic, COOKIE_SECRET_LIFETIME, 0,
	    cookie_update_secret, NULL, &cookie_timer_id) != 0) {
		err(EXIT_FAILURE, "Could not schedule cookie periodic");
	}
}
