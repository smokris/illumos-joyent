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

#include <errno.h>
#include <netinet/in.h>
#include <signal.h>
#include <string.h>
#include <sys/debug.h>
#include <sys/time.h>
#include <time.h>
#include <pthread.h>
#include <port.h>
#include "defs.h"
#include "ikev2_cookie.h"
#include "ikev2_pkt.h"
#include "ikev2_proto.h"
#include "pkcs11.h"
#include "random.h"

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
 * Whenever cookies are enabled, we arm cookie_timer to fire every
 * COOKIE_SECRET_LIFETIME seconds to trigger the generation of a new secret
 * and increment of the version.  When the cookie_timer fires, it generates
 * an event on the event port used by the main thread which calls
 * cookie_update_secret() to create the new secret and increment the version
 * number.
 *
 * This rotation is done to minimize the ability of a remote attacker from
 * being able to determine the value of secret.  When we generate a new
 * secret, we do retain the previous version and allow the old secret to
 * be used for up to COOKIE_GRACE seconds after a new cookie is created.  This
 * should minimize excessive IKE_SA_INIT exchanges if they happen to occur
 * right before a new secret is generated, while hopefully having a minimal
 * impact on the effectiveness of the cookies themselves.
 *
 * The cookie secrets are not used in any way in deriving keying material
 * and only serve to make the prediction of the cookie value by a remote
 * attacker relatively expensive.  As such, we are not concerned about old
 * secret values lingering around in memory after they expire.
 *
 * While it is possible the version value could wrap around (being only 8-bits),
 * this is also not a concern as we generally only are concerned if the returned
 * cookie value has the same version as ours, or for COOKIE_GRACE seconds after
 * a new secret is generated, if the returned cookie version is the previous
 * version.  With the currently defined values, if cookies are continuously
 * enabled, it will take approximately 4.25 hours to wrap around.  In the worst
 * (and largely absurd) case, if a remote peer send back a cookie derived using
 * an 4.25 hour old secret that was derived using the same version (having
 * wrapped-around), the cookie check will merely fail and the remote peer will
 * need to resend its IKE_SA_INIT request with a current cookie.  This does
 * mean that we impose a maximum latency of
 * COOKIE_SECRET_LIFETIME + COOKIE_GRACE (currently 65) seconds on packets,
 * regardless of configured IKE timeouts.  Since we currently do not currently
 * have networks that span beyond Earth, this seems like a reasonable limitation
 * for the time being.
 */
static struct secret_s {
	uint8_t s_val[COOKIE_SECRET_LEN];
	hrtime_t s_birth;
} secret[2];
#define	SECRET(v) secret[(v) & 0x1].s_val
#define	SECRET_BIRTH(v) secret[(v) & 0x1].s_birth
#define	SECRET_AGE(v) (gethrtime() - SECRET_BIRTH(v))

static pthread_rwlock_t lock = PTHREAD_RWLOCK_INITIALIZER;
static uint8_t version;
static boolean_t enabled;
static timer_t cookie_timer;

static void cookie_update_secret(void);

void
ikev2_cookie_enable(void)
{
	VERIFY0(pthread_rwlock_wrlock(&lock));
	if (enabled)
		goto done;

	if (SECRET_AGE(version) < COOKIE_SECRET_LIFETIME) {
		struct itimerspec it = { 0 };
		hrtime_t exp = SECRET_BIRTH(version) + COOKIE_SECRET_LIFETIME;

		it.it_value.tv_sec = NSEC2SEC(exp);
		it.it_value.tv_nsec = exp % NANOSEC;

		if (timer_settime(cookie_timer, TIMER_ABSTIME, &it,
		    NULL) != 0) {
			STDERR(fatal, log, "timer_settime() failed");
			exit(EXIT_FAILURE);
		}
		goto done;
	}

	cookie_update_secret();

done:
	VERIFY0(pthread_rwlock_unlock(&lock));
}

void
ikev2_cookie_disable(void)
{
	struct itimerspec it = { 0 };
	VERIFY0(pthread_rwlock_wrlock(&lock));
	enabled = B_FALSE;
	if (timer_settime(cookie_timer, 0, &it, NULL) != 0) {
		STDERR(fatal, log, "timer_settime() failed");
		exit(EXIT_FAILURE);
	}
	VERIFY0(pthread_rwlock_wrlock(&lock));
}

static boolean_t
cookie_calc(uint8_t v, uint8_t *restrict nonce, size_t noncelen,
    const struct sockaddr_storage *restrict ip, uint64_t spi,
    uint8_t *out, CK_ULONG outlen)
{
	CK_SESSION_HANDLE h = p11h();
	CK_MECHANISM mech = { COOKIE_MECH, NULL_PTR, 0 };
	CK_ULONG iplen = 0;
	CK_RV rc = CKR_OK;

	rc = C_DigestInit(h, &mech);
	if (rc != CKR_OK) {
		PKCS11ERR(error, log, "C_DigestInit", rc);
		goto done;
	}

	rc = C_DigestUpdate(h, nonce, noncelen);
	if (rc != CKR_OK) {
		PKCS11ERR(error, log, "C_DigestUpdate", rc);
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
		PKCS11ERR(error, log, "C_DigestUpdate", rc);
		goto done;
	}

	rc = C_DigestUpdate(h, (CK_BYTE_PTR)&spi, sizeof (spi));
	if (rc != CKR_OK) {
		PKCS11ERR(error, log, "C_DigestUpdate", rc);
		goto done;
	}

	rc = C_DigestUpdate(h, SECRET(v), COOKIE_SECRET_LEN);
	if (rc != CKR_OK) {
		PKCS11ERR(error, log, "C_DigestUpdate", rc);
		goto done;
	}

	rc = C_DigestFinal(h, out, &outlen);
	if (rc != CKR_OK) {
		PKCS11ERR(error, log, "C_DigestFinal", rc);
		goto done;
	}

done:
	return ((rc == CKR_OK) ? B_TRUE : B_FALSE);
}

static void
send_cookie(pkt_t *restrict pkt,
    const struct sockaddr_storage *restrict laddr,
    const struct sockaddr_storage *restrict raddr)
{
	pkt_payload_t *nonce = pkt_get_payload(pkt, IKEV2_PAYLOAD_NONCE, NULL);
	pkt_t *resp = ikev2_pkt_new_response(pkt);
	uint8_t buf[COOKIE_LEN] = { 0 };

	if (resp == NULL || nonce == NULL)
		return;

	buf[0] = version;
	if (!cookie_calc(version, nonce->pp_ptr, nonce->pp_len, raddr,
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
    const struct sockaddr_storage *restrict laddr,
    const struct sockaddr_storage *restrict raddr)
{
	pkt_notify_t *cookie = pkt_get_notify(pkt, IKEV2_N_COOKIE, NULL);
	pkt_payload_t *nonce = pkt_get_payload(pkt, IKEV2_PAYLOAD_NONCE, NULL);
	boolean_t ok = B_TRUE;

	VERIFY0(pthread_rwlock_rdlock(&lock));
	if (!enabled)
		goto done;

	if (cookie == NULL) {
		ok = B_FALSE;
		send_cookie(pkt, laddr, raddr);
		goto done;
	}

	if (cookie->pn_len != COOKIE_LEN) {
		ok = B_FALSE;
		goto done;
	}

	if (cookie->pn_ptr[0] != version && (cookie->pn_ptr[0] != version - 1 ||
	    SECRET_AGE(version - 1) > COOKIE_GRACE)) {
		ok = B_FALSE;
		goto done;
	}

	ok = cookie_compare(nonce->pp_ptr, nonce->pp_len, raddr,
	    pkt->pkt_raw[0], cookie->pn_ptr, cookie->pn_len);

done:
	VERIFY0(pthread_rwlock_unlock(&lock));
	return (ok);
}

static void
cookie_update_secret(void)
{
	struct itimerspec it = { 0 };

	VERIFY0(pthread_rwlock_wrlock(&lock));

	if (SECRET_BIRTH(version) != 0)
		version++;
	random_low(SECRET(version), COOKIE_SECRET_LEN);
	SECRET_BIRTH(version) = gethrtime();

	VERIFY0(pthread_rwlock_unlock(&lock));

	it.it_value.tv_sec = NSEC2SEC(COOKIE_SECRET_LIFETIME);
	it.it_value.tv_nsec = COOKIE_SECRET_LIFETIME % NANOSEC;
	it.it_interval = it.it_value;
	if (timer_settime(cookie_timer, 0, &it, NULL) != 0) {
		STDERR(fatal, log, "timer_settime() failed");
		exit(EXIT_FAILURE);
	}
}

void
ikev2_cookie_init(void)
{
	struct sigevent se = { 0 };
	port_notify_t pn;

	pn.portnfy_port = port;
	pn.portnfy_user = cookie_update_secret;
	se.sigev_notify = SIGEV_PORT;
	se.sigev_value.sival_ptr = &pn;

	if (timer_create(CLOCK_REALTIME, &se, &cookie_timer) != 0) {
		STDERR(fatal, log, "timer_create() failed");
		exit(EXIT_FAILURE);
	}
}
