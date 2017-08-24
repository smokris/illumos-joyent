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
 * Copyright (c) 2017 Joyent, Inc.
 */

#include <pthread.h>
#include <umem.h>
#include <err.h>
#include <sys/debug.h>
#include <bunyan.h>
#include <time.h>
#include <string.h>
#include "defs.h"
#include "worker.h"
#include "pkt.h"
#include "timer.h"
#include "pkcs11.h"
#include "ikev2_proto.h"
#include "ikev2_sa.h"
#include "config.h"
#include "ikev2_pkt.h"
#include "ikev2_enum.h"
#include "ikev2_common.h"
#include "prf.h"

static boolean_t find_config(pkt_t *, sockaddr_u_t, sockaddr_u_t);
static boolean_t add_nat(pkt_t *);
static boolean_t check_nats(pkt_t *);
static void check_vendor(pkt_t *);
static boolean_t add_vendor(pkt_t *);
static boolean_t add_rule_proposals(pkt_t *restrict,
    const config_rule_t *restrict, uint64_t);
static boolean_t add_cookie(pkt_t *restrict, void *restrict, size_t len);

/*
 * New inbound IKE_SA_INIT exchange
 */
void
ikev2_sa_init_inbound_init(pkt_t *pkt)
{
	ikev2_sa_t *sa = pkt->pkt_sa;
	pkt_t *resp = NULL;
	sockaddr_u_t laddr = { .sau_ss = &sa->laddr };
	sockaddr_u_t raddr = { .sau_ss = &sa->raddr };
	ikev2_sa_result_t sa_result = { 0 };
	size_t noncelen = 0;

	VERIFY(!(sa->flags & I2SA_INITIATOR));

	if (!find_config(pkt, laddr, raddr))
		goto fail;
	if (!check_nats(pkt))
		goto fail;
	check_vendor(pkt);

	sa->init = pkt;

	if (!ikev2_sa_match_rule(sa->i2sa_rule, pkt, &sa_result)) {
		/* XXX: no proposal chosen */
		goto fail;
	}

	/* RFC7296 2.10 nonce length should be at least half key size of PRF */
	noncelen = ikev2_prf_keylen(sa_result.sar_prf) / 2;

	/* But must still be within defined limits */
	if (noncelen < IKEV2_NONCE_MIN)
		noncelen = IKEV2_NONCE_MIN;
	if (noncelen > IKEV2_NONCE_MAX)
		noncelen = IKEV2_NONCE_MAX;

	resp = ikev2_pkt_new_response(pkt);
	if (resp == NULL)
		goto fail;

	if (!ikev2_sa_add_result(resp, &sa_result))
		goto fail;

	/* XXX: KE */

	if (!ikev2_add_nonce(resp, noncelen))
		goto fail;
	if (!add_nat(resp))
		goto fail;

	/* XXX: CERTREQ? */
	/* XXX: other notifications */

	if (!add_vendor(resp))
		goto fail;

	if (!ikev2_send(resp, B_FALSE))
		goto fail;
	return;

fail:
	ikev2_pkt_free(pkt);
	ikev2_pkt_free(resp);
	/* XXX: Delete larval IKE SA? anything else? */
}

void
ikev2_sa_init_inbound_resp(pkt_t *pkt)
{
	pkt_notify_t *cookie = pkt_get_notify(pkt, (uint16_t)IKEV2_N_COOKIE,
	    NULL);

	if (cookie != NULL) {
		pkt_t *out = pkt->pkt_sa->init;

		if (!add_cookie(out, cookie->pn_ptr, cookie->pn_len) ||
		    !ikev2_send(out, B_FALSE)) {
			/* XXX: destroy larval IKE SA? */
		}
		return;
	}

	if (!check_nats(pkt))
		goto fail;
	check_vendor(pkt);

	/* XXX: Verify SA payload */

	return;
fail:
	/* XXX: destroy IKE SA? */
	;
}

void
ikev2_sa_init_outbound(ikev2_sa_t *i2sa)
{
	pkt_t *pkt = NULL;
	sockaddr_u_t laddr = { .sau_ss = &i2sa->laddr };
	sockaddr_u_t raddr = { .sau_ss = &i2sa->raddr };
	size_t noncelen = 0;

	VERIFY(i2sa->flags & I2SA_INITIATOR);

	pkt = ikev2_pkt_new_initiator(i2sa, IKEV2_EXCH_IKE_SA_INIT);

	if (!find_config(pkt, laddr, raddr))
		goto fail;

	if (!add_rule_proposals(pkt, i2sa->i2sa_rule, 0))
		goto fail;

	/* XXX: KE */

	if (!ikev2_add_nonce(pkt, noncelen))
		goto fail;
	if (!add_nat(pkt))
		goto fail;
	if (!add_vendor(pkt))
		goto fail;

	/* XXX: CERTREQ */

	i2sa->init = pkt;

	if (!ikev2_send(pkt, B_FALSE))
		goto fail;
	return;

fail:
	ikev2_pkt_free(pkt);
	/* XXX: destroy SA? */
}

/*
 * XXX: These two functions should probably be moved at some point so they
 * can be used both for initial IKE SA creation and for IKE re-keying
 * (which operates as a type of CREATE_CHILD_SA exchange
 */
static boolean_t
add_rule_xform(pkt_t *restrict pkt, const config_xf_t *restrict xf)
{
	encr_modes_t mode = ikev2_encr_mode(xf->xf_encr);
	boolean_t ok = B_TRUE;

	ok &= ikev2_add_xf_encr(pkt, xf->xf_encr, xf->xf_minbits,
	    xf->xf_maxbits);

	/*
	 * For all currently known combined mode ciphers, we don't need
	 * to also include an integrity transform
	 */
	if (!MODE_IS_COMBINED(mode))
		ok &= ikev2_add_xform(pkt, IKEV2_XF_AUTH, xf->xf_auth);

	ok &= ikev2_add_xform(pkt, IKEV2_XF_DH, xf->xf_dh);

	/*
	 * XXX: IKEV1 determined the PRF based on the authentication method.
	 * IKEV2 allows it to be negotiated separately.  Eventually we
	 * should probably add an option to specify it in a transform
	 * definition.  For now, we just include all the ones we support
	 * in decreasing order of preference.
	 */
	ikev2_prf_t supported[] = {
	    IKEV2_PRF_HMAC_SHA2_512,
	    IKEV2_PRF_HMAC_SHA2_384,
	    IKEV2_PRF_HMAC_SHA2_256,
	    IKEV2_PRF_HMAC_SHA1,
	    IKEV2_PRF_HMAC_MD5
	};

	for (size_t i = 0; i < ARRAY_SIZE(supported); i++)
		ok &= ikev2_add_xform(pkt, IKEV2_XF_PRF, supported[i]);

	return (ok);
}

static boolean_t
add_rule_proposals(pkt_t *restrict pkt, const config_rule_t *restrict rule,
    uint64_t spi)
{
	boolean_t ok = B_TRUE;

	if (!ikev2_add_sa(pkt))
		return (B_FALSE);

	for (uint8_t i = 0; rule->rule_xf[i] != NULL; i++) {
		/* RFC7296 3.3.1 proposal numbers start with 1 */
		ok &= ikev2_add_prop(pkt, i + 1, IKEV2_PROTO_IKE, spi);
		ok &= add_rule_xform(pkt, rule->rule_xf[i]);
	}

	return (ok);
}

static boolean_t
find_config(pkt_t *pkt, sockaddr_u_t laddr, sockaddr_u_t raddr)
{
	ikev2_sa_t *sa = pkt->pkt_sa;

	sa->i2sa_rule = config_get_rule(&laddr, &raddr);

	if (sa->i2sa_rule->rule_xf[0] == NULL) {
		bunyan_debug(sa->i2sa_log, "No rules found", BUNYAN_T_END);
		ikev2_no_proposal_chosen(sa, pkt, IKEV2_PROTO_IKE, 0);
		return (B_FALSE);
	}

	if (RULE_IS_DEFAULT(sa->i2sa_rule)) {
		bunyan_debug(sa->i2sa_log, "Using default rule", BUNYAN_T_END);
	} else {
		bunyan_debug(sa->i2sa_log, "Found rule",
		    BUNYAN_T_STRING, "label", sa->i2sa_rule->rule_label,
		    BUNYAN_T_END);
	}
	return (B_TRUE);
}

#define	NAT_LEN	(20)
/*
 * Check if the NAT {src,dest} payload matches our IP address.
 * Return 0 if match (i.e. no nat)
 *     1 if match
 *     -1 on error
 */
static int
check_one_nat(pkt_t *pkt, pkt_notify_t *n)
{
	bunyan_logger_t *l = pkt->pkt_sa->i2sa_log;
	CK_SESSION_HANDLE h = p11h;
	sockaddr_u_t addr;
	CK_MECHANISM mech = { .mechanism = CKM_SHA_1 };
	buf_t buf[3];
	CK_BYTE data[NAT_LEN] = { 0 };
	buf_t out = { .b_ptr = data, .b_len = sizeof (data) };
	CK_LONG len = 0;
	CK_RV rv;

	switch (n->pn_type) {
	case IKEV2_N_NAT_DETECTION_SOURCE_IP:
		addr.sau_ss = &pkt->pkt_sa->laddr;
		break;
	case IKEV2_N_NAT_DETECTION_DESTINATION_IP:
		addr.sau_ss = &pkt->pkt_sa->raddr;
		break;
	default:
		INVALID(n->pn_type);
		/*NOTREACHED*/
		return (-1);
	}

	buf[0].b_ptr = (CK_BYTE_PTR)&pkt->pkt_raw;
	buf[0].b_len = 2 * sizeof (uint64_t);

	switch (addr.sau_ss->ss_family) {
	case AF_INET:
		buf[1].b_ptr = (CK_BYTE_PTR)&addr.sau_sin->sin_addr;
		buf[1].b_len = sizeof (in_addr_t);
		buf[2].b_ptr = (CK_BYTE_PTR)&addr.sau_sin->sin_port;
		buf[2].b_len = sizeof (addr.sau_sin->sin_port);
		break;
	case AF_INET6:
		buf[1].b_ptr = (CK_BYTE_PTR)&addr.sau_sin6->sin6_addr;
		buf[1].b_len = sizeof (in6_addr_t);
		buf[2].b_ptr = (CK_BYTE_PTR)&addr.sau_sin6->sin6_port;
		buf[2].b_len = sizeof (addr.sau_sin6->sin6_port);
		break;
	default:
		INVALID("addr.sau_ss->ss_family");
		return (-1);
	}

	if (n->pn_len != NAT_LEN) {
		bunyan_error(l, "Invalid notify payload size",
		    BUNYAN_T_STRING, "notify_type",
		    ikev2_notify_str(n->pn_type),
		    BUNYAN_T_UINT32, "payload_size", (uint32_t)n->pn_len,
		    BUNYAN_T_UINT32, "expected_size", (uint32_t)NAT_LEN,
		    BUNYAN_T_END);
		return (-1);
	}

	if (!pkcs11_digest(CKM_SHA_1, buf, ARRAY_SIZE(buf), &out, l))
		return (-1);

	VERIFY3U(n->pn_len, ==, sizeof (data));
	if (memcmp(n->pn_ptr, data, sizeof (data)) == 0)
		return (0);

	return (1);
}

/*
 * Perform NAT detection and update IKEV2 SA accordingly.  Return B_FALSE on
 * error, B_TRUE if no error.
 */
static boolean_t
check_nats(pkt_t *pkt)
{
	ikev2_sa_t *sa = pkt->pkt_sa;
	pkt_notify_t *n = NULL;
	int rc = 0;
	boolean_t local_nat = B_TRUE;
	boolean_t remote_nat = B_TRUE;

	/*
	 * Since the SOURCE/DESTINATION designation is from the perspective
	 * of the remote side, the local/remote notion is reversed on our
	 * side.
	 */
	n = pkt_get_notify(pkt, IKEV2_N_NAT_DETECTION_SOURCE_IP, NULL);
	if (n == NULL) {
		/* If the notification isn't present, assume no NAT */
		remote_nat = B_FALSE;
	} else {
		while (n != NULL) {
			rc = check_one_nat(pkt, n);
			if (rc == -1) {
				return (B_FALSE);
			} else if (rc == 0) {
				remote_nat = B_FALSE;
				break;
			}
			n = pkt_get_notify(pkt,
			    IKEV2_N_NAT_DETECTION_SOURCE_IP, n);
		}
	}

	if (remote_nat) {
		bunyan_debug(sa->i2sa_log, "Remote NAT detected", BUNYAN_T_END);
		sa->flags |= I2SA_NAT_REMOTE;
	}

	n = pkt_get_notify(pkt, IKEV2_N_NAT_DETECTION_DESTINATION_IP, NULL);
	if (n == NULL) {
		/* Similar as above */
		local_nat = B_FALSE;
	} else {
		while (n != NULL) {
			rc = check_one_nat(pkt, n);
			if (rc == -1) {
				return (B_FALSE);
			} else if (rc == 0) {
				local_nat = B_FALSE;
				break;
			}
			n = pkt_get_notify(pkt,
			    IKEV2_N_NAT_DETECTION_DESTINATION_IP, n);
		}
	}

	if (local_nat) {
		bunyan_debug(sa->i2sa_log, "Local NAT detected", BUNYAN_T_END);
		sa->flags |= I2SA_NAT_LOCAL;
	}

	return (B_TRUE);
}

/*
 * RFC7296 2.23 -- Add NAT detection notifiation payloads.  The notification
 * payload consists of the SHA-1 has of the SPIs (in order as they appear in
 * the header), IP address, and port.
 */
static boolean_t
add_nat(pkt_t *pkt)
{
	bunyan_logger_t *l = pkt->pkt_sa->i2sa_log;
	sockaddr_u_t addr[2];
	uint64_t spi[2];
	ikev2_notify_type_t ntype[2];
	buf_t buf[3];

	addr[0].sau_ss = &pkt->pkt_sa->laddr;
	addr[1].sau_ss = &pkt->pkt_sa->raddr;
	ntype[0] = IKEV2_N_NAT_DETECTION_SOURCE_IP;
	ntype[1] = IKEV2_N_NAT_DETECTION_DESTINATION_IP;

	/*
	 * These normally don't get converted to network byte order until
	 * the packet has finished construction, so we need to do local
	 * conversion for the NAT payload creation
	 */
	spi[0] = htonll(pkt->pkt_header.initiator_spi);
	spi[1] = htonll(pkt->pkt_header.responder_spi);

	buf[0].b_ptr = (CK_BYTE_PTR)&spi;
	buf[0].b_len = sizeof (spi);

	for (int i = 0; i < 2; i++) {
		uchar_t data[NAT_LEN] = { 0 };
		buf_t out = { .b_ptr = data, .b_len = sizeof (data) };

		switch (addr[i].sau_ss->ss_family) {
		case AF_INET:
			buf[1].b_ptr = (CK_BYTE_PTR)&addr[i].sau_sin->sin_addr;
			buf[1].b_len = sizeof (in_addr_t);
			buf[2].b_ptr = (CK_BYTE_PTR)&addr[i].sau_sin->sin_port;
			buf[2].b_len = sizeof (addr[i].sau_sin->sin_port);
			break;
		case AF_INET6:
			buf[1].b_ptr =
			    (CK_BYTE_PTR)&addr[i].sau_sin6->sin6_addr;
			buf[1].b_len = sizeof (in6_addr_t);
			buf[2].b_ptr =
			    (CK_BYTE_PTR)&addr[i].sau_sin6->sin6_port;
			buf[2].b_len = sizeof (addr[i].sau_sin6->sin6_port);
			break;
		default:
			INVALID("addr.sau_ss->ss_family");
			return (B_FALSE);
		}

		if (!pkcs11_digest(CKM_SHA_1, buf, ARRAY_SIZE(buf), &out, l))
			return (B_FALSE);

		if (!ikev2_add_notify(pkt, IKEV2_PROTO_IKE, 0, ntype[i],
		    data, sizeof (data)))
			return (B_FALSE);
	}

	return (B_TRUE);
}

static void
check_vendor(pkt_t *pkt)
{
	ikev2_sa_t *sa = pkt->pkt_sa;

	for (uint16_t i = 0; i < pkt->pkt_payload_count; i++) {
		pkt_payload_t *pay = pkt_payload(pkt, i);

		if (pay->pp_type != IKEV2_PAYLOAD_VENDOR)
			continue;
		if (pay->pp_len != sizeof (VENDOR_STR_ILLUMOS_1))
			continue;

		if (memcmp(VENDOR_STR_ILLUMOS_1, pay->pp_ptr,
		    sizeof (VENDOR_STR_ILLUMOS_1)) == 0) {
			bunyan_debug(sa->i2sa_log,
			    "Found illumos_1 vendor payload", BUNYAN_T_END);
			sa->vendor = VENDOR_ILLUMOS_1;
		}
	}
}

static boolean_t
add_vendor(pkt_t *pkt)
{
	return (ikev2_add_vendor(pkt, (uchar_t *)VENDOR_STR_ILLUMOS_1,
	    sizeof (VENDOR_STR_ILLUMOS_1)));
}

static boolean_t
add_cookie(pkt_t *restrict pkt, void *restrict cookie, size_t len)
{
	pkt_notify_t *n = pkt_get_notify(pkt, IKEV2_N_COOKIE, NULL);
	uint8_t *start = (uint8_t *)pkt_start(pkt) + sizeof (ike_header_t) +
	    sizeof (ikev2_payload_t);
	ssize_t total = sizeof (ikev2_payload_t) + sizeof (ikev2_notify_t) +
	    len;
	size_t num = 1;
	ikev2_notify_t ntfy = {
	    .n_protoid = IKEV2_PROTO_IKE,
	    .n_spisize = 0,
	    .n_type = htons((uint16_t)IKEV2_N_COOKIE)
	};

	/*
	 * If there's no existing cookie payload, make room for one,
	 * otherwise just shift existing payloads (if necessary) to reuse
	 * existing cookie payload
	 */
	if (n == NULL) {
		total += sizeof (ikev2_payload_t) + sizeof (ikev2_notify_t);
		num = 1;
	} else {
		/* Per RFC7296 2.6, this better be the first payload */
		VERIFY3P(start, ==, (uint8_t *)n->pn_ptr);
		total += len - (ssize_t)n->pn_len;
		num = 0;
	}

	if (total > 0 && pkt_write_left(pkt) < total)
		return (B_FALSE);

	if (!(pkt->pkt_header.flags & IKEV2_FLAG_INITIATOR)) {
		/* Simple case, we are responding with own cookie */

		/* Should be the only payload */
		VERIFY3U(pkt->pkt_payload_count, ==, 0);

		return (ikev2_add_notify(pkt, IKEV2_PROTO_IKE, 0,
		    IKEV2_N_COOKIE, cookie, len));
	}

	/* Make room to insert new first payload */
	if (!pkt_pay_shift(pkt, (uint8_t)IKEV2_PAYLOAD_NOTIFY, num, total))
		return (B_FALSE);

	(void) memcpy(start, &ntfy, sizeof (ntfy));
	(void) memcpy(start + sizeof (ntfy), cookie, len);
	return (B_TRUE);
}
