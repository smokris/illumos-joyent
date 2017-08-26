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
		ikev2_no_proposal_chosen(sa, pkt, IKEV2_PROTO_IKE, 0);
		goto fail;
	}

	sa->encr = sa_result.sar_encr;
	sa->encr_key_len = sa_result.sar_encr_keylen;
	sa->auth = sa_result.sar_auth;
	sa->prf = sa_result.sar_prf;
	sa->dhgrp = sa_result.sar_dh;

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

/*
 * Size of a SHA1 hash.  NAT detection always uses SHA1 to compute the
 * NAT detection payload contents.
 */
#define	NAT_LEN	(20)

/* Compute a NAT detection payload and place result into buf */
static boolean_t
compute_nat(uint64_t *restrict spi, struct sockaddr_storage *restrict addr,
    uint8_t *restrict buf, size_t buflen, bunyan_logger_t *l)
{
	const char *p11f = NULL;
	CK_SESSION_HANDLE h = p11h();
	CK_MECHANISM mech = {
		.mechanism = CKM_SHA_1,
		.pParameter = NULL_PTR,
		.ulParameterLen = 0
	};
	CK_BYTE_PTR addrp = (CK_BYTE_PTR)ss_addr(addr);
	CK_ULONG len = buflen;
	CK_RV ret = CKR_OK;
	size_t addrlen = (addr->ss_family == AF_INET) ?
	    sizeof (in_addr_t) : sizeof (in6_addr_t);
	uint16_t port = (uint16_t)ss_port(addr);

	VERIFY3U(buflen, >=, NAT_LEN);

	p11f = "C_DigestInit";
	ret = C_DigestInit(h, &mech);
	if (ret != CKR_OK)
		goto fail;

	/* Both SPIs (in order) */
	p11f = "C_DigestUpdate";
	ret = C_DigestUpdate(h, (CK_BYTE_PTR)spi, 2 * sizeof (uint64_t));
	if (ret != CKR_OK)
		goto fail;

	ret = C_DigestUpdate(h, addrp, addrlen);
	if (ret != CKR_OK)
		goto fail;

	ret = C_DigestUpdate(h, (CK_BYTE_PTR)&port, sizeof (port));
	if (ret != CKR_OK)
		goto fail;

	p11f = "C_DigestFinal";
	ret = C_DigestFinal(h, buf, &len);
	if (ret != CKR_OK)
		goto fail;

	return (B_TRUE);

fail:
	PKCS11ERR(error, l, p11f, ret);
	return (B_FALSE);
}

/*
 * Perform NAT detection and update IKEV2 SA accordingly.  Return B_FALSE on
 * error, B_TRUE if no error.
 */
static boolean_t
check_nats(pkt_t *pkt)
{
	ikev2_sa_t *sa = pkt->pkt_sa;
	struct {
		ikev2_notify_type_t	ntype;
		struct sockaddr_storage *addr;
		const char		*msg;
		uint32_t		flag;
	} params[] = {
		/*
		 * Since these are from the perspective of the remote system,
		 * we check the local address against the NAT destination IP
		 * and vice versa.
		 */
		{
			IKEV2_N_NAT_DETECTION_DESTINATION_IP,
			&pkt->pkt_sa->laddr,
			"Local NAT detected",
			I2SA_NAT_LOCAL
		},
		{
			IKEV2_N_NAT_DETECTION_SOURCE_IP,
			&pkt->pkt_sa->raddr,
			"Remote NAT detected",
			I2SA_NAT_REMOTE
		}
	};

	for (size_t i = 0; i < 2; i++) {
		pkt_notify_t *n = pkt_get_notify(pkt, params[i].ntype, NULL);
		ikev2_notify_t ntfy = { 0 };
		uint8_t data[NAT_LEN] = { 0 };

		/* If notification isn't present, assume no NAT */
		if (n == NULL)
			continue;

		if (!compute_nat(pkt->pkt_raw, params[i].addr, data,
		    sizeof (data), sa->i2sa_log))
			return (B_FALSE);

		while (n != NULL) {
			ikev2_notify_t ntfy = { 0 };

			VERIFY3U(n->pn_len, >, sizeof (ntfy));
			(void) memcpy(&ntfy, n->pn_ptr, sizeof (ntfy));
			ntfy.n_type = ntohs(ntfy.n_type);
			VERIFY3U(ntfy.n_type, ==, params[i].ntype);

			if (ntfy.n_spisize != 0) {
				bunyan_error(sa->i2sa_log,
				    "Non-zero SPI size in NAT notification",
				    BUNYAN_T_STRING, "notification",
				    ikev2_notify_str(params[i].ntype),
				    BUNYAN_T_END);
				return (B_FALSE);
			}

			if (n->pn_len != sizeof (ntfy) + NAT_LEN) {
				bunyan_error(sa->i2sa_log,
				    "NAT notification size mismatch",
				    BUNYAN_T_STRING, "notification",
				    ikev2_notify_str(params[i].ntype),
				    BUNYAN_T_UINT32, "notifylen",
				    (uint32_t)n->pn_len,
				    BUNYAN_T_UINT32, "expected",
				    (uint32_t)(sizeof (ntfy) + NAT_LEN),
				    BUNYAN_T_END);
				return (B_FALSE);
			}

			if (memcmp(data, n->pn_ptr + sizeof (ntfy),
			    NAT_LEN) == 0) {
				sa->flags |= params[i].flag;
				bunyan_debug(sa->i2sa_log, params[i].msg,
				    BUNYAN_T_END);
				break;
			}

			n = pkt_get_notify(pkt, params[i].ntype, n);
		}
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
	ikev2_sa_t *sa = pkt->pkt_sa;
	struct {
		ikev2_notify_type_t	ntype;
		struct sockaddr_storage *addr;
	} params[] = {
		/*
		 * Since these are from our perspective, the local address
		 * corresponds to the source address and remote to the
		 * destination address.
		 */
		{
			IKEV2_N_NAT_DETECTION_SOURCE_IP,
			&pkt->pkt_sa->laddr,
		},
		{
			IKEV2_N_NAT_DETECTION_DESTINATION_IP,
			&pkt->pkt_sa->raddr,
		}
	};

	/*
	 * These normally don't get converted to network byte order until
	 * the packet has finished construction, so we need to do local
	 * conversion for the NAT payload creation
	 */
	uint64_t spi[2] = {
		htonll(pkt->pkt_header.initiator_spi),
		htonll(pkt->pkt_header.responder_spi)
	};

	for (int i = 0; i < 2; i++) {
		uint8_t data[NAT_LEN] = { 0 };

		if (!compute_nat(spi, params[i].addr, data, sizeof (data),
		    sa->i2sa_log))
			return (B_FALSE);

		if (!ikev2_add_notify(pkt, IKEV2_PROTO_IKE, 0, params[i].ntype,
		    data, sizeof (data)))
			return (B_FALSE);
	}

	return (B_TRUE);

fail:
	return (B_FALSE);
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
	return (ikev2_add_vendor(pkt, (uint8_t *)VENDOR_STR_ILLUMOS_1,
	    sizeof (VENDOR_STR_ILLUMOS_1)));
}

static boolean_t
add_cookie(pkt_t *restrict pkt, void *restrict cookie, size_t len)
{
	pkt_notify_t *n = pkt_get_notify(pkt, IKEV2_N_COOKIE, NULL);
	uint8_t *start = pkt_start(pkt) + sizeof (ike_header_t) +
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
