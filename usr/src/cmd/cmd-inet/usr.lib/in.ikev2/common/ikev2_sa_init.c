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

#include <bunyan.h>
#include <err.h>
#include <errno.h>
#include <string.h>
#include <strings.h>
#include <sys/debug.h>
#include <time.h>
#include <umem.h>
#include "config.h"
#include "defs.h"
#include "dh.h"
#include "ikev2_common.h"
#include "ikev2_enum.h"
#include "ikev2_pkt.h"
#include "ikev2_proto.h"
#include "ikev2_sa.h"
#include "pfkey.h"
#include "pkcs11.h"
#include "pkt.h"
#include "prf.h"
#include "worker.h"

static void ikev2_sa_init_init_resp(ikev2_sa_t *restrict, pkt_t *restrict,
    void *restrict);
static boolean_t redo_sa_init(pkt_t *restrict, ikev2_sa_args_t *restrict);

static config_rule_t *find_rule(sockaddr_u_t, sockaddr_u_t);
static boolean_t add_nat(pkt_t *);
static boolean_t check_nats(pkt_t *);
static void check_vendor(pkt_t *);
static boolean_t add_vendor(pkt_t *);
static boolean_t add_cookie(pkt_t *restrict, void *restrict, size_t len);
static boolean_t ikev2_sa_keygen(ikev2_sa_match_t *restrict, pkt_t *restrict);
static boolean_t ikev2_save_init_pkt(ikev2_sa_args_t *restrict,
    pkt_t *restrict);

/* New IKE_SA_INIT exchange, we are initiator */
void
ikev2_sa_init_init(ikev2_sa_t *restrict i2sa, parsedmsg_t *restrict pmsg)
{
	pkt_t *pkt = NULL;
	ikev2_sa_args_t *sa_args = i2sa->sa_init_args;
	uint8_t *nonce = NULL;
	size_t noncelen = IKEV2_NONCE_DEFAULT;
	sockaddr_u_t laddr = { .sau_ss = &i2sa->laddr };
	sockaddr_u_t raddr = { .sau_ss = &i2sa->raddr };

	VERIFY(MUTEX_HELD(&i2sa->i2sa_lock));
	VERIFY(!(i2sa->flags & I2SA_AUTHENTICATED));
	VERIFY(i2sa->flags & I2SA_INITIATOR);

	pkt = ikev2_pkt_new_exchange(i2sa, IKEV2_EXCH_IKE_SA_INIT);

	if (sa_args->i2a_pmsg == NULL) {
		sa_args->i2a_pmsg = pmsg;
		sa_args->i2a_sadb_msg = pmsg->pmsg_samsg;

		(void) bunyan_info(log,
		    "Starting new IKE_SA_INIT exchange as initiator",
		    BUNYAN_T_END);
	}

	if (i2sa->i2sa_rule == NULL) {
		i2sa->i2sa_rule = find_rule(laddr, raddr);
		if (i2sa->i2sa_rule == NULL)
			goto fail;
	}

	if (RULE_IS_DEFAULT(i2sa->i2sa_rule)) {
		(void) bunyan_debug(log, "Using default rule",
		    BUNYAN_T_END);
	} else {
		(void) bunyan_debug(log, "Found rule",
		    BUNYAN_T_POINTER, "rule", i2sa->i2sa_rule,
		    BUNYAN_T_STRING, "label", i2sa->i2sa_rule->rule_label,
		    BUNYAN_T_END);
	}

	if (!add_cookie(pkt, sa_args->i2a_cookie, sa_args->i2a_cookielen))
		goto fail;

	if (!ikev2_sa_from_rule(pkt, i2sa->i2sa_rule, 0))
		goto fail;

	/*
	 * Try the first DH group in the first rule if we already don't have
	 * one set from a previous attempt.
	 */
	if (sa_args->i2a_dh == IKEV2_DH_NONE)
		sa_args->i2a_dh = i2sa->i2sa_rule->rule_xf[0]->xf_dh;

	if (!ikev2_add_dh(sa_args, pkt))
		goto fail;

	/*
	 * If we've retried the IKE_SA_INIT exchange due to a COOKIE or
	 * INVALID_KE_PAYLOAD, we reuse the nonce we saved from the
	 * initial attempt.
	 */
	if (sa_args->i2a_nonce_i_len > 0) {
		nonce = sa_args->i2a_nonce_i;
		noncelen = sa_args->i2a_nonce_i_len;
	}
	if (!ikev2_add_nonce(pkt, nonce, noncelen))
		goto fail;
	ikev2_save_nonce(sa_args, pkt);

	if (!add_nat(pkt))
		goto fail;

	if (!add_vendor(pkt))
		goto fail;

	/* XXX: Add CERTREQ once supported */

	if (!ikev2_save_init_pkt(sa_args, pkt))
		goto fail;

	if (!ikev2_send_req(pkt, ikev2_sa_init_init_resp, sa_args)) {
		pkt = NULL;
		goto fail;
	}

	return;

fail:
	(void) bunyan_error(log, "Could not send IKE_SA_INIT packet",
	    BUNYAN_T_END);

	parsedmsg_free(pmsg);
	i2sa->flags |= I2SA_CONDEMNED;
	ikev2_pkt_free(pkt);
}

/* We are responder */
void
ikev2_sa_init_resp(pkt_t *pkt)
{
	ikev2_sa_t *sa = pkt->pkt_sa;
	ikev2_sa_args_t *sa_args = sa->sa_init_args;
	pkt_t *resp = NULL;
	sockaddr_u_t laddr = { .sau_ss = &sa->laddr };
	sockaddr_u_t raddr = { .sau_ss = &sa->raddr };
	pkt_payload_t *ke_i = pkt_get_payload(pkt, IKEV2_PAYLOAD_KE, NULL);
	ikev2_auth_type_t authmethod;
	ikev2_sa_match_t sa_result = { 0 };

	/* Verify inbound sanity checks */
	VERIFY(!(sa->flags & I2SA_INITIATOR));
	VERIFY3P(ke_i, !=, NULL);

	(void) bunyan_info(log,
	    "Starting new IKE_SA_INIT exchange as responder",
	    BUNYAN_T_END);

	resp = ikev2_pkt_new_response(pkt);
	if (resp == NULL)
		goto fail;

	sa->i2sa_rule = find_rule(laddr, raddr);
	if (sa->i2sa_rule == NULL) {
		/* This is the 2nd payload, it should fit */
		VERIFY(ikev2_add_notify(resp, IKEV2_N_NO_PROPOSAL_CHOSEN));
		(void) ikev2_send_resp(resp);
		return;
	}

	if (RULE_IS_DEFAULT(sa->i2sa_rule)) {
		(void) bunyan_debug(log, "Using default rule",
		    BUNYAN_T_END);
	} else {
		(void) bunyan_debug(log, "Found rule",
		    BUNYAN_T_POINTER, "rule", sa->i2sa_rule,
		    BUNYAN_T_STRING, "label", sa->i2sa_rule->rule_label,
		    BUNYAN_T_END);
	}

	if (!ikev2_sa_match_rule(sa->i2sa_rule, pkt, &sa_result, B_FALSE)) {
		VERIFY(ikev2_add_notify(resp, IKEV2_N_NO_PROPOSAL_CHOSEN));
		(void) ikev2_send_resp(resp);
		return;
	}

	sa->authmethod = sa_result.ism_authmethod;

	/*
	 * A bit annoying, but it's possible the negotiated DH group is
	 * different than the public key value that was sent in the IKE_SA_INIT
	 * exchange.  In that case, we respond with an INVALID_KE_PAYLOAD
	 * notification and include the result we want.  In this instance, we
	 * expect that the initiator will respond with a new KE payload
	 * containing the desired DH group (and otherwise identical).
	 * Therefore, keep the larval IKE SA around until we either proceed to
	 * an AUTH exchange, or we time out.
	 */
	sa_args->i2a_dh = sa_result.ism_dh;
	if (ikev2_get_dhgrp(pkt) != sa_args->i2a_dh) {
		if (ikev2_invalid_ke(resp, sa_args->i2a_dh))
			goto send;
		else
			goto fail;
	}

	if (!check_nats(pkt))
		goto fail;

	check_vendor(pkt);

	/* Save the initiator's nonce */
	ikev2_save_nonce(sa_args, pkt);

	/*
	 * The packet response functions take their SPI values from the
	 * initating packet, so for this one instance we must set it
	 * manually since the initiator doesn't yet know our local SPI.
	 *
	 * This is done _after_ we've verified our response isn't an error
	 * (NO_PROPOSALS_CHOSEN) or a request for a new KE group.  Cookies
	 * are checked/requested prior to ikev2_sa_init_resp() being called.
	 */
	pkt_header(resp)->responder_spi = I2SA_LOCAL_SPI(sa);

	if (!ikev2_sa_add_result(resp, &sa_result, 0))
		goto fail;

	/*
	 * While premissible, we do not currently reuse DH exponentials.  Since
	 * generating them is a potentially an expensive operation, we wait
	 * until necessary to create them.
	 */
	if (!ikev2_add_dh(sa_args, resp))
		goto fail;

	if (!ikev2_ke(sa_args, pkt))
		goto fail;

	if (!ikev2_add_nonce(resp, NULL, IKEV2_NONCE_DEFAULT))
		goto fail;

	/* Save our nonce */
	ikev2_save_nonce(sa_args, resp);

	if (!add_nat(resp))
		goto fail;

	/* XXX: HTTP_CERT_LOOKUP_SUPPORTED if we do support it */
	/* XXX: CERTREQ? */

	if (!add_vendor(resp))
		goto fail;

	if (!ikev2_sa_keygen(&sa_result, resp))
		goto fail;

	if (!ikev2_save_init_pkt(sa_args, pkt) ||
	    !ikev2_save_init_pkt(sa_args, resp))
		goto fail;

send:
	if (!ikev2_send_resp(resp)) {
		resp = NULL;
		goto fail;
	}
	return;

fail:
	(void) bunyan_error(log,
	    "Could not send response in IKE_SA_INIT exchange",
	    BUNYAN_T_END);

	/* condemning/deleting the IKEv2 SA will destroy the DH objects */
	sa->flags |= I2SA_CONDEMNED;
	ikev2_pkt_free(resp);
}

/*
 * We initiated the IKE_SA_INIT exchange, this is the remote response
 */
static void
ikev2_sa_init_init_resp(ikev2_sa_t *restrict sa, pkt_t *restrict pkt,
    void *restrict arg)
{
	ikev2_sa_args_t *sa_args = arg;
	parsedmsg_t *pmsg = sa_args->i2a_pmsg;
	ikev2_auth_type_t authmethod;
	ikev2_sa_match_t sa_result = { 0 };

	VERIFY(!MUTEX_HELD(&sa->i2sa_queue_lock));
	VERIFY(MUTEX_HELD(&sa->i2sa_lock));

	if (pkt == NULL) {
		(void) bunyan_info(log, "Timeout during IKE_SA_INIT exchange",
		    BUNYAN_T_END);

		/*
		 * Timeout on IKE_SA_INIT packet send.  Timeout handler will
		 * condemn the larval IKE SA, so only need to let the kernel
		 * know we failed if it prompted the IKE_SA_INIT exchange.
		 */
		if (PMSG_FROM_KERNEL(sa_args->i2a_pmsg))
			pfkey_send_error(sa_args->i2a_sadb_msg, ETIMEDOUT);
		return;
	}

	(void) bunyan_debug(log, "Processing IKE_SA_INIT response",
	     BUNYAN_T_END);

	/*
	 * Since this is an unprotected/unauthenticated reply, we only note
	 * if we've received a NO_PROPOSAL_CHOSEN error.  This could be a
	 * spoofed reply.  We let the retransmissions continue until we
	 * either receive a non-error reply, we exhaust our transmission
	 * attempts, or hit the P1 timeout based on the recommendation
	 * in RFC7296 2.21.1.
	 *
	 * Note: this is different than when we receive a NO_PROPOSAL_CHOSEN
	 * notification within a CREATE_CHILD_SA exchange -- at that point,
	 * our peer has been authenticated and the communication is encrypted
	 * and signed.
	 */
	if (pkt_get_notify(pkt, IKEV2_N_NO_PROPOSAL_CHOSEN, NULL) != NULL) {
		(void) bunyan_warn(log, "Received NO_PROPOSAL_CHOSEN from peer",
		    BUNYAN_T_END);
		return;
	}

	/* Did we get a request for cookies or a new DH group? */
	if (redo_sa_init(pkt, sa_args))
		return;

	/*
	 * Verify the algorithms selected by the responder match our policy.
	 * While the responder is supposed to reply with a set of algorithms
	 * chosen from what we propose (or send NO_PROPOSAL_CHOSEN), there is
	 * nothing in the protocol that can guarantee it.  Obviously we do not
	 * want to let a peer to trick us into using a set of algorithms that
	 * are not in our policy.  RFC7296 doesn't provide any specific
	 * guidance for this instance, however in keeping with the
	 * recommendations in section 2.21.1, we just ignore this response
	 * and hope we either receive a correct response, we exhaust
	 * transmission attempts, or we hit the P1 timeout.
	 */
	if (!ikev2_sa_check_prop(sa->i2sa_rule, pkt, &sa_result, B_FALSE)) {
		(void) bunyan_warn(log,
		    "Received response from peer that does not match our "
		    "policy", BUNYAN_T_END);
		return;
	}

	if (!check_nats(pkt))
		goto fail;

	check_vendor(pkt);

	if (!ikev2_ke(sa_args, pkt))
		goto fail;

	/* Save the remote nonce */
	ikev2_save_nonce(sa_args, pkt);

	/* And the responder IKE_SA_INIT packet */
	ikev2_save_init_pkt(sa_args, pkt);

	/* The generated keys use the initiator/responder SPI values from
	 * the ikev2_sa_t for the exchange, so we need to set the responder's
	 * SPI before we try to create our keys.
	 */
	ikev2_sa_set_remote_spi(sa, INBOUND_REMOTE_SPI(pkt_header(pkt)));
	sa->authmethod = sa_result.ism_authmethod;

	if (!ikev2_sa_keygen(&sa_result, pkt))
		goto fail;

	/*
	 * Per the comment in ikev2_handle_response(), unlike the other
	 * exchanges, we must dispose of our request packet and cancel its
	 * retransmit timer (since certain responses are ignored).
	 */
	ikev2_sa_clear_req(sa, &sa->last_req);
	ikev2_ike_auth_init(sa);
	return;

fail:
	sa->flags |= I2SA_CONDEMNED;
	return;
}

static boolean_t
redo_check_cookie(pkt_t *restrict pkt, ikev2_sa_args_t *restrict sa_args,
    boolean_t *restrict discard)
{
	pkt_notify_t *cookie = pkt_get_notify(pkt, IKEV2_N_COOKIE, NULL);

	if (cookie == NULL)
		return (B_FALSE);

	if (cookie->pn_len > IKEV2_COOKIE_MAX) {
		(void) bunyan_info(log,
		    "Received IKEV2 COOKIE notification with oversized "
		    "cookie value; ignoring",
		    BUNYAN_T_UINT32, "cookielen", (uint32_t)cookie->pn_len,
		    BUNYAN_T_END);
		*discard = B_TRUE;
		return (B_FALSE);
	}

	sa_args->i2a_cookielen = cookie->pn_len;
	bcopy(cookie->pn_ptr, sa_args->i2a_cookie, cookie->pn_len);

	return (B_TRUE);
}

static boolean_t
redo_check_ke(pkt_t *restrict pkt, ikev2_sa_args_t *restrict sa_args,
    boolean_t *restrict discard)
{
	pkt_notify_t *invalid_ke = NULL;
	config_rule_t *rule = NULL;
	uint16_t val = 0;
	boolean_t match = B_FALSE;

	invalid_ke = pkt_get_notify(pkt, IKEV2_N_INVALID_KE_PAYLOAD, NULL);
	if (invalid_ke == NULL)
		return (B_FALSE);

	if (invalid_ke->pn_len != sizeof (uint16_t)) {
		uint32_t len = invalid_ke->pn_len;

		/* The notification does not have the correct format */
		(void) bunyan_warn(log,
		    "INVALID_KE_PAYLOAD notification does not include a "
		    "16-bit DH group payload",
		    BUNYAN_T_UINT32, "ntfylen", len, BUNYAN_T_END);

		*discard = B_TRUE;
		return (B_FALSE);
	}

	rule = pkt->pkt_sa->i2sa_rule;
	val = BE_IN16(invalid_ke->pn_ptr);

	for (size_t i = 0; rule->rule_xf[i] != NULL; i++) {
		config_xf_t *xf = rule->rule_xf[i];

		if (val == xf->xf_dh) {
			match = B_TRUE;
			break;
		}
	}

	if (!match) {
		(void) bunyan_info(log,
		    "Received INVALID_KE_PAYLOAD notification with "
		    "unacceptable group; ignoring",
		    BUNYAN_T_UINT32, "groupval", (uint32_t)val,
		    BUNYAN_T_STRING, "group", ikev2_dh_str(val),
		    BUNYAN_T_END);
		*discard = B_TRUE;
		return (B_FALSE);
	}

	pkcs11_destroy_obj("dh_pubkey", &sa_args->i2a_pubkey);
	pkcs11_destroy_obj("dh_privkey", &sa_args->i2a_privkey);
	sa_args->i2a_dh = val;

	return (B_TRUE);
}

/*
 * If we get a cookie request or a new DH group in response to our
 * initiated IKE_SA_INIT exchange, restart with the new parameters.  Returns
 * B_TRUE if it has consumed pkt and further processing by caller of packet
 * should stop (i.e. we are restarting the IKE_SA_INIT exchange, or the
 * payload was bad), B_FALSE if the caller should continue processing.
 *
 * Since this packet is sent to us unprotected, it's treated mostly as advisory.
 * If something's wrong with the packet, or if it is trying to get us to use
 * a DH group our policy doesn't allow, we merely ignore the packet.  The
 * worst case is that the larval IKE SA will timeout and be deleted.
 *
 */
static boolean_t
redo_sa_init(pkt_t *restrict pkt, ikev2_sa_args_t *restrict sa_args)
{
	ikev2_sa_t *sa = pkt->pkt_sa;
	boolean_t discard = B_FALSE;
	boolean_t redo = B_FALSE;

	redo |= redo_check_cookie(pkt, sa_args, &discard);
	if (discard) {
		ikev2_pkt_free(pkt);
		return (B_TRUE);
	}

	redo |= redo_check_ke(pkt, sa_args, &discard);
	if (discard) {
		ikev2_pkt_free(pkt);
		return (B_TRUE);
	}

	if (!redo)
		return (B_FALSE);

	/*
	 * If we're restarting the IKE_SA_INIT exchange, we must always start
	 * with msgid 0.
	 */
	sa->outmsgid = 0;

	/* Discard old request since we're restarting with new parameters */
	ikev2_sa_clear_req(sa, &sa->last_req);

	(void) bunyan_debug(log,
	    "Response requested new parameters; "
	    "restarting IKE_SA_INIT exchange",
	    BUNYAN_T_END);

	ikev2_sa_init_init(sa, sa_args->i2a_pmsg);
	ikev2_pkt_free(pkt);
	return (B_TRUE);
}

static config_rule_t *
find_rule(sockaddr_u_t laddr, sockaddr_u_t raddr)
{
	config_rule_t *rule = config_get_rule(laddr, raddr);

	if (rule == NULL) {
		(void) bunyan_warn(log, "No rules found for address",
		    BUNYAN_T_END);
		return (NULL);
	}

	if (rule->rule_xf == NULL || rule->rule_xf[0] == NULL) {
		(void) bunyan_debug(log, "No transforms found in rue",
		    BUNYAN_T_END);
		CONFIG_REFRELE(rule->rule_config);
		return (NULL);
	}

	VERIFY3P(rule->rule_config, !=, NULL);
	return (rule);
}

/* Compute a NAT detection payload and place result into buf */
static boolean_t
compute_nat(uint64_t *restrict spi, struct sockaddr *restrict addr,
    uint8_t *restrict buf, size_t buflen)
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
	size_t addrlen = ss_addrlen(addr);
	uint16_t port = htons((uint16_t)ss_port(addr));

	VERIFY3U(buflen, >=, IKEV2_N_NAT_SIZE);
	VERIFY(addr->sa_family == AF_INET || addr->sa_family == AF_INET6);

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
	PKCS11ERR(error, p11f, ret);
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
		struct sockaddr		*addr;
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
			SSTOSA(&pkt->pkt_sa->laddr),
			"Local NAT detected",
			I2SA_NAT_LOCAL
		},
		{
			IKEV2_N_NAT_DETECTION_SOURCE_IP,
			SSTOSA(&pkt->pkt_sa->raddr),
			"Remote NAT detected",
			I2SA_NAT_REMOTE
		}
	};

	/*
	 * RFC7296 2.23 goes into more detail, but briefly, each side
	 * generates an SHA1 hash of the packet SPIs (in the order they
	 * appear in the header), the IP address of the source/destination
	 * (based on which NAT payload is being constructed) and port number.
	 * It is permissible that an implementation may include multiple
	 * NAT_DETECTION_SOURCE_IP payloads if the host has multiple addresses
	 * and is unsure which one was used to send the datagram.
	 *
	 * We perform the same hash (using the IP and port we see) and if
	 * there are no matches, then the side (local/remote) being checked
	 * is behind a NAT.  If either side is behind a NAT,  we switch to
	 * using the NATT port (4500) for all subsequent traffic.
	 *
	 * While the presense of a NAT on one side of the connection is all
	 * that is necessary to switch to NAT traversal mode, we still
	 * retain knowledge of which side is behind the NAT as we will
	 * (eventually) want to enable UDP keepalives when we are the ones
	 * behind a NAT.
	 */
	for (size_t i = 0; i < ARRAY_SIZE(params); i++) {
		pkt_notify_t *n = pkt_get_notify(pkt, params[i].ntype, NULL);
		uint8_t data[IKEV2_N_NAT_SIZE] = { 0 };
		boolean_t match = B_FALSE;

		/* If notification isn't present, assume no NAT */
		if (n == NULL)
			continue;

		if (!compute_nat(pkt->pkt_raw, params[i].addr, data,
		    sizeof (data)))
			return (B_FALSE);

		while (n != NULL) {
			/*
			 * Ignore the proto (satype) and SPI values.  RFC7296
			 * is somewhat unclear here -- RFC4718 suggests that
			 * most notifications do not use the proto or SPI
			 * fields of the notification (which then by RFC7296
			 * 3.10 means they MUST be ignored).  We have no
			 * use for them for NAT detection, so we will opt
			 * to ignore them.
			 */
			if (n->pn_len != IKEV2_N_NAT_SIZE) {
				(void) bunyan_error(log,
				    "NAT notification size mismatch",
				    BUNYAN_T_STRING, "notification",
				    ikev2_notify_str(params[i].ntype),
				    BUNYAN_T_UINT32, "notifylen",
				    (uint32_t)n->pn_len,
				    BUNYAN_T_UINT32, "expected",
				    (uint32_t)IKEV2_N_NAT_SIZE,
				    BUNYAN_T_END);
				return (B_FALSE);
			}

			if (memcmp(data, n->pn_ptr, IKEV2_N_NAT_SIZE) == 0) {
				match = B_TRUE;
				break;
			}

			n = pkt_get_notify(pkt, params[i].ntype, n);
		}

		if (!match) {
			sa->flags |= params[i].flag;
			(void) bunyan_debug(log, params[i].msg, BUNYAN_T_END);
		}
	}

	/* Switch to using the NAT port if either side is NATted */
	if (I2SA_IS_NAT(sa)) {
		sockaddr_u_t local_addr = { .sau_ss = &sa->laddr };
		sockaddr_u_t remote_addr = { .sau_ss = &sa->raddr };

		VERIFY3S(local_addr.sau_ss->ss_family, ==,
		    remote_addr.sau_ss->ss_family);

		/*
		 * While sendfromto() uses the source port of the bound socket
		 * when sending, we still update local and remote for
		 * clarity
		 */
		switch (local_addr.sau_ss->ss_family) {
		case AF_INET:
			local_addr.sau_sin->sin_port = htons(IPPORT_IKE_NATT);
			remote_addr.sau_sin->sin_port = htons(IPPORT_IKE_NATT);
			break;
		case AF_INET6:
			local_addr.sau_sin6->sin6_port = htons(IPPORT_IKE_NATT);
			remote_addr.sau_sin6->sin6_port =
			    htons(IPPORT_IKE_NATT);
			break;
		default:
			INVALID(ss_family);
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
		struct sockaddr		*addr;
	} params[] = {
		/*
		 * Since these are from our perspective, the local address
		 * corresponds to the source address and remote to the
		 * destination address.
		 */
		{
			IKEV2_N_NAT_DETECTION_SOURCE_IP,
			SSTOSA(&pkt->pkt_sa->laddr),
		},
		{
			IKEV2_N_NAT_DETECTION_DESTINATION_IP,
			SSTOSA(&pkt->pkt_sa->raddr),
		}
	};

	for (int i = 0; i < ARRAY_SIZE(params); i++) {
		uint8_t data[IKEV2_N_NAT_SIZE] = { 0 };

		/* The SPIs are always at the start of the packet */
		if (!compute_nat(pkt->pkt_raw, params[i].addr, data,
		    sizeof (data)))
			return (B_FALSE);

		if (!ikev2_add_notify_full(pkt, IKEV2_PROTO_NONE, 0,
		    params[i].ntype, data, sizeof (data)))
			return (B_FALSE);
	}
	return (B_TRUE);
}

static void
check_vendor(pkt_t *pkt)
{
	ikev2_sa_t *sa = pkt->pkt_sa;
	pkt_payload_t *pay = NULL;

	for (pay = pkt_get_payload(pkt, IKEV2_PAYLOAD_VENDOR, NULL);
	    pay != NULL;
	    pay = pkt_get_payload(pkt, IKEV2_PAYLOAD_VENDOR, pay)) {
		if (pay->pp_len != sizeof (VENDOR_STR_ILLUMOS_1))
			continue;

		if (memcmp(VENDOR_STR_ILLUMOS_1, pay->pp_ptr,
		    sizeof (VENDOR_STR_ILLUMOS_1)) == 0) {
			(void) bunyan_debug(log,
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
	if (cookie == NULL || len == 0)
		return (B_TRUE);

	/* Should be the first payload */
	VERIFY3U(pkt->pkt_payload_count, ==, 0);

	return (ikev2_add_notify_full(pkt, IKEV2_PROTO_NONE, 0, IKEV2_N_COOKIE,
	    cookie, len));
}

static size_t
skeyseed_noncelen(ikev2_prf_t prf, size_t len)
{
	switch (prf) {
	/*
	 * RFC7296 2.14 - For these PRFs, only the first 64 bits of Ni and Nr
	 * are used when calculating skeyseed, though all bits are used for
	 * the prf+ function
	 */
	case IKEV2_PRF_AES128_XCBC:
	case IKEV2_PRF_AES128_CMAC:
		if (len > 8)
			return (8);
		/*FALLTHRU*/
	default:
		return (len);
	}
}

/* Create a PKCS#11 object of Ni | Nr */
static boolean_t
create_nonceobj(ikev2_prf_t prf, ikev2_sa_args_t *restrict sa_args,
    CK_OBJECT_HANDLE_PTR restrict objp)
{
	CK_MECHANISM_TYPE p11_prf = ikev2_prf_to_p11(prf);
	size_t ni_len = skeyseed_noncelen(prf, sa_args->i2a_nonce_i_len);
	size_t nr_len = skeyseed_noncelen(prf, sa_args->i2a_nonce_r_len);
	size_t noncelen = MAX(ni_len + nr_len, ikev2_prf_outlen(prf));
	uint8_t nonce[noncelen];
	CK_RV rc;

	bzero(nonce, noncelen);
	bcopy(sa_args->i2a_nonce_i, nonce, ni_len);
	bcopy(sa_args->i2a_nonce_r, nonce + ni_len, nr_len);

	rc = SUNW_C_KeyToObject(p11h(), p11_prf, nonce, noncelen, objp);

	if (rc != CKR_OK) {
		PKCS11ERR(error, "SUNW_C_KeyToObject", rc,
		    BUNYAN_T_STRING, "objname", "Ni|Nr");
	} else if (show_keys) {
		size_t hexlen = noncelen * 2 + 1;
		char hex[hexlen];

		bzero(hex, hexlen);
		writehex(nonce, noncelen, "", hex, hexlen);

		/*
		 * This really isn't a key and is already sent in plaintext,
		 * but can't hurt to be consistent.
		 */
		(void) bunyan_debug(log, "Ni|Nr",
		    BUNYAN_T_STRING, "key", hex,
		    BUNYAN_T_END);

		explicit_bzero(hex, hexlen);
	}

	explicit_bzero(nonce, noncelen);
	return ((rc == CKR_OK) ? B_TRUE : B_FALSE);
}

static boolean_t
create_skeyseed(ikev2_sa_t *restrict sa, CK_OBJECT_HANDLE nonce,
    CK_OBJECT_HANDLE_PTR restrict keyp)
{
	void *dh_key = NULL;
	size_t dh_len = 0;
	size_t skeyseed_len = ikev2_prf_outlen(sa->prf);
	CK_SESSION_HANDLE h = p11h();
	CK_OBJECT_HANDLE dhkey_h = sa->sa_init_args->i2a_dhkey;
	CK_RV rc = CKR_OK;
	boolean_t ok = B_TRUE;
	/* The largest prf output (SHA512) is 64 bytes */
	uint8_t skeyseed[skeyseed_len];

	/*
	 * Unfortunately, to generate SKEYSEED, we need to copy down the g^ir
	 * value to perform the prf function since there is no C_SignKey
	 * function in PKCS#11. As such we try to keep the value in memory for
	 * as short a time as possible.
	 */
	rc = pkcs11_ObjectToKey(h, dhkey_h, &dh_key, &dh_len, B_FALSE);
	if (rc != CKR_OK) {
		PKCS11ERR(error, "pkcs11_ObjectToKey", rc,
		    BUNYAN_T_STRING, "objname", "dh_key");
		goto fail;
	}

	/*
	 * RFC7296 2.14:
	 *	SKEYSEED = prf(Ni | Nr, g^ir)
	 */
	ok = prf(sa->prf, nonce, skeyseed, skeyseed_len, dh_key, dh_len, NULL);
	explicit_bzero(dh_key, dh_len);
	free(dh_key);
	dh_key = NULL;
	dh_len = 0;

	if (!ok)
		goto fail;

	rc = SUNW_C_KeyToObject(h, ikev2_prf_to_p11(sa->prf), skeyseed,
	    skeyseed_len, keyp);

	if (rc != CKR_OK) {
		PKCS11ERR(error, "SUNW_C_KeyToObject", rc,
		    BUNYAN_T_STRING, "objname", "skeyseed");
		goto fail;
	} else {
		size_t hexlen = skeyseed_len * 2 + 1;
		char hex[hexlen];

		bzero(hex, hexlen);
		if (show_keys)
			writehex(skeyseed, skeyseed_len, "", hex, hexlen);

		(void) bunyan_debug(log, "Created SKEYSEED",
		    show_keys ? BUNYAN_T_STRING : BUNYAN_T_END, "key", hex,
		    BUNYAN_T_END);

		explicit_bzero(hex, hexlen);
	}

	explicit_bzero(skeyseed, skeyseed_len);
	return (B_TRUE);

fail:
	if (dh_key != NULL) {
		explicit_bzero(dh_key, dh_len);
		free(dh_key);
	}
	explicit_bzero(skeyseed, skeyseed_len);
	return (B_FALSE);
}

static boolean_t
ikev2_sa_keygen(ikev2_sa_match_t *restrict result, pkt_t *restrict resp)
{
	ikev2_sa_t *sa = resp->pkt_sa;
	ikev2_sa_args_t *sa_args = sa->sa_init_args;
	CK_OBJECT_HANDLE nonce = CK_INVALID_HANDLE;
	CK_OBJECT_HANDLE skeyseed = CK_INVALID_HANDLE;
	boolean_t ret = B_FALSE;

	ikev2_save_i2sa_results(sa, result);

	if (!create_nonceobj(result->ism_prf, sa_args, &nonce))
		goto done;
	if (!create_skeyseed(sa, nonce, &skeyseed))
		goto done;
	pkcs11_destroy_obj("Ni|Nr", &nonce);

	ret = ikev2_create_i2sa_keys(sa, skeyseed,
	    sa_args->i2a_nonce_i, sa_args->i2a_nonce_i_len,
	    sa_args->i2a_nonce_r, sa_args->i2a_nonce_r_len);

done:
	/*
	 * pkcs11_destroy_obj sets the object handle to CK_INVALID_HANDLE
	 * after destruction, so subsequent calls w/ the same var are a
	 * no-op
	 */
	pkcs11_destroy_obj("Ni|Nr", &nonce);
	pkcs11_destroy_obj("skeyseed", &skeyseed);
	return (ret);
}

/*
 * Save the contents of the IKE_SA_INIT packets so that we can sign/verify
 * in the IKE_AUTH exchange
 */
static boolean_t
ikev2_save_init_pkt(ikev2_sa_args_t *restrict i2a, pkt_t *restrict pkt)
{
	uint8_t **pktp = NULL;
	size_t *lenp = NULL;
	size_t len = pkt_len(pkt);

	if (!ikev2_pkt_done(pkt)) {
		(void) bunyan_error(log, "Packet not done", BUNYAN_T_END);
		return (B_FALSE);
	}

	if (I2P_INITIATOR(pkt)) {
		pktp = &i2a->i2a_init_i;
		lenp = &i2a->i2a_init_i_len;
	} else {
		pktp = &i2a->i2a_init_r;
		lenp = &i2a->i2a_init_r_len;
	}

	if (*pktp != NULL) {
		umem_free(*pktp, *lenp);
		*pktp = NULL;
		*lenp = 0;
	}

	if ((*pktp = umem_alloc(len, UMEM_DEFAULT)) == NULL) {
		STDERR(error, "No memory to perform IKE_SA_INIT exchange");
		return (B_FALSE);
	}
	*lenp = len;
	bcopy(pkt_start(pkt), *pktp, len);

	return (B_TRUE);
}
