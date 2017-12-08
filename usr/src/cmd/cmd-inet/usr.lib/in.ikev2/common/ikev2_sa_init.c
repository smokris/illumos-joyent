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
#include <string.h>
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

struct sa_init_args {
	parsedmsg_t	*sia_pmsg;
	ikev2_dh_t	sia_dh;
	uint8_t		sia_cookie[IKEV2_COOKIE_MAX];
	size_t		sia_cookielen;
	uint8_t		sia_nonce[IKEV2_NONCE_MAX];
	size_t		sia_noncelen;
};

static void ikev2_sa_init_init_resp(ikev2_sa_t *restrict, pkt_t *restrict,
    void *restrict);
static boolean_t redo_init(pkt_t *restrict, struct sa_init_args *restrict);

static boolean_t find_config(pkt_t *, sockaddr_u_t, sockaddr_u_t);
static boolean_t add_nat(pkt_t *);
static boolean_t check_nats(pkt_t *);
static void check_vendor(pkt_t *);
static boolean_t add_vendor(pkt_t *);
static boolean_t add_cookie(pkt_t *restrict, void *restrict, size_t len);
static boolean_t ikev2_sa_keygen(ikev2_sa_result_t *restrict, pkt_t *restrict,
    pkt_t *restrict);

/* New IKE_SA_INIT exchange, we are initiator */
void
ikev2_sa_init_init(ikev2_sa_t *restrict i2sa, parsedmsg_t *restrict pmsg,
    void *restrict arg)
{
	struct sa_init_args *sa_args = arg;
	pkt_t *pkt = NULL;
	uint8_t *nonce = NULL;
	size_t noncelen = 0;
	sockaddr_u_t laddr = { .sau_ss = &i2sa->laddr };
	sockaddr_u_t raddr = { .sau_ss = &i2sa->raddr };

	VERIFY(MUTEX_HELD(&i2sa->i2sa_lock));
	VERIFY(!(i2sa->flags & I2SA_AUTHENTICATED));
	VERIFY(i2sa->flags & I2SA_INITIATOR);
	VERIFY((pmsg != NULL && arg == NULL) || (pmsg == NULL && arg != NULL));

	pkt = ikev2_pkt_new_exchange(i2sa, IKEV2_EXCH_IKE_SA_INIT);

	if (sa_args == NULL) {
		sa_args = umem_zalloc(sizeof (*sa_args), UMEM_DEFAULT);
		if (sa_args == NULL) {
			(void) bunyan_error(log,
			    "No memory to perform IKE_SA_INIT exchange",
			    BUNYAN_T_END);
			ikev2_sa_condemn(i2sa);

			/*
			 * Inform kernel of failure if it originated the
			 * request that led to IKEv2 SA creation.
			 */
			if (pmsg->pmsg_samsg->sadb_msg_pid == 0)
				pfkey_send_error(pmsg->pmsg_samsg, ENOMEM);

			parsedmsg_free(pmsg);
			return;
		}

		sa_args->sia_pmsg = pmsg;

		(void) bunyan_info(log,
		    "Starting new IKE_SA_INIT exchange as initiator",
		    BUNYAN_T_END);
	}

	if (!find_config(pkt, laddr, raddr))
		goto fail;

	if (!add_cookie(pkt, sa_args->sia_cookie, sa_args->sia_cookielen))
		goto fail;

	if (!ikev2_sa_from_rule(pkt, i2sa->i2sa_rule, 0))
		goto fail;

	/* Start with the first DH group in the first rule */
	if (sa_args->sia_dh == IKEV2_DH_NONE)
		sa_args->sia_dh = i2sa->i2sa_rule->rule_xf[0]->xf_dh;

	if (i2sa->dh_pubkey == CK_INVALID_HANDLE &&
	    !dh_genpair(sa_args->sia_dh, &i2sa->dh_pubkey, &i2sa->dh_privkey))
		goto fail;

	if (!ikev2_add_ke(pkt, sa_args->sia_dh, i2sa->dh_pubkey))
		goto fail;

	if (sa_args->sia_noncelen == 0) {
		nonce = NULL;
		noncelen = IKEV2_NONCE_DEFAULT;
	} else {
		nonce = sa_args->sia_nonce;
		noncelen = sa_args->sia_noncelen;
	}
	if (!ikev2_add_nonce(pkt, nonce, noncelen))
		goto fail;

	if (!add_nat(pkt))
		goto fail;

	if (!add_vendor(pkt))
		goto fail;

	/* XXX: CERTREQ */

	i2sa->init_i = pkt;

	if (!ikev2_send_req(pkt, ikev2_sa_init_init_resp, sa_args))
		goto fail;

	I2SA_REFRELE(i2sa);
	return;

fail:
	parsedmsg_free(pmsg);
	umem_free(sa_args, sizeof (*sa_args));
	i2sa->init_i = NULL;
	ikev2_sa_condemn(i2sa);
	ikev2_pkt_free(pkt);
	I2SA_REFRELE(i2sa);
}

/* We are responder */
void
ikev2_sa_init_resp(pkt_t *pkt)
{
	ikev2_sa_t *sa = pkt->pkt_sa;
	pkt_t *resp = NULL;
	sockaddr_u_t laddr = { .sau_ss = &sa->laddr };
	sockaddr_u_t raddr = { .sau_ss = &sa->raddr };
	pkt_payload_t *ke_i = pkt_get_payload(pkt, IKEV2_PAYLOAD_KE, NULL);
	ikev2_sa_result_t sa_result = { 0 };
	ikev2_auth_type_t authmethod;

	/* Verify inbound sanity checks */
	VERIFY(!(sa->flags & I2SA_INITIATOR));
	VERIFY3P(ke_i, !=, NULL);

	(void) bunyan_info(log,
	    "Starting new IKE_SA_INIT exchange as responder",
	    BUNYAN_T_END);

	if (!find_config(pkt, laddr, raddr))
		goto fail;
	if (!check_nats(pkt))
		goto fail;
	check_vendor(pkt);

	if (!ikev2_sa_match_rule(sa->i2sa_rule, pkt, &sa_result, &authmethod)) {
		/*
		 * It seems very unlikely that an initiator will be able to
		 * react and resend a new payload in this situation (as opposed
		 * to a DH group mismatch or if we were to respond with a
		 * cookie).  Therefore, we can delete the larval IKE SA.
		 */
		(void) ikev2_no_proposal_chosen(pkt, IKEV2_PROTO_IKE);
		goto fail;
	}

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
	if (ikev2_get_dhgrp(pkt) != sa_result.sar_dh) {
		(void) ikev2_invalid_ke(pkt, IKEV2_PROTO_IKE, 0,
		    sa_result.sar_dh);
		ikev2_pkt_free(pkt);
		return;
	}

	sa->init_i = pkt;
	sa->authmethod = authmethod;

	resp = ikev2_pkt_new_response(pkt);
	if (resp == NULL)
		goto fail;

	/*
	 * The packet response functions take their SPI values from the
	 * initating packet, so for this one instance we must set it
	 * manually since the initiator doesn't yet know our local SPI.
	 */
	pkt_header(resp)->responder_spi = I2SA_LOCAL_SPI(sa);

	if (!ikev2_sa_add_result(resp, &sa_result, 0))
		goto fail;
	/*
	 * While premissible, we do not currently reuse DH exponentials.  Since
	 * generating them is a potentially an expensive operation, we wait
	 * until necessary to create them.
	 */
	if (!dh_genpair(sa_result.sar_dh, &sa->dh_pubkey, &sa->dh_privkey))
		goto fail;
	if (!dh_derivekey(sa->dh_privkey, ke_i->pp_ptr + sizeof (ikev2_ke_t),
	    ke_i->pp_len - sizeof (ikev2_ke_t), &sa->dh_key))
		goto fail;
	if (!ikev2_add_ke(resp, sa_result.sar_dh, sa->dh_pubkey))
		goto fail;

	/*
	 * RFC7296 2.10 nonce length should be at least half key size of PRF.
	 * ikev2_add_nonce will cap the nonce length to the range
	 * [IKEV2_NONCE_MIN, IKEV2_NONCE_MAX].
	 */
	if (!ikev2_add_nonce(resp, NULL,
	    ikev2_prf_keylen(sa_result.sar_prf) / 2))
		goto fail;
	if (!add_nat(resp))
		goto fail;

	/* XXX: CERTREQ? */
	/* XXX: other notifications */

	if (!add_vendor(resp))
		goto fail;

	if (!ikev2_sa_keygen(&sa_result, pkt, resp))
		goto fail;
	if (!ikev2_send_resp(resp))
		goto fail;

	/*
	 * We don't reuse DH keys, and the DH key is not needed once we've
	 * sent our response (a new one may optionally be created for a
	 * CREATE_CHILD_SA exchange).
	 */
	pkcs11_destroy_obj("dh_pubkey", &sa->dh_pubkey);
	pkcs11_destroy_obj("dh_privkey", &sa->dh_privkey);
	pkcs11_destroy_obj("gir", &sa->dh_key);
	sa->init_r = resp;
	return;

fail:
	(void) bunyan_error(log,
	    "Could not send response in IKE_SA_INIT exchange",
	    BUNYAN_T_END);

	sa->init_r = NULL;
	/* condemning/deleting the IKEv2 SA will destroy the DH objects */
	ikev2_sa_condemn(sa);
	ikev2_pkt_free(pkt);
	ikev2_pkt_free(resp);
	/* XXX: Anything else? */
}

/*
 * We initiated the IKE_SA_INIT exchange, this is the remote response
 */
static void
ikev2_sa_init_init_resp(ikev2_sa_t *restrict sa, pkt_t *restrict pkt,
    void *restrict arg)
{
	pkt_payload_t *ke_r = NULL;
	struct sa_init_args *sa_args = arg;
	parsedmsg_t *pmsg = sa_args->sia_pmsg;
	ikev2_sa_result_t sa_result = { 0 };
	ikev2_auth_type_t authmethod;

	VERIFY(!MUTEX_HELD(&sa->i2sa_queue_lock));
	VERIFY(MUTEX_HELD(&sa->i2sa_lock));

	if (pkt == NULL) {
		(void) bunyan_info(log, "Timeout during IKE_SA_INIT exchange",
		    BUNYAN_T_END);

		/*
		 * Timeout on IKE_SA_INIT packet send.  Timeout handler will
		 * condemn the larval IKE SA, so only need to clean up
		 * sa_args.
		 */
		parsedmsg_free(sa_args->sia_pmsg);
		umem_free(sa_args, sizeof (*sa_args));
		return;
	}

	ke_r = pkt_get_payload(pkt, IKEV2_PAYLOAD_KE, NULL);

	(void) bunyan_debug(log, "Processing IKE_SA_INIT response",
	     BUNYAN_T_END);

	if (pkt_get_notify(pkt, IKEV2_N_NO_PROPOSAL_CHOSEN, NULL) != NULL) {
		(void) bunyan_error(log,
		    "IKE_SA_INIT exchange failed, no proposal chosen",
		    BUNYAN_T_END);
		ikev2_sa_condemn(sa);
		ikev2_pkt_free(pkt);
		return;
	}

	/* Did we get a request for cookies or a new DH group? */
	if (redo_init(pkt, sa_args))
		return;
	if (!check_nats(pkt))
		goto fail;
	check_vendor(pkt);

	if (!ikev2_sa_match_rule(sa->i2sa_rule, pkt, &sa_result, &authmethod)) {
		/*
		 * XXX: Tried to send back something that wasn't in the propsals
		 * we sent.  What should we do?  Just destroy the IKE SA?
		 * Ignore?  For now ignore and hope a valid answer comes
		 * back before we timeout.
		 */
		ikev2_pkt_free(pkt);
		return;
	}

	if (!dh_derivekey(sa->dh_privkey, ke_r->pp_ptr + sizeof (ikev2_ke_t),
	    ke_r->pp_len - sizeof (ikev2_ke_t), &sa->dh_key))
		goto fail;
	if (!ikev2_sa_keygen(&sa_result, sa->init_i, pkt))
		goto fail;

	ikev2_sa_set_remote_spi(sa, INBOUND_REMOTE_SPI(pkt_header(pkt)));
	sa->authmethod = authmethod;
	sa->init_r = pkt;
	umem_free(sa_args, sizeof (*sa_args));
	ikev2_ike_auth_init(sa, pmsg);
	return;

fail:
	umem_free(sa_args, sizeof (*sa_args));
	ikev2_sa_condemn(sa);
	ikev2_pkt_free(pkt);
	/* XXX: Anything else? */
	return;
}

/*
 * If we get a cookie request or a new DH group in response to our
 * initiated IKE_SA_INIT exchange, restart with the new parameters.  Returns
 * B_TRUE if it has consumed pkt and further processing by caller of packet
 * should stop, B_FALSE if caller should continue processing pkt.
 *
 * Since this packet is sent to us unprotected, it's treated mostly as advisory.
 * If something's wrong with the packet, or if it is trying to get us to use
 * a DH group our policy doesn't allow, we merely ignore the packet.  The
 * worst case is that the larval IKE SA will timeout and be deleted.
 *
 * XXX: Better name?
 */
static boolean_t
redo_init(pkt_t *restrict pkt, struct sa_init_args *restrict sa_args)
{
	ikev2_sa_t *sa = pkt->pkt_sa;
	pkt_notify_t *cookie = pkt_get_notify(pkt, IKEV2_N_COOKIE, NULL);
	pkt_notify_t *invalid_ke = pkt_get_notify(pkt,
	    IKEV2_N_INVALID_KE_PAYLOAD, NULL);
	pkt_t *out = sa->init_i;
	pkt_payload_t *nonce = pkt_get_payload(out, IKEV2_PAYLOAD_NONCE, NULL);

	if (cookie == NULL && invalid_ke == NULL)
		return (B_FALSE);

	VERIFY3U(nonce->pp_len, <=, IKEV2_NONCE_MAX);
	(void) memcpy(sa_args->sia_nonce, nonce->pp_ptr, nonce->pp_len);

	if (cookie != NULL) {
		if (cookie->pn_len > IKEV2_COOKIE_MAX) {
			(void) bunyan_info(log,
			    "Received IKEV2 COOKIE notification with oversized "
			    "cookie value; ignoring",
			    BUNYAN_T_UINT32, "cookielen",
			    (uint32_t)cookie->pn_len,
			    BUNYAN_T_END);
			ikev2_pkt_free(pkt);
			return (B_TRUE);
		}
		sa_args->sia_cookielen = cookie->pn_len;
		(void) memcpy(sa_args->sia_cookie, cookie->pn_ptr,
		    cookie->pn_len);
	}

	if (invalid_ke != NULL) {
		if (invalid_ke->pn_len != sizeof (uint16_t)) {
			/*
			 * The notification does not have the correct format
			 */
			(void) bunyan_info(log,
			    "INVALID_KE_PAYLOAD notification does not "
			    "include a 16-bit DH group payload",
			    BUNYAN_T_UINT32, "ntfylen",
			    (uint32_t)invalid_ke->pn_len, BUNYAN_T_END);

			/* We will just ignore it for now */
			ikev2_pkt_free(pkt);
			return (B_TRUE);
		}

		config_rule_t *rule = sa->i2sa_rule;
		uint16_t val = BE_IN16(invalid_ke->pn_ptr);
		boolean_t match = B_FALSE;

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
			ikev2_pkt_free(pkt);
			return (B_TRUE);
		}

		pkcs11_destroy_obj("dh_pubkey", &sa->dh_pubkey);
		pkcs11_destroy_obj("dh_privkey", &sa->dh_privkey);
		sa_args->sia_dh = val;
	}

	/*
	 * If we're restarting the IKE_SA_INIT exchange, we must always start
	 * with msgid 0, and our last response should be the initiator init
	 * packet.  Reset those and restart.
	 */
	VERIFY3P(sa->last_sent, ==, sa->init_i);
	sa->init_i = sa->last_sent = NULL;
	sa->outmsgid = 0;

	/*
	 * Stop trying to resend old IKE_SA_INIT packet, but keep the P1 timer
	 * going.
	 */
	(void) ikev2_sa_disarm_timer(sa, I2SA_EVT_PKT_XMIT);

	(void) bunyan_debug(log,
	    "Response requested new parameters; restarting exchange",
	    BUNYAN_T_END);

	ikev2_sa_init_init(sa, NULL, sa_args);
	ikev2_pkt_free(pkt);
	ikev2_pkt_free(out);
	return (B_TRUE);
}

static boolean_t
find_config(pkt_t *pkt, sockaddr_u_t laddr, sockaddr_u_t raddr)
{
	ikev2_sa_t *sa = pkt->pkt_sa;

	if (sa->i2sa_rule != NULL)
		goto done;

	sa->i2sa_rule = config_get_rule(laddr, raddr);

done:
	if (RULE_IS_DEFAULT(sa->i2sa_rule)) {
		(void) bunyan_debug(log, "Using default rule",
		    BUNYAN_T_END);
	} else {
		(void) bunyan_debug(log, "Found rule",
		    BUNYAN_T_STRING, "label", sa->i2sa_rule->rule_label,
		    BUNYAN_T_END);
	}

	if (sa->i2sa_rule->rule_xf == NULL ||
	    sa->i2sa_rule->rule_xf[0] == NULL) {
		(void) bunyan_debug(log, "No transforms found",
		    BUNYAN_T_END);
		(void) ikev2_no_proposal_chosen(pkt, IKEV2_PROTO_IKE);
		return (B_FALSE);
	}

	return (B_TRUE);
}

/* Compute a NAT detection payload and place result into buf */
static boolean_t
compute_nat(uint64_t *restrict spi, struct sockaddr_storage *restrict addr,
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
	size_t addrlen = (addr->ss_family == AF_INET) ?
	    sizeof (in_addr_t) : sizeof (in6_addr_t);
	uint16_t port = (addr->ss_family == AF_INET) ?
	    ((struct sockaddr_in *)addr)->sin_port :
	    ((struct sockaddr_in6 *)addr)->sin6_port;

	VERIFY3U(buflen, >=, IKEV2_N_NAT_SIZE);
	VERIFY(addr->ss_family == AF_INET || addr->ss_family == AF_INET6);

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
	for (size_t i = 0; i < 2; i++) {
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
			 * XXX: Should these validation failures just ignore
			 * the individual payload, or discard the packet
			 * entirely?
			 */
			if (n->pn_proto != IKEV2_PROTO_IKE) {
				(void) bunyan_error(log,
				    "Invalid SPI protocol in notification",
				    BUNYAN_T_STRING, "notification",
				    ikev2_notify_str(params[i].ntype),
				    BUNYAN_T_STRING, "protocol",
				    ikev2_spi_str(n->pn_proto),
				    BUNYAN_T_UINT32, "protonum",
				    (uint32_t)n->pn_proto, BUNYAN_T_END);
				return (B_FALSE);
			}
			if (n->pn_spi != 0) {
				(void) bunyan_error(log,
				    "Non-zero SPI size in NAT notification",
				    BUNYAN_T_STRING, "notification",
				    ikev2_notify_str(params[i].ntype),
				    BUNYAN_T_END);
				return (B_FALSE);
			}
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
			INVALID("ss_family");
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

	for (int i = 0; i < 2; i++) {
		uint8_t data[IKEV2_N_NAT_SIZE] = { 0 };

		/* The SPIs are always at the start of the packet */
		if (!compute_nat(pkt->pkt_raw, params[i].addr, data,
		    sizeof (data)))
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

	return (ikev2_add_notify(pkt, IKEV2_PROTO_IKE, 0, IKEV2_N_COOKIE,
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
create_nonceobj(ikev2_prf_t prf, pkt_payload_t *restrict ni,
    pkt_payload_t *restrict nr, CK_OBJECT_HANDLE_PTR restrict objp)
{
	size_t noncelen = MAX(ni->pp_len + nr->pp_len, ikev2_prf_outlen(prf));
	uint8_t nonce[noncelen];
	size_t ni_len = skeyseed_noncelen(prf, ni->pp_len);
	size_t nr_len = skeyseed_noncelen(prf, nr->pp_len);
	CK_RV rc;

	(void) memset(nonce, 0, noncelen);
	(void) memcpy(nonce, ni->pp_ptr, ni_len);
	(void) memcpy(nonce + ni_len, nr->pp_ptr, nr_len);

	rc = SUNW_C_KeyToObject(p11h(), ikev2_prf_to_p11(prf), nonce, noncelen,
	    objp);
	explicit_bzero(nonce, noncelen);

	if (rc != CKR_OK)
		PKCS11ERR(error, "SUNW_C_KeyToObject", rc,
		    BUNYAN_T_STRING, "objname", "Ni|Nr");

	return ((rc == CKR_OK) ? B_TRUE : B_FALSE);
}

static boolean_t
create_skeyseed(ikev2_sa_t *restrict sa, CK_OBJECT_HANDLE nonce,
    CK_OBJECT_HANDLE_PTR restrict keyp)
{
	CK_SESSION_HANDLE h = p11h();
	uint8_t *dh_key = NULL, *skeyseed = NULL;
	size_t dh_key_len = 0, skeyseed_len = 0;
	CK_RV rc = CKR_OK;
	boolean_t ok = B_TRUE;

	skeyseed_len = ikev2_prf_outlen(sa->prf);
	skeyseed = umem_zalloc(skeyseed_len, UMEM_DEFAULT);
	if (skeyseed == NULL)
		goto fail;

	/*
	 * Unfortunately, to generate SKEYSEED, we need to copy down the g^ir
	 * value to perform the prf function since there is no C_SignKey
	 * function in PKCS#11. As such we try to keep the value in memory for
	 * as short a time as possible.
	 */
	rc = pkcs11_ObjectToKey(h, sa->dh_key, (void **)&dh_key, &dh_key_len,
	    B_FALSE);
	if (rc != CKR_OK) {
		PKCS11ERR(error, "pkcs11_ObjectToKey", rc,
		    BUNYAN_T_STRING, "objname", "dh_key");
		goto fail;
	}

	ok = prf(sa->prf, nonce, skeyseed, skeyseed_len, dh_key, dh_key_len,
	    NULL);
	explicit_bzero(dh_key, dh_key_len);
	free(dh_key);
	dh_key = NULL;
	dh_key_len = 0;

	if (!ok) {
		explicit_bzero(skeyseed, skeyseed_len);
		goto fail;
	}

	rc = SUNW_C_KeyToObject(h, ikev2_prf_to_p11(sa->prf), skeyseed,
	    skeyseed_len, keyp);
	explicit_bzero(skeyseed, skeyseed_len);
	if (rc != CKR_OK) {
		PKCS11ERR(error, "SUNW_C_KeyToObject", rc,
		    BUNYAN_T_STRING, "objname", "skeyseed");
		goto fail;
	}

	(void) bunyan_trace(log, "Created SKEYSEED", BUNYAN_T_END);

	return (B_TRUE);

fail:
	if (dh_key != NULL) {
		explicit_bzero(dh_key, dh_key_len);
		free(dh_key);
	}
	if (skeyseed != NULL) {
		explicit_bzero(skeyseed, skeyseed_len);
		umem_free(skeyseed, skeyseed_len);
	}
	return (B_FALSE);
}

static boolean_t
ikev2_sa_keygen(ikev2_sa_result_t *restrict result, pkt_t *restrict init,
    pkt_t *restrict resp)
{
	ikev2_sa_t *sa = resp->pkt_sa;
	pkt_payload_t *ni = pkt_get_payload(init, IKEV2_PAYLOAD_NONCE, NULL);
	pkt_payload_t *nr = pkt_get_payload(resp, IKEV2_PAYLOAD_NONCE, NULL);
	CK_OBJECT_HANDLE nonce = CK_INVALID_HANDLE;
	CK_OBJECT_HANDLE skeyseed = CK_INVALID_HANDLE;
	size_t encrlen = result->sar_encr_keylen;
	size_t prflen = ikev2_prf_keylen(result->sar_prf);
	size_t authlen = auth_data[result->sar_auth].ad_keylen;
	int p11prf = ikev2_prf_to_p11(result->sar_prf);
	int p11encr = encr_data[result->sar_encr].ed_p11id;
	int p11auth = auth_data[result->sar_auth].ad_p11id;
	prfp_t prfp = { 0 };

	if (encrlen == 0)
		encrlen = encr_data[sa->encr].ed_keydefault;

	sa->encr = result->sar_encr;
	sa->auth = result->sar_auth;
	sa->prf = result->sar_prf;
	sa->dhgrp = result->sar_dh;
	sa->saltlen = encr_data[result->sar_encr].ed_saltlen;
	sa->encr_key_len = encrlen / NBBY;

	if (!create_nonceobj(sa->prf, ni, nr, &nonce))
		goto fail;
	if (!create_skeyseed(sa, nonce, &skeyseed))
		goto fail;
	pkcs11_destroy_obj("Ni|Nr", &nonce);

	if (!prfplus_init(&prfp, sa->prf, skeyseed,
	    ni->pp_ptr, (size_t)ni->pp_len,
	    nr->pp_ptr, (size_t)nr->pp_len,
	    pkt_start(init), sizeof (uint64_t) * 2, NULL))
		goto fail;
	if (!prf_to_p11key(&prfp, "SK_d", p11prf, prflen, &sa->sk_d))
		goto fail;
	if (!prf_to_p11key(&prfp, "SK_ai", p11auth, authlen, &sa->sk_ai))
		goto fail;
	if (!prf_to_p11key(&prfp, "SK_ar", p11auth, authlen, &sa->sk_ar))
		goto fail;
	if (!prf_to_p11key(&prfp, "SK_ei", p11encr, sa->encr_key_len,
	    &sa->sk_ei))
		goto fail;
	if (!prfplus(&prfp, sa->salt_i, sa->saltlen))
		goto fail;
	if (!prf_to_p11key(&prfp, "SK_er", p11encr, sa->encr_key_len,
	    &sa->sk_er))
		goto fail;
	if (!prfplus(&prfp, sa->salt_r, sa->saltlen))
		goto fail;
	if (!prf_to_p11key(&prfp, "SK_pi", p11prf, prflen, &sa->sk_pi))
		goto fail;
	if (!prf_to_p11key(&prfp, "SK_pr", p11prf, prflen, &sa->sk_pr))
		goto fail;

	pkcs11_destroy_obj("Ni|Nr", &nonce);
	pkcs11_destroy_obj("skeyseed", &skeyseed);
	prfplus_fini(&prfp);
	return (B_TRUE);

fail:
	pkcs11_destroy_obj("Ni|Nr", &nonce);
	pkcs11_destroy_obj("skeyseed", &skeyseed);
	prfplus_fini(&prfp);
	return (B_FALSE);
}
