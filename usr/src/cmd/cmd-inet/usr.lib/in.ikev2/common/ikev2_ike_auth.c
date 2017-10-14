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
#include <errno.h>
#include <strings.h>
#include <synch.h>
#include <sys/debug.h>
#include "defs.h"
#include "ikev2.h"
#include "ikev2_common.h"
#include "ikev2_enum.h"
#include "ikev2_pkt.h"
#include "ikev2_proto.h"
#include "ikev2_sa.h"
#include "pkcs11.h"
#include "pkt.h"
#include "preshared.h"
#include "prf.h"
#include "worker.h"

static void ikev2_ike_auth_inbound_init(pkt_t *);
static void ikev2_ike_auth_inbound_resp(pkt_t *);
static boolean_t ikev2_auth_failed(const pkt_t *);
static boolean_t ikev2_auth(pkt_t *, boolean_t);
static boolean_t create_psk(ikev2_sa_t *restrict, preshared_entry_t *restrict);
static boolean_t calc_auth(ikev2_sa_t *restrict, boolean_t,
    const uint8_t *restrict, size_t, uint8_t *restrict, size_t);

void
ikev2_ike_auth_inbound(pkt_t *pkt)
{
	VERIFY(IS_WORKER);
	VERIFY(MUTEX_HELD(&pkt->pkt_sa->i2sa_lock));

	if (pkt_header(pkt)->flags & IKEV2_FLAG_INITIATOR)
		ikev2_ike_auth_inbound_init(pkt);
	else
		ikev2_ike_auth_inbound_resp(pkt);
}

/*
 * We are the responder
 */
static void
ikev2_ike_auth_inbound_init(pkt_t *req)
{
	VERIFY(IS_WORKER);
	VERIFY(MUTEX_HELD(&req->pkt_sa->i2sa_lock));

	ikev2_sa_t *sa = req->pkt_sa;
	pkt_t *resp = NULL;
	parsedmsg_t *pmsg = NULL;
	pkt_payload_t *id_r = NULL;
	sockaddr_u_t src = { .sau_ss = &sa->raddr };
	sockaddr_u_t dest = { .sau_ss = &sa->laddr };
	ikev2_sa_result_t result = { 0 };
	uint32_t spi = 0;

	/*
	 * RFC7296 2.21.2 - We must first authenticate before we can
	 * possibly send errors related to the piggybacked child SA
	 * creation.
	 */
	if (!ikev2_auth(req, B_TRUE)) {
		ikev2_auth_failed(req);	/* XXX: return value ! */
		ikev2_sa_condemn(sa);
		goto fail;
	}

	if (!pfkey_getspi(src, dest, 0, &spi))
		goto fail;

	/* XXX: Handle TSi TSr payloads from initiator */

	if (!ikev2_sa_match_acquire(pmsg, IKEV2_DH_NONE, req, &result)) {
		int proto = 0, spi = 0; /* XXX! */

		ikev2_no_proposal_chosen(req, proto, spi);
		/*
		 * XXX: For testing purposes at least, we elect to keep
		 * the IKE SA around even after failing to negotiate the
		 * child SA.  This is permissible (RFC7296 2.21.2), and
		 * could help with additional testing during development.
		 * We can revisit if we wish to keep this (possibly as an
		 * optional policy option) before integration.
		 */
		goto fail;
	}

	/* The initiator may optionally equest we send a specific ID */
	id_r = pkt_get_payload(req, IKEV2_PAYLOAD_IDr, NULL);

	resp = ikev2_pkt_new_response(req);
	/*
	 * If we're out of memory, instead of just condemning the IKE SA
	 * we'll wait for the P1 timeout.  It may be possible we can
	 * proceed upon receiving a retransmit.
	 */
	if (resp == NULL)
		goto fail;
	if (!ikev2_add_sk(resp))
		goto fail;

	/* XXX: Add IDr payload */

	/* XXX: Add CERT payloads */

	/* XXX: ADD CERTREQ payloads */

	if (!ikev2_auth(resp, B_FALSE))
		goto fail;

	if (!ikev2_sa_add_result(resp, &result))
		goto fail;

	/* XXX: Add TSi TSr Payloads */

	if (!ikev2_send(resp, B_FALSE))
		goto fail;

	return;

fail:
	ikev2_pkt_free(resp);
	ikev2_pkt_free(req);
}

/*
 * We are the initiator
 */
void
ikev2_ike_auth_outbound(ikev2_sa_t *sa)
{
	VERIFY(IS_WORKER);
	VERIFY(MUTEX_HELD(&sa->i2sa_lock));

	pkt_t *req = ikev2_pkt_new_exchange(sa, IKEV2_EXCH_IKE_AUTH);
	parsedmsg_t *pmsg = list_head(&sa->i2sa_pending);
	sockaddr_u_t src = { .sau_ss = &sa->laddr };
	sockaddr_u_t dest = { .sau_ss = &sa->raddr };
	uint32_t spi = 0;

	/* We should have at least one ACQUIRE pending if we got this far */
	VERIFY3P(pmsg, !=, NULL);
	VERIFY3U(pmsg->pmsg_samsg->sadb_msg_type, ==, SADB_ACQUIRE);

	if (req == NULL)
		goto fail;

	/* XXX: how to delete if we fail? */
	if (!pfkey_getspi(src, dest, pmsg->pmsg_samsg->sadb_msg_satype, &spi))
		goto fail;

	if (!ikev2_add_sk(req))
		goto fail;

	/* XXX: Get & add ID payload */

	/* XXX: Add any CERT or CERTREQ payloads */

	/* XXX: Add an IDr payload if requesting a specific ID from peer */

	if (!ikev2_auth(req, B_TRUE))
		goto fail;

	/*
	 * RFC7296 1.2 (Last paragraph) -- the IKE_AUTH exchanges do not
	 * contain nonce or KE payloads.  Only subsequent CREATE_CHILD_SA
	 * exchanges (new IPsec SAs or rekeys) can perform a new integrity
	 * (DH/ECP/etc) exchange.
	 */
	if (!ikev2_sa_from_acquire(req, pmsg, spi, IKEV2_DH_NONE))
		goto fail;

	/* XXX: Add TS's */

	if (!ikev2_send(req, B_FALSE))
		goto fail;

	return;

fail:
	ikev2_pkt_free(req);
	ikev2_sa_condemn(sa);
}

/*
 * We are the initiator, this is the response
 */
static void
ikev2_ike_auth_inbound_resp(pkt_t *resp)
{
	VERIFY(IS_WORKER);
	VERIFY(MUTEX_HELD(&resp->pkt_sa->i2sa_lock));
}

/*
 * Calculate what the AUTH payload value should be. If check is B_FALSE,
 * add calculated value to packet in IKEV2_PAYLOAD_AUTH payload and return.
 * Otherwise the calculated value is compared to the existing value in pkt,
 * if they match, the SA is marked as authenticated and the P1 timer is
 * cancelled.
 */
static boolean_t
ikev2_auth(pkt_t *pkt, boolean_t check)
{
	ikev2_sa_t *sa = pkt->pkt_sa;
	pkt_payload_t *id = NULL;
	pkt_payload_t *auth = NULL;
	uint8_t *buf = NULL;
	size_t buflen = 0;
	boolean_t initiator =
	    pkt_header(pkt)->flags & IKEV2_FLAG_INITIATOR ? B_TRUE : B_FALSE;
	boolean_t ret = B_FALSE;

	/*
	 * XXX: Maybe move this check as part of post-decrypt validation
	 * checks?
	 */
	if (check &&
	    (auth = pkt_get_payload(pkt, IKEV2_PAYLOAD_AUTH, NULL)) == NULL) {
		ikev2_pkt_log(pkt, sa->i2sa_log, BUNYAN_L_ERROR,
		    "Packet is missing AUTH payload");
		goto done;
	}

	switch (sa->authmethod) {
	case IKEV2_AUTH_SHARED_KEY_MIC:
		buflen = ikev2_prf_outlen(sa->prf);
		break;
	case IKEV2_AUTH_RSA_SIG:
	case IKEV2_AUTH_DSS_SIG:
	case IKEV2_AUTH_ECDSA_256:
	case IKEV2_AUTH_ECDSA_384:
	case IKEV2_AUTH_ECDSA_512:
	case IKEV2_AUTH_GSPM: {
		char str[IKEV2_ENUM_STRLEN];

		(void) bunyan_info(sa->i2sa_log,
		    "IKE SA Authentication method not yet implemented",
		    BUNYAN_T_STRING, "authmethod",
		    ikev2_auth_type_str(sa->authmethod, str, sizeof (str)),
		    BUNYAN_T_END);
		goto done;
	}
	case IKEV2_AUTH_NONE:
		INVALID("sa->authmethod");
		break;
	}

	if (check && buflen != auth->pp_len) {
		(void) bunyan_error(sa->i2sa_log,
		    "AUTH payload size mismatch",
		    BUNYAN_T_UINT32, "authlen", (uint32_t)auth->pp_len,
		    BUNYAN_T_UINT32, "expected", (uint32_t)buflen,
		    BUNYAN_T_END);
	}

	if ((buf = umem_alloc(buflen, UMEM_DEFAULT)) == NULL) {
		STDERR(error, sa->i2sa_log, "No memory for IKE SA AUTH");
		goto done;
	}

	id = pkt_get_payload(pkt,
	    initiator ? IKEV2_PAYLOAD_IDi : IKEV2_PAYLOAD_IDr, NULL);
	if (id == NULL) {
		/*
		 * If we're adding (i.e. constructing) the packet, something is
		 * wrong if we've not added the proper ID payload.  However
		 * if we're authenticating the peer, just fail the
		 * authentication check due to a missing id.
		 */
		if (!check) {
			VERIFY3P(id, !=, NULL);
		} else {
			/* XXX: Do as inbound check? */
			ikev2_pkt_log(pkt, sa->i2sa_log, BUNYAN_L_ERROR,
			    "packet is missing ID payload");
			goto done;
		}
	}

	if (!calc_auth(sa, initiator, id->pp_ptr, id->pp_len, buf, buflen))
		goto done;

	if (!check) {
		ret = ikev2_add_auth(pkt, sa->authmethod, buf, buflen);
	} else {
		/* We checked earlier that the two buffers are the same size */
		if (memcmp(auth->pp_ptr, buf, buflen) != 0) {
			(void) bunyan_error(sa->i2sa_log,
			    "Authentication failed", BUNYAN_T_END);
			goto done;
		}

		(void) bunyan_info(sa->i2sa_log, "Authentication succeeded",
		    BUNYAN_T_END);
		sa->flags |= I2SA_AUTHENTICATED;

		(void) periodic_cancel(wk_periodic, sa->i2sa_p1_timer);
		sa->i2sa_p1_timer = 0;

		ret = B_TRUE;
	}

done:
	explicit_bzero(buf, buflen);
	umem_free(buf, buflen);
	return (ret);
}

static boolean_t
calc_auth(ikev2_sa_t *restrict sa, boolean_t initiator,
    const uint8_t *restrict id, size_t idlen, uint8_t *restrict out,
    size_t outlen)
{
	pkt_t *init = NULL;
	pkt_payload_t *nonce = NULL;
	CK_OBJECT_HANDLE mackey;
	CK_RV rc;
	size_t maclen = ikev2_prf_outlen(sa->prf);
	boolean_t ret = B_FALSE;
	/* This is at most 64 bytes */
	uint8_t mac[maclen];

	VERIFY(MUTEX_HELD(&sa->i2sa_lock));

	/*
	 * Gather the data to be signed for the given side.  The detailed
	 * explanation can be read in RFC7296 2.15.  The summarized version is
	 * we sign using the method specified in the IKE rule (e.g. preshared
	 * key, RSA, etc -- this is not negotiated, but must be pre-agreed to
	 * by both peers).
	 *
	 * Note that while we include our IKE_SA_INIT and MACed ID as part of
	 * the data to sign, we use the nonce of our peer.
	 */
	if (initiator) {
		init = sa->init_i;
		nonce = pkt_get_payload(sa->init_r, IKEV2_PAYLOAD_NONCE, NULL);
		mackey = sa->sk_pi;
	} else {
		init = sa->init_r;
		nonce = pkt_get_payload(sa->init_i, IKEV2_PAYLOAD_NONCE, NULL);
		mackey = sa->sk_pr;
	}
	/* MACedIDFor{R|I} */
	if (!prf(sa->prf, mackey, mac, maclen, sa->i2sa_log, id, idlen, NULL))
		goto done;

	switch (sa->authmethod) {
	case IKEV2_AUTH_SHARED_KEY_MIC:
		ret = prf(sa->prf, sa->psk, out, outlen, sa->i2sa_log,
		    pkt_start(init), pkt_len(init),	/* RealMessage{1|2} */
		    nonce->pp_ptr, nonce->pp_len,	/* Nonce{R|I}Data */
		    mac, maclen, NULL);			/* MACedIDFor{I|R} */
		break;
	case IKEV2_AUTH_RSA_SIG:
	case IKEV2_AUTH_DSS_SIG:
	case IKEV2_AUTH_ECDSA_256:
	case IKEV2_AUTH_ECDSA_384:
	case IKEV2_AUTH_ECDSA_512:
	case IKEV2_AUTH_GSPM: {
		char str[IKEV2_ENUM_STRLEN];

		(void) bunyan_info(sa->i2sa_log,
		    "IKE SA Authentication method not yet implemented",
		    BUNYAN_T_STRING, "authmethod",
		    ikev2_auth_type_str(sa->authmethod, str, sizeof (str)),
		    BUNYAN_T_END);
		goto done;
	}
	case IKEV2_AUTH_NONE:
		INVALID("sa->authmethod");
		break;
	}

done:
	explicit_bzero(mac, maclen);
	return (ret);
}

/* Compute prf(<preshared secret>, IKEV2_KEYPAD) and store in objp */
static boolean_t
create_psk(ikev2_sa_t *restrict sa, preshared_entry_t *restrict pe)
{
	CK_SESSION_HANDLE h = p11h();
	CK_MECHANISM_TYPE mechtype = ikev2_prf_to_p11(sa->prf);
	CK_OBJECT_HANDLE psktemp = CK_INVALID_HANDLE;
	CK_RV rc;
	size_t outlen = ikev2_prf_outlen(sa->prf);
	boolean_t ret = B_FALSE;
	uint8_t buf[outlen];

	/*
	 * First need to convert the preshared secret into a PKCS#11 object
	 * XXX: We could potentially do this on startup.
	 */
	rc = SUNW_C_KeyToObject(h, mechtype, pe->pe_keybuf, pe->pe_keybuf_bytes,
	    &psktemp);
	if (rc != CKR_OK) {
		PKCS11ERR(error, sa->i2sa_log, "SUNW_C_KeyToObject", rc,
		    BUNYAN_T_STRING, "objname", "psktemp", BUNYAN_T_END);
		goto done;
	}

	if (!prf(sa->prf, psktemp, buf, outlen, sa->i2sa_log,
	    IKEV2_KEYPAD, sizeof (IKEV2_KEYPAD), NULL))
		goto done;

	rc = SUNW_C_KeyToObject(h, mechtype, buf, outlen, &sa->psk);
	if (rc != CKR_OK) {
		PKCS11ERR(error, sa->i2sa_log, "SUNW_C_KeyToObject", rc,
		    BUNYAN_T_STRING, "objname", "psk", BUNYAN_T_END);
		goto done;
	}
	ret = B_TRUE;

done:
	pkcs11_destroy_obj("psktemp", &psktemp, sa->i2sa_log);
	explicit_bzero(buf, outlen);
	return (ret);
}

static boolean_t
ikev2_auth_failed(const pkt_t *src)
{
	pkt_t *msg = NULL;
	boolean_t resp =
	    pkt_header(src)->flags & IKEV2_FLAG_INITIATOR ? B_TRUE : B_FALSE;

	if (resp)
		msg = ikev2_pkt_new_response(src);
	else
		msg = ikev2_pkt_new_exchange(src->pkt_sa,
		    IKEV2_EXCH_INFORMATIONAL);

	if (msg == NULL)
		return (B_FALSE);

	if (!ikev2_add_notify(msg, IKEV2_PROTO_IKE, 0,
	    IKEV2_N_AUTHENTICATION_FAILED, NULL, 0)) {
		ikev2_pkt_free(msg);
		return (B_FALSE);
	}

	return (ikev2_send(msg, resp));
}
