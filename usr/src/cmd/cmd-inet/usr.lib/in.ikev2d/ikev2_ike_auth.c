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
 * Copyright 2018, Joyent, Inc.
 */

#include <bunyan.h>
#include <errno.h>
#include <note.h>
#include <strings.h>
#include <synch.h>
#include <sys/debug.h>
#include <sys/sha2.h>	/* For digest sizes */

#include "config.h"
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
#include "util.h"
#include "worker.h"

static void ikev2_ike_auth_init_resp(ikev2_sa_t *restrict, pkt_t *restrict,
    void *restrict);
static void ikev2_auth_failed(ikev2_sa_t *);
static boolean_t create_psk(ikev2_sa_t *);
static boolean_t calc_auth(ikev2_sa_t *restrict, boolean_t,
    pkt_payload_t *restrict, uint8_t *restrict, size_t);
static boolean_t add_id(pkt_t *, const config_id_t *id, boolean_t);
static boolean_t add_auth(pkt_t *);
static boolean_t check_auth(pkt_t *);
static boolean_t check_remote_id(pkt_t *, config_id_t **);

static config_id_t *i2id_to_cid(pkt_payload_t *);
static size_t get_authlen(const ikev2_sa_t *);

void
ikev2_ike_auth_init(ikev2_sa_t *restrict sa)
{
	VERIFY(IS_WORKER);
	VERIFY(!MUTEX_HELD(&sa->i2sa_queue_lock));
	VERIFY(MUTEX_HELD(&sa->i2sa_lock));

	ikev2_sa_args_t *sa_args = sa->sa_init_args;
	config_rule_t *rule = sa->i2sa_rule;
	pkt_t *req = ikev2_pkt_new_exchange(sa, IKEV2_EXCH_IKE_AUTH);

	/*
	 * Once we start the IKE_AUTH exchange, we no longer need the
	 * DH keys used during the IKE_SA_INIT exchange
	 */
	pkcs11_destroy_obj("dh_pubkey", &sa_args->i2a_pubkey);
	pkcs11_destroy_obj("dh_privkey", &sa_args->i2a_privkey);
	pkcs11_destroy_obj("dh_key", &sa_args->i2a_dhkey);

	(void) bunyan_debug(log, "Starting IKE_AUTH exchange", BUNYAN_T_END);

	if (req == NULL)
		goto fail;

	if (!add_id(req, rule->rule_local_id, B_TRUE))
		goto fail;

	/* XXX: CERT */

	/*
	 * Since we should be the only IKE instance running on this host/zone,
	 * if we are initiating a new IKE SA, it means we have no existing
	 * IKE SA for this peer.  Inform the peer of this in case we restarted
	 * due to a crash or such.  This allows the peer to clear out any
	 * leftover IKE SA it might have for us.
	 */
	if (!ikev2_add_notify(req, IKEV2_N_INITIAL_CONTACT))
		goto fail;

	/* XXX: HTTP_CERT_LOOKUP_SUPPORTED */

	/* XXX: CERTREQ */

	/*
	 * XXX: We can optionally add _1_ IDr payload to indicate a preferred
	 * ID for the responder to use.  Since we currently support multiple
	 * remote ids in a rule, not sure there's any benefit to do this.
	 * For now, we elect not to do this.
	 */

	if (!add_auth(req))
		goto fail;

	if (!ikev2_create_child_sa_init_auth(sa, req))
		goto fail;

	if (!ikev2_send_req(req, ikev2_ike_auth_init_resp, sa_args)) {
		req = NULL;
		goto fail;
	}

	return;

fail:
	(void) bunyan_error(log, "Cound not send IKE_AUTH request",
	    BUNYAN_T_END);
	sa->flags |= I2SA_CONDEMNED;
	ikev2_pkt_free(req);
}

/* We are the responder */
void
ikev2_ike_auth_resp(pkt_t *req)
{
	VERIFY(IS_WORKER);
	VERIFY(MUTEX_HELD(&req->pkt_sa->i2sa_lock));

	ikev2_sa_t *sa = req->pkt_sa;
	ikev2_sa_args_t *sa_args = sa->sa_init_args;
	config_rule_t *rule = sa->i2sa_rule;
	pkt_t *resp = NULL;
	pkt_payload_t *id_r = NULL;
	config_id_t *cid_i = NULL;
	const char *mstr = NULL;

	resp = ikev2_pkt_new_response(req);

	/*
	 * If we're out of memory, instead of just condemning the IKE SA
	 * we'll wait for the P1 timeout.  It may be possible we can
	 * proceed upon receiving a retransmit.
	 */
	if (resp == NULL)
		goto fail;

	/*
	 * This is possible, but strange -- we've authenticated
	 * (IKE_AUTH messages always start with msgid 1, but could go higher
	 * if/when we support EAP, so it must be > 1 or else we should have
	 * already handled it as a duplicate), but are receiving another
	 * IKE_AUTH request.  RFC7296 says nothing about this, however the
	 * peer is expecting a response, the only good candidates are
	 * AUTHENTICATION_FAILED or INVALID_SYNTAX.  The latter seems better
	 * since we've already authenticated.
	 */
	if (sa->flags & I2SA_AUTHENTICATED) {
		VERIFY3U(ntohl(pkt_header(req)->msgid), >, 1);
		(void) bunyan_warn(log,
		    "Received an IKE_AUTH request to an already authenticated "
		    "IKE SA;", BUNYAN_T_END);

		/* This is the 2nd payload (after SK) -- it should always fit */
		VERIFY(ikev2_add_notify(resp, IKEV2_N_INVALID_SYNTAX));
		ikev2_send_resp(resp);
		return;
	}

	/*
	 * Once we start the IKE_AUTH exchange, we no longer need the
	 * DH keys used during the IKE_SA_INIT exchange
	 */
	pkcs11_destroy_obj("dh_pubkey", &sa_args->i2a_pubkey);
	pkcs11_destroy_obj("dh_privkey", &sa_args->i2a_privkey);
	pkcs11_destroy_obj("dh_key", &sa_args->i2a_dhkey);

	(void) bunyan_debug(log, "Responding to IKE_AUTH request",
	    BUNYAN_T_END);

	if (!check_remote_id(req, &cid_i))
		goto authfail;
	key_add_id(LOG_KEY_REMOTE_ID, LOG_KEY_REMOTE_ID_TYPE, cid_i);

	mstr = ikev2_auth_type_str(sa->authmethod);

	/*
	 * RFC7296 2.21.2 - We must first authenticate before we can
	 * possibly send errors related to the piggybacked child SA
	 * creation.
	 */
	if (!check_auth(req)) {
		(void) bunyan_warn(log, "Authentication failed",
		    BUNYAN_T_STRING, "authmethod", mstr,
		    BUNYAN_T_END);

		goto authfail;
	}

	sa->remote_id = cid_i;
	sa->flags |= I2SA_AUTHENTICATED;
	(void) ikev2_sa_disarm_timer(sa, I2SA_EVT_P1_EXPIRE);

	(void) bunyan_info(log, "Authentication successful",
	    BUNYAN_T_STRING, "authmethod", mstr,
	    BUNYAN_T_END);

	/*
	 * XXX: Check for INITIAL_CONTACT, if there are, delete any existing
	 * IPsec SAs between the two hosts based on the authenticated ID.
	 */

	/* The initiator may optionally request we send a specific ID */
	if ((id_r = pkt_get_payload(req, IKEV2_PAYLOAD_IDr, NULL)) != NULL) {
		/*
		 * If the initiator is requesting an ID that is not the one
		 * specified in the rule, for now we'll note the difference
		 * and still respond, using our configured id.
		 */
		config_id_t *cid_r = NULL;

		/* If this fails, we just ignore the whole payload */
		if ((cid_r = i2id_to_cid(id_r)) != NULL &&
		    config_id_cmp(cid_r, rule->rule_local_id) != 0) {
			uint8_t idtype = *id_r->pp_ptr;
			char idbuf[256] = { 0 };

			(void) bunyan_info(log,
			    "Initiator requested ID other than ours",
			    BUNYAN_T_STRING, "idtype",
			    ikev2_id_type_str(idtype),
			    BUNYAN_T_STRING, "id",
			    ikev2_id_str(id_r, idbuf, sizeof (idbuf)),
			    BUNYAN_T_END);
		}
		config_id_free(cid_r);
	}

	if (!add_id(resp, rule->rule_local_id, B_FALSE))
		goto fail;

	/* XXX: Add CERT payloads */

	if (!add_auth(resp))
		goto fail;

	if (!ikev2_create_child_sa_resp_auth(req, resp))
		goto fail;

	ikev2_send_resp(resp);
	ikev2_sa_args_free(sa->sa_init_args);
	sa->sa_init_args = NULL;
	return;

fail:
	(void) bunyan_error(log, "Cound not send IKE_AUTH response",
	    BUNYAN_T_END);

	ikev2_sa_args_free(sa->sa_init_args);
	sa->sa_init_args = NULL;
	sa->flags |= I2SA_CONDEMNED;
	ikev2_pkt_free(resp);
	return;

authfail:
	config_id_free(cid_i);
	ikev2_sa_args_free(sa->sa_init_args);
	sa->sa_init_args = NULL;
	sa->flags |= I2SA_CONDEMNED;

	VERIFY(ikev2_add_notify(resp, IKEV2_N_AUTHENTICATION_FAILED));
	ikev2_send_resp(resp);
}

/*
 * We are the initiator, this is the response
 */
static void
ikev2_ike_auth_init_resp(ikev2_sa_t *restrict sa, pkt_t *restrict resp,
    void *restrict arg)
{
	config_id_t *cid_r = NULL;
	const char *mstr = NULL;

	VERIFY(IS_WORKER);
	VERIFY(MUTEX_HELD(&sa->i2sa_lock));

	(void) bunyan_debug(log, "Received IKE_AUTH response",
	    BUNYAN_T_END);

	/* ikev2_retransmit() will condemn the IKE SA if we timeout */
	if (resp == NULL) {
		/* Let the piggy-backed child SA cleanup */
		ikev2_create_child_sa_init_resp_auth(sa, NULL, arg);
		return;
	}

	/*
	 * RFC 7296 2.21.2 -- If authentication fails, the IKE SA is not
	 * established.  However, authentication can successfully complete
	 * while the included child SA request can fail, which does not
	 * necessairly cause the IKE SA to be deleted -- if we wish to
	 * delete the IKE SA, or if we (the initiator) reject the IKE SA
	 * (as opposed to the responder), it all must be done in a separate
	 * exchange.  All of that is to say, that this is the only notification
	 * we check for before doing the authentication portion of the
	 * processing.
	 */
	if (pkt_get_notify(resp, IKEV2_N_AUTHENTICATION_FAILED, NULL) != NULL) {
		(void) bunyan_warn(log,
		    "Remote rejected our authentication attempt",
		    BUNYAN_T_END);

		ikev2_create_child_sa_init_resp_auth(sa, NULL, arg);
		sa->flags |= I2SA_CONDEMNED;
		return;
	}

	if (!check_remote_id(resp, &cid_r))
		goto fail;

	mstr = ikev2_auth_type_str(sa->authmethod);

	key_add_id(LOG_KEY_REMOTE_ID, LOG_KEY_REMOTE_ID_TYPE, cid_r);

	if (!check_auth(resp)) {
		(void) bunyan_warn(log, "Authentication failed",
		    BUNYAN_T_STRING, "authmethod", mstr,
		    BUNYAN_T_END);
		goto fail;
	}

	(void) bunyan_info(log, "Authentication successful",
	    BUNYAN_T_STRING, "authmethod", mstr,
	    BUNYAN_T_END);

	sa->remote_id = cid_r;
	sa->flags |= I2SA_AUTHENTICATED;
	(void) ikev2_sa_disarm_timer(sa, I2SA_EVT_P1_EXPIRE);

	ikev2_create_child_sa_init_resp_auth(sa, resp, arg);
	ikev2_sa_args_free(sa->sa_init_args);
	sa->sa_init_args = NULL;
	return;

fail:
	ikev2_create_child_sa_init_resp_auth(sa, NULL, arg);
	ikev2_sa_args_free(sa->sa_init_args);
	sa->sa_init_args = NULL;
	ikev2_auth_failed(sa);
}

static boolean_t
add_auth(pkt_t *pkt)
{
	ikev2_sa_t *sa = pkt->pkt_sa;
	pkt_payload_t *payid = NULL;
	size_t authlen = get_authlen(sa);
	boolean_t initiator = I2P_INITIATOR(pkt);
	boolean_t ret = B_FALSE;
	/* This is at most 64 bytes */
	uint8_t auth[authlen];

	payid = pkt_get_payload(pkt,
	    initiator ? IKEV2_PAYLOAD_IDi : IKEV2_PAYLOAD_IDr, NULL);

	/* We're constructing the pkt, so we've messed up badly if missing */
	VERIFY3P(payid, !=, NULL);

	if (!calc_auth(sa, initiator, payid, auth, authlen))
		goto done;

	(void) bunyan_trace(log, "Adding AUTH payload to packet", BUNYAN_T_END);

	if (!ikev2_add_auth(pkt, sa->authmethod, auth, authlen)) {
		(void) bunyan_error(log, "No space for AUTH payload in packet",
		    BUNYAN_T_END);
		goto done;
	}
	ret = B_TRUE;

done:
	explicit_bzero(auth, authlen);
	return (ret);
}

static boolean_t
check_auth(pkt_t *pkt)
{
	ikev2_sa_t *sa = pkt->pkt_sa;
	pkt_payload_t *payid = NULL;
	pkt_payload_t *payauth = NULL;
	uint8_t *auth = NULL;
	size_t authlen = 0;
	size_t buflen = get_authlen(sa);
	boolean_t initiator = I2P_INITIATOR(pkt);
	boolean_t ret = B_FALSE;
	/* This is at most 64 bytes each */
	uint8_t buf[buflen];

	(void) bunyan_trace(log, "Checking AUTH payload", BUNYAN_T_END);

	payauth = pkt_get_payload(pkt, IKEV2_PAYLOAD_AUTH, NULL);

	/* XXX: Move these to inbound packet checks? */
	payid = pkt_get_payload(pkt,
	    initiator ? IKEV2_PAYLOAD_IDi : IKEV2_PAYLOAD_IDr, NULL);

	if (payid == NULL) {
		(void) bunyan_warn(log, "Packet is missing it's ID payload",
		    BUNYAN_T_END);
		return (B_FALSE);
	}

	if (payauth == NULL) {
		(void) bunyan_warn(log, "Packet is missing AUTH payload",
		    BUNYAN_T_END);
		return (B_FALSE);
	}

	/* Our packet checks should catch this */
	VERIFY3U(payauth->pp_len, >, sizeof (ikev2_auth_t));

	/*
	 * XXX: It seems that in theory (at least) we could support different
	 * authentication methods in each direction.  It seems like this
	 * could invite troubleshooting headaches though. For now at least,
	 * we will require both ends to use the same method.
	 */
	if (payauth->pp_ptr[0] != sa->authmethod) {
		const char *l_meth = NULL, *r_meth = NULL;

		l_meth = ikev2_auth_type_str(sa->authmethod);
		r_meth = ikev2_auth_type_str(payauth->pp_ptr[0]);

		(void) bunyan_warn(log,
		    "Authentication method mismatch with remote peer",
		    BUNYAN_T_STRING, "local_method", l_meth,
		    BUNYAN_T_STRING, "remote_method", r_meth,
		    BUNYAN_T_END);
		return (B_FALSE);
	}

	auth = payauth->pp_ptr + sizeof (ikev2_auth_t);
	authlen = payauth->pp_len - sizeof (ikev2_auth_t);

	if (authlen != buflen) {
		(void) bunyan_warn(log,
		    "AUTH size mismatch",
		    BUNYAN_T_UINT32, "authlen", (uint32_t)authlen,
		    BUNYAN_T_UINT32, "expected", (uint32_t)buflen,
		    BUNYAN_T_END);
		return (B_FALSE);
	}

	if (!calc_auth(sa, initiator, payid, buf, buflen))
		goto done;

	/* We previously verified authlen == buflen */
	if (memcmp(auth, buf, buflen) == 0)
		ret = B_TRUE;

done:
	explicit_bzero(buf, buflen);
	return (ret);
}

static boolean_t
calc_auth(ikev2_sa_t *restrict sa, boolean_t initiator,
    pkt_payload_t *restrict id, uint8_t *restrict out, size_t outlen)
{
	ikev2_sa_args_t *sa_args = sa->sa_init_args;
	uint8_t *nonce = NULL, *init = NULL;
	size_t noncelen = 0, initlen = 0;
	size_t maclen = ikev2_prf_outlen(sa->prf);
	CK_OBJECT_HANDLE mackey;
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
		nonce = sa_args->i2a_nonce_r;
		noncelen = sa_args->i2a_nonce_r_len;
		mackey = sa->sk_pi;
		init = sa_args->i2a_init_i;
		initlen = sa_args->i2a_init_i_len;
	} else {
		nonce = sa_args->i2a_nonce_i;
		noncelen = sa_args->i2a_nonce_r_len;
		mackey = sa->sk_pr;
		init = sa_args->i2a_init_r;
		initlen = sa_args->i2a_init_r_len;
	}

	/* MACedIDFor{R|I} */
	if (!prf(sa->prf, mackey, mac, maclen, id->pp_ptr, id->pp_len, NULL))
		goto done;

	switch (sa->authmethod) {
	case IKEV2_AUTH_SHARED_KEY_MIC:
		if (sa->psk == CK_INVALID_HANDLE && !create_psk(sa))
			goto done;

		ret = prf(sa->prf, sa->psk, out, outlen,
		    init, initlen,			/* RealMessage{1|2} */
		    nonce, noncelen,			/* Nonce{R|I}Data */
		    mac, maclen, NULL);			/* MACedIDFor{I|R} */
		break;
	case IKEV2_AUTH_RSA_SIG:
	case IKEV2_AUTH_DSS_SIG:
	case IKEV2_AUTH_ECDSA_256:
	case IKEV2_AUTH_ECDSA_384:
	case IKEV2_AUTH_ECDSA_512:
	case IKEV2_AUTH_GSPM:
		/* TODO: Hook in certificate authentication support */
		(void) bunyan_info(log,
		    "IKE SA Authentication method not yet implemented",
		    BUNYAN_T_END);
		goto done;
	case IKEV2_AUTH_NONE:
		INVALID(sa->authmethod);
		break;
	}

done:
	explicit_bzero(mac, maclen);
	return (ret);
}

/*
 * Find the PSK for these addresses,
 * compute prf(<preshared secret>, IKEV2_KEYPAD), store as PKCS#11 object,
 * and save as sa->psk so it's ready for to use when creating/validating the
 * AUTH payloads.
 */
static boolean_t
create_psk(ikev2_sa_t *sa)
{
	preshared_entry_t *pe = NULL;
	sockaddr_u_t laddr = { .sau_ss = &sa->laddr };
	sockaddr_u_t raddr = { .sau_ss = &sa->raddr };
	CK_SESSION_HANDLE h = p11h();
	CK_MECHANISM_TYPE mechtype = ikev2_prf_to_p11(sa->prf);
	CK_OBJECT_HANDLE psktemp = CK_INVALID_HANDLE;
	CK_RV rc;
	size_t outlen = ikev2_prf_outlen(sa->prf);
	boolean_t ret = B_FALSE;
	uint8_t buf[outlen];

	switch (sa->raddr.ss_family) {
	case AF_INET:
		pe = lookup_ps_by_in_addr(&laddr.sau_sin->sin_addr,
		    &raddr.sau_sin->sin_addr);
		break;
	case AF_INET6:
		pe = lookup_ps_by_in6_addr(&laddr.sau_sin6->sin6_addr,
		    &raddr.sau_sin6->sin6_addr);
		break;
	default:
		INVALID("ss_family");
	}

	if (pe == NULL) {
		(void) bunyan_error(log,
		    "No matching preshared key found", BUNYAN_T_END);
		return (B_FALSE);
	}

	/*
	 * First need to convert the preshared secret into a PKCS#11 object
	 * XXX: We could potentially do this when we load the secrets.
	 */
	rc = SUNW_C_KeyToObject(h, mechtype, pe->pe_keybuf, pe->pe_keybuf_bytes,
	    &psktemp);
	if (rc != CKR_OK) {
		PKCS11ERR(error, "SUNW_C_KeyToObject", rc,
		    BUNYAN_T_STRING, "objname", "psktemp", BUNYAN_T_END);
		goto done;
	}

	if (!prf(sa->prf, psktemp, buf, outlen,
	    IKEV2_KEYPAD, sizeof (IKEV2_KEYPAD), NULL))
		goto done;

	rc = SUNW_C_KeyToObject(h, mechtype, buf, outlen, &sa->psk);
	if (rc != CKR_OK) {
		PKCS11ERR(error, "SUNW_C_KeyToObject", rc,
		    BUNYAN_T_STRING, "objname", "psk", BUNYAN_T_END);
		goto done;
	}
	ret = B_TRUE;

done:
	pkcs11_destroy_obj("psktemp", &psktemp);
	explicit_bzero(buf, outlen);
	return (ret);
}

static boolean_t
add_id(pkt_t *pkt, const config_id_t *id, boolean_t initiator)
{
	ikev2_sa_t *sa = pkt->pkt_sa;
	config_auth_id_t cid_type = 0;
	/* arbitrary default value to quiet GCC */
	ikev2_id_type_t id_type = IKEV2_ID_FQDN;
	const void *ptr = NULL;
	size_t idlen = 0;

	/* Default to IP if no id was specified */
	if (id == NULL) {
		switch (sa->laddr.ss_family) {
		case AF_INET:
			cid_type = CFG_AUTH_ID_IPV4;
			id_type = IKEV2_ID_IPV4_ADDR;
			break;
		case AF_INET6:
			cid_type = CFG_AUTH_ID_IPV6;
			id_type = IKEV2_ID_IPV6_ADDR;
			break;
		default:
			INVALID("ss_family");
		}
		ptr = ss_addr(SSTOSA(&sa->laddr));
		idlen = ss_addrlen(SSTOSA(&sa->laddr));
	} else if (id->cid_len == 0) {
		/* parsing should prevent this */
		INVALID(id->cid_len);
	} else {
		idlen = id->cid_len;
		ptr = id->cid_data;

		switch (id->cid_type) {
		case CFG_AUTH_ID_DN:
			id_type = IKEV2_ID_DER_ASN1_DN;
			break;
		case CFG_AUTH_ID_DNS:
			id_type = IKEV2_ID_FQDN;
			/* Exclude trailing NUL */
			idlen--;
			break;
		case CFG_AUTH_ID_GN:
			id_type = IKEV2_ID_DER_ASN1_GN;
			break;
		case CFG_AUTH_ID_IPV4:
		case CFG_AUTH_ID_IPV4_PREFIX:
		case CFG_AUTH_ID_IPV4_RANGE:
			id_type = IKEV2_ID_IPV4_ADDR;
			break;
		case CFG_AUTH_ID_IPV6:
		case CFG_AUTH_ID_IPV6_PREFIX:
		case CFG_AUTH_ID_IPV6_RANGE:
			id_type = IKEV2_ID_IPV6_ADDR;
			break;
		case CFG_AUTH_ID_EMAIL:
			id_type = IKEV2_ID_RFC822_ADDR;
			/* Exclude trailing NUL */
			idlen--;
			break;
		}
		cid_type = id->cid_type;
	}

	/* If we're adding our own (local) id, save it to the IKEv2 SA */
	if ((initiator && (sa->flags & I2SA_INITIATOR)) ||
	    (!initiator && !(sa->flags & I2SA_INITIATOR))) {
		sa->local_id = config_id_new(cid_type, ptr, idlen);
		if (sa->local_id == NULL) {
			(void) bunyan_error(log, "No memory to create IKE id",
			    BUNYAN_T_END);
			return (B_FALSE);
		}
		key_add_id(LOG_KEY_LOCAL_ID, LOG_KEY_LOCAL_ID_TYPE,
		    sa->local_id);
	}

	(void) bunyan_trace(log, "Setting IKEv2 ID", BUNYAN_T_END);

	return (ikev2_add_id(pkt, initiator, id_type, ptr, idlen));
}

static boolean_t
check_remote_id(pkt_t *pkt, config_id_t **pcid)
{
	config_id_t **remote_ids = NULL;
	pkt_payload_t *pid = NULL;
	boolean_t match = B_FALSE;

	*pcid = NULL;

	pid = pkt_get_payload(pkt,
	    I2P_INITIATOR(pkt) ? IKEV2_PAYLOAD_IDi : IKEV2_PAYLOAD_IDr, NULL);
	if (pid == NULL) {
		(void) bunyan_warn(log, "IKE_AUTH packet is missing ID",
		    BUNYAN_T_END);
		return (B_FALSE);
	}

	if ((*pcid = i2id_to_cid(pid)) == NULL)
		return (B_FALSE);

	/* If no remote id given, accept all IDs */
	remote_ids = pkt->pkt_sa->i2sa_rule->rule_remote_id;
	if (remote_ids == NULL)
		return (B_TRUE);

	for (size_t i = 0; remote_ids[i] != NULL; i++) {
		if (config_id_cmp(*pcid, remote_ids[i]) == 0) {
			match = B_TRUE;
			break;
		}
	}

	return (match);
}

/*
 * Convert an IKEv2 ID to a config_id_t and return the config_id_t.
 * Returns NULL on failure.
 */
static config_id_t *
i2id_to_cid(pkt_payload_t *i2id)
{
	config_id_t *cid = NULL;
	config_auth_id_t cidtype = 0;
	void *data = NULL;
	uint32_t datalen = 0;
	char *buf = NULL;
	const char *idtstr = NULL;

	if (i2id->pp_len <= sizeof (ikev2_id_t)) {
		(void) bunyan_error(log, "ID payload is truncated",
		    BUNYAN_T_UINT32, "len",
		    (uint32_t)(i2id->pp_len + sizeof (ikev2_payload_t)),
		    BUNYAN_T_UINT32, "expected",
		    (uint32_t)(sizeof (ikev2_payload_t) + sizeof (ikev2_id_t)),
		    BUNYAN_T_END);
		return (NULL);
	}

	idtstr = ikev2_id_type_str(i2id->pp_ptr[0]);

	data = i2id->pp_ptr + sizeof (ikev2_id_t);
	datalen = i2id->pp_len - sizeof (ikev2_id_t);

	switch ((ikev2_id_type_t)i2id->pp_ptr[0]) {
	case IKEV2_ID_IPV4_ADDR:
		cidtype = CFG_AUTH_ID_IPV4;
		if (datalen != sizeof (in_addr_t)) {
			(void) bunyan_warn(log, "ID payload length mismatch",
			    BUNYAN_T_STRING, "idtype", idtstr,
			    BUNYAN_T_UINT32, "len", datalen,
			    BUNYAN_T_UINT32, "expected",
			    (uint32_t)sizeof (in_addr_t), BUNYAN_T_END);
			return (NULL);
		}
		break;
	case IKEV2_ID_FQDN:
		cidtype = CFG_AUTH_ID_DNS;
		if ((buf = umem_zalloc(datalen + 1, UMEM_DEFAULT)) == NULL) {
			(void) bunyan_error(log, "No memory for IKE ID",
			    BUNYAN_T_END);
			return (NULL);
		}
		(void) memcpy(buf, data, datalen++);
		data = buf;
		break;
	case IKEV2_ID_RFC822_ADDR:
		cidtype = CFG_AUTH_ID_EMAIL;
		if ((buf = umem_zalloc(datalen + 1, UMEM_DEFAULT)) == NULL) {
			(void) bunyan_error(log, "No memory for IKE ID",
			    BUNYAN_T_END);
			return (NULL);
		}
		(void) memcpy(buf, data, datalen++);
		data = buf;
		break;
	case IKEV2_ID_IPV6_ADDR:
		cidtype = CFG_AUTH_ID_IPV6;
		if (datalen != sizeof (in6_addr_t)) {
			(void) bunyan_warn(log, "ID payload length mismatch",
			    BUNYAN_T_STRING, "idtype", idtstr,
			    BUNYAN_T_UINT32, "len", datalen,
			    BUNYAN_T_UINT32, "expected",
			    (uint32_t)sizeof (in6_addr_t), BUNYAN_T_END);
			return (NULL);
		}
		break;
	case IKEV2_ID_DER_ASN1_DN:
		cidtype = CFG_AUTH_ID_DN;
		break;
	case IKEV2_ID_DER_ASN1_GN:
		cidtype = CFG_AUTH_ID_GN;
		break;
	case IKEV2_ID_KEY_ID:
	case IKEV2_ID_FC_NAME:
		(void) bunyan_warn(log, "Unsupported IKE ID type",
		    BUNYAN_T_STRING, "idtype", idtstr,
		    BUNYAN_T_END);
		return (NULL);
	}

	cid = config_id_new(cidtype, data, datalen);
	if (buf != NULL)
		umem_free(buf, datalen);

	return (cid);
}

/*
 * If we are the initiator and the responder failed to authenticate, we
 * must immediately start a new INFORMATIONAL exchange with the
 * AUTHENTICATION_FAILED notification as it's contents (RFC7296 2.21.2).
 */

/* Nothing to process with the acknowledgement */
static void
ikev2_auth_failed_reply(ikev2_sa_t *restrict i2sa __unused,
    pkt_t *restrict resp __unused, void *arg __unused)
{
	NOTE(ARGUNUSED(i2sa))
	NOTE(ARGUNUSED(resp))
	NOTE(ARGUNUSED(arg))
}

/* Kick off the INFORMATINOAL exchange */
static void
ikev2_auth_failed(ikev2_sa_t *i2sa)
{
	pkt_t *msg = ikev2_pkt_new_exchange(i2sa, IKEV2_EXCH_INFORMATIONAL);

	i2sa->flags |= I2SA_CONDEMNED;

	if (msg == NULL) {
		(void) bunyan_error(log,
		    "No memory to send AUTHENTICATION_FAILED notification",
		    BUNYAN_T_END);
		return;
	}

	VERIFY(ikev2_add_notify(msg, IKEV2_N_AUTHENTICATION_FAILED));
	(void) ikev2_send_req(msg, ikev2_auth_failed_reply, NULL);
}

/*
 * We've received an AUTHENTICATION_FAILED notification in an INFORMATIONAL
 * exchange
 */
boolean_t
ikev2_auth_failed_resp(pkt_t *restrict req, pkt_t *restrict resp __unused)
{
	NOTE(ARGUNUSED(resp))
	ikev2_sa_t *i2sa = req->pkt_sa;

	(void) bunyan_warn(log,
	    "Peer rejected our authentication attempt", BUNYAN_T_END);

	ikev2_sa_delete_children(i2sa);
	req->pkt_sa->flags |= I2SA_CONDEMNED;

	/* Send an empty response to acknowledge we received the message */
	return (B_TRUE);
}

static size_t
get_authlen(const ikev2_sa_t *sa)
{
	const char *authstr = ikev2_auth_type_str(sa->authmethod);

	switch (sa->authmethod) {
	case IKEV2_AUTH_NONE:
		return (0);
	case IKEV2_AUTH_SHARED_KEY_MIC:
		return (ikev2_prf_outlen(sa->prf));
	case IKEV2_AUTH_RSA_SIG:
		/* XXX: This may need to vary based on the cert used */
		return (SHA1_DIGEST_LENGTH);
	case IKEV2_AUTH_DSS_SIG:
		return (SHA1_DIGEST_LENGTH);
	case IKEV2_AUTH_ECDSA_256:
		return (SHA256_DIGEST_LENGTH);
	case IKEV2_AUTH_ECDSA_384:
		return (SHA384_DIGEST_LENGTH);
	case IKEV2_AUTH_ECDSA_512:
		return (SHA512_DIGEST_LENGTH);
	case IKEV2_AUTH_GSPM:
		(void) bunyan_error(log,
		    "IKE SA authentication method not yet implemented",
		    BUNYAN_T_STRING, "authmethod", authstr,
		    BUNYAN_T_END);
		return (0);
	}
	return (0);
}
