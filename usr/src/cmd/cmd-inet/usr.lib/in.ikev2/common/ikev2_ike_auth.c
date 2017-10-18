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
#include "worker.h"

static void ikev2_ike_auth_inbound_init(pkt_t *);
static void ikev2_ike_auth_inbound_resp(pkt_t *);
static boolean_t ikev2_auth_failed(const pkt_t *);
static boolean_t ikev2_auth(pkt_t *, boolean_t);
static boolean_t create_psk(ikev2_sa_t *);
static boolean_t calc_auth(ikev2_sa_t *restrict, boolean_t,
    const uint8_t *restrict, size_t, uint8_t *restrict, size_t);
static boolean_t add_id(pkt_t *, config_id_t *id, boolean_t);
static boolean_t i2id_is_equal(const pkt_payload_t *, const config_id_t *);

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
	config_rule_t *rule = sa->i2sa_rule;
	pkt_t *resp = NULL;
	pkt_payload_t *id_r = NULL;

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

	/* The initiator may optionally equest we send a specific ID */
	if ((id_r = pkt_get_payload(req, IKEV2_PAYLOAD_IDr, NULL)) != NULL) {
		/*
		 * If the initiator is requesting an ID that is not the one
		 * specified in the rule, for now we'll note the difference
		 * and still respond, using our configured id.
		 */
		if (!i2id_is_equal(id_r, rule->rule_local_id)) {
			uint8_t idtype = *id_r->pp_ptr;
			char typebuf[IKEV2_ENUM_STRLEN];
			char idbuf[256] = { 0 };

			(void) bunyan_warn(sa->i2sa_log,
			    "Initiator requested ID other than ours",
			    BUNYAN_T_STRING, "idtype",
			    ikev2_id_type_str(idtype, typebuf,
			    sizeof (typebuf)),
			    BUNYAN_T_STRING, "id",
			    ikev2_id_str(id_r, idbuf, sizeof (idbuf)),
			    BUNYAN_T_END);
		}
	}

	if (!add_id(resp, rule->rule_local_id, B_FALSE))
		goto fail;
	/* XXX: Add CERT payloads */
	if (!ikev2_auth(req, B_FALSE))
		goto fail;

	ikev2_create_child_sa_inbound(req, resp);
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

	config_rule_t *rule = sa->i2sa_rule;
	pkt_t *req = ikev2_pkt_new_exchange(sa, IKEV2_EXCH_IKE_AUTH);

	/* We should have at least one ACQUIRE pending if we got this far */
	VERIFY(!list_is_empty(&sa->i2sa_pending));

	if (req == NULL)
		goto fail;
	if (!ikev2_add_sk(req))
		goto fail;
	if (!add_id(req, rule->rule_local_id, B_TRUE))
		goto fail;

	/* XXX: Add any CERT or CERTREQ payloads */

	/*
	 * XXX: We can optionally add _1_ IDr payload to indicate a preferred
	 * ID for the responder to use.  Since we currently support multiple
	 * remote ids in a rule, not sure there's any benefit to do this.
	 * For now, we will elect to no do this.
	 */
	if (!ikev2_auth(req, B_FALSE))
		goto fail;

	ikev2_create_child_sa_outbound(sa, req);
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

	ikev2_sa_t *sa = resp->pkt_sa;
	config_id_t **remote_ids = sa->i2sa_rule->rule_remote_id;
	pkt_payload_t *id_r = NULL;
	boolean_t match = B_FALSE;

	/* XXX: check for error NOTIFICATIONS */

	if (ikev2_auth(resp, B_TRUE))
		goto fail;

	for (size_t i = 0; remote_ids != NULL && remote_ids[i] != NULL; i++) {
		if (i2id_is_equal(id_r, remote_ids[i])) {
			match = B_TRUE;
			break;
		}
	}
	if (!match && remote_ids != NULL) {
		ikev2_id_t *id = (ikev2_id_t *)id_r->pp_ptr;
		char typebuf[IKEV2_ENUM_STRLEN];
		char idbuf[128];

		(void) bunyan_error(sa->i2sa_log, "Unknown remote ID given",
		    BUNYAN_T_STRING, "idtype", ikev2_id_type_str(id->id_type,
		    typebuf, sizeof (typebuf)),
		    BUNYAN_T_STRING, "id", ikev2_id_str(id_r, idbuf,
		    sizeof (idbuf)),
		    BUNYAN_T_END);

		/* XXX: Create new informational exchange to delete IKE SA */
	}

	ikev2_create_child_sa_inbound(resp, NULL);

fail:
	/* TODO */
	ikev2_pkt_free(resp);
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
		if (sa->psk == CK_INVALID_HANDLE && !create_psk(sa)) {
			/* XXX: error */
			goto done;
		}
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
	default:
		INVALID("ss_family");
	}

	if (pe == NULL) {
		(void) bunyan_error(sa->i2sa_log,
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
add_id(pkt_t *pkt, config_id_t *id, boolean_t initiator)
{
	ikev2_sa_t *sa = pkt->pkt_sa;
	ikev2_id_type_t id_type = IKEV2_ID_FQDN; /* set default to quiet GCC */
	size_t idlen = 0;
	void *ptr = NULL;

	if (id == NULL) {
		switch (sa->laddr.ss_family) {
		case AF_INET:
			id_type = IKEV2_ID_IPV4_ADDR;
			idlen = sizeof (in_addr_t);
			ptr = &((struct sockaddr_in *)&sa->laddr)->sin_addr;
			break;
		case AF_INET6:
			id_type = IKEV2_ID_IPV6_ADDR;
			idlen = sizeof (in6_addr_t);
			ptr = &((struct sockaddr_in6 *)&sa->laddr)->sin6_addr;
			break;
		default:
			INVALID("ss_family");
		}
	} else if (id->cid_len == 0) {
		/* parsing should prevent this */
		INVALID("id->cid_len");
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
	}

	return (ikev2_add_id(pkt, initiator, id_type, ptr, idlen));
}

static boolean_t
i2id_is_equal(const pkt_payload_t *i2id, const config_id_t *cid)
{
	ikev2_id_t *i2idp = (ikev2_id_t *)i2id->pp_ptr;
	void *id = (void *)(i2idp + 1);
	size_t cidlen = cid->cid_len;
	size_t idlen = i2id->pp_len - sizeof (*i2idp);

	switch (cid->cid_type) {
	case CFG_AUTH_ID_DNS:
		if (i2idp->id_type != IKEV2_ID_FQDN)
			return (B_FALSE);
		/* Exclude trailing NUL in comparison */
		cidlen--;
		break;
	case CFG_AUTH_ID_EMAIL:
		if (i2idp->id_type != IKEV2_ID_RFC822_ADDR)
			return (B_FALSE);
		/* Exclude trailing NUL in comparison */
		cidlen--;
		break;
	case CFG_AUTH_ID_GN:
		if (i2idp->id_type != IKEV2_ID_DER_ASN1_GN)
			return (B_FALSE);
		break;
	case CFG_AUTH_ID_DN:
		if (i2idp->id_type != IKEV2_ID_DER_ASN1_DN)
			return (B_FALSE);
		break;
	case CFG_AUTH_ID_IPV4:
	case CFG_AUTH_ID_IPV4_PREFIX:
	case CFG_AUTH_ID_IPV4_RANGE:
		if (i2idp->id_type != IKEV2_ID_IPV4_ADDR)
			return (B_FALSE);
		break;
	case CFG_AUTH_ID_IPV6:
	case CFG_AUTH_ID_IPV6_PREFIX:
	case CFG_AUTH_ID_IPV6_RANGE:
		if (i2idp->id_type != IKEV2_ID_IPV6_ADDR)
			return (B_FALSE);
	}
	if (cid->cid_len != idlen)
		return (B_FALSE);
	if (memcmp(id, cid->cid_data, idlen) != 0)
		return (B_FALSE);

	return (B_TRUE);
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
