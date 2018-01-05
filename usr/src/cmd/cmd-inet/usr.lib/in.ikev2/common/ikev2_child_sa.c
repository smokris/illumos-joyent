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

#include <ipsec_util.h>
#include <strings.h>
#include <sys/debug.h>
#include "config.h"
#include "dh.h"
#include "ikev2.h"
#include "ikev2_common.h"
#include "ikev2_enum.h"
#include "ikev2_pkt.h"
#include "ikev2_proto.h"
#include "ikev2_sa.h"
#include "pfkey.h"
#include "pkcs11.h"
#include "prf.h"
#include "ts.h"
#include "worker.h"

#define	IS_AUTH(args) ((args)->i2a_is_auth)
#define	INITIATOR(args) ((args)->i2a_child[0].csa_child->i2c_initiator)
#define	TRANSPORT_MODE(args) ((args)->i2a_child[0].csa_child->i2c_transport)

static boolean_t ikev2_create_child_sa_init_common(ikev2_sa_t *restrict,
    pkt_t *restrict req, ikev2_sa_args_t *restrict);
static boolean_t ikev2_create_child_sa_resp_common(pkt_t *restrict,
    pkt_t *restrict, ikev2_sa_args_t *restrict);

static void ikev2_create_child_sa_init_resp(ikev2_sa_t *restrict,
    pkt_t *restrict, void *restrict);
static void ikev2_rekey_child_sa_init_resp(ikev2_sa_t *restrict,
    pkt_t *restrict, void *restrict);
static void ikev2_create_child_sa_init_resp_common(ikev2_sa_t *restrict,
    pkt_t *restrict, void *restrict);

static boolean_t ikev2_sa_from_acquire(pkt_t *restrict, parsedmsg_t *restrict,
    uint32_t, ikev2_dh_t);
static boolean_t get_resp_policy(pkt_t *restrict, boolean_t,
    ikev2_sa_args_t *restrict);
static boolean_t ikev2_sa_select_acq(parsedmsg_t *restrict, ikev2_dh_t,
    pkt_t *restrict, ikev2_sa_match_t *restrict);
static boolean_t ikev2_sa_check_acquire(parsedmsg_t *restrict, ikev2_dh_t,
    pkt_t *restrict, ikev2_sa_match_t *restrict);

static boolean_t add_ts_init(pkt_t *restrict, parsedmsg_t *restrict);
static boolean_t add_ts_resp(pkt_t *restrict, const ts_t *restrict,
    const ts_t *restrict);
static void resp_set_child_addr(ikev2_child_sa_t *restrict,
    ikev2_child_sa_t *restrict, struct sockaddr_storage *restrict, uint8_t,
    boolean_t);
static boolean_t add_ts_resp_one(pkt_payload_t *restrict,
    sadb_address_t *restrict, pkt_t *restrict,
    struct sockaddr_storage *restrict, uint8_t *restrict);

static boolean_t generate_keys(ikev2_sa_t *restrict, ikev2_sa_args_t *);
static boolean_t create_keymat(ikev2_sa_t *restrict, boolean_t,
    uint8_t *restrict, size_t,
    uint8_t *restrict, size_t, prfp_t *restrict);
static boolean_t ikev2_create_child_sas(ikev2_sa_t *restrict,
    ikev2_sa_args_t *restrict);
static void ikev2_save_child_results(ikev2_child_sa_state_t *restrict,
    const ikev2_sa_match_t *restrict);
static void ikev2_save_child_ts(ikev2_child_sa_state_t *restrict,
    const ts_t *restrict, const ts_t *restrict);
static void ikev2_set_child_type(ikev2_child_sa_state_t *restrict, boolean_t,
    ikev2_spi_proto_t);

static void check_natt_addrs(pkt_t *restrict, boolean_t);
static sadb_address_t *get_sadb_addr(parsedmsg_t *, boolean_t);
static void ikev2_rekey_delete_old_kids(ikev2_sa_t *restrict,
    ikev2_sa_args_t *restrict);

/*
 * We are the initiator for an IKE_AUTH exchange, and are performing the
 * child SA creation that occurs during the IKE AUTH exchange.
 */
boolean_t
ikev2_create_child_sa_init_auth(ikev2_sa_t *restrict sa, pkt_t *restrict req)
{
	ikev2_sa_args_t *csa = sa->sa_init_args;

	VERIFY(IS_WORKER);
	VERIFY(!MUTEX_HELD(&sa->i2sa_queue_lock));
	VERIFY(MUTEX_HELD(&sa->i2sa_lock));

	VERIFY3U(pkt_header(req)->exch_type, ==, IKEV2_EXCH_IKE_AUTH);
	VERIFY(sa->flags & I2SA_INITIATOR);

	csa->i2a_is_auth = B_TRUE;
	csa->i2a_dh = IKEV2_DH_NONE;

	return (ikev2_create_child_sa_init_common(sa, req, csa));
}

/* We are the initiator in a CREATE_CHILD_SA exchange */
void
ikev2_create_child_sa_init(ikev2_sa_t *restrict sa, parsedmsg_t *restrict pmsg)
{
	ikev2_sa_args_t *csa = NULL;
	pkt_t *req = NULL;

	VERIFY(IS_WORKER);
	VERIFY(!MUTEX_HELD(&sa->i2sa_queue_lock));
	VERIFY(MUTEX_HELD(&sa->i2sa_lock));

	/*
	 * This entry point into CREATE_CHILD_SA should only be for kernel
	 * originated ACQUIRES.
	 */
	VERIFY(PMSG_FROM_KERNEL(pmsg));

	/*
	 * We shouldn't try to initiate any other exchanges until we've
	 * authenticated.
	 */
	VERIFY(sa->flags & I2SA_AUTHENTICATED);

	(void) bunyan_debug(log, "Starting CREATE_CHILD_SA exchange",
	    BUNYAN_T_END);

	if ((csa = ikev2_sa_args_new(B_TRUE)) == NULL) {
		(void) bunyan_error(log,
		    "No memory to perform CREATE_CHILD_SA exchange",
		    BUNYAN_T_END);
		goto fail;
	}

	csa->i2a_i2sa = sa;
	csa->i2a_pmsg = pmsg;
	csa->i2a_sadb_msg = pmsg->pmsg_samsg;
	csa->i2a_dh = sa->i2sa_rule->rule_p2_dh;

	req = ikev2_pkt_new_exchange(sa, IKEV2_EXCH_CREATE_CHILD_SA);
	if (req == NULL)
		goto fail;

	if (!ikev2_create_child_sa_init_common(sa, req, csa)) {
		ikev2_pkt_free(req);
		goto fail;
	}

	if (!ikev2_send_req(req, ikev2_create_child_sa_init_resp, csa))
		goto fail;

	return;

fail:
	pfkey_send_error(pmsg->pmsg_samsg, ENOMEM);
	ikev2_sa_args_free(csa);
}

#ifdef notyet
/* We are the initiator in a CREATE_CHILD_SA exchange to rekey an AH/ESP SA */
void
ikev2_rekey_child_sa_init(ikev2_sa_t *restrict sa, parsedmsg_t *restrict pmsg)
{
	sadb_msg_t *samsg = pmsg->pmsg_samsg;
	sadb_sa_t *saext = (sadb_sa_t *)pmsg->pmsg_exts[SADB_EXT_SA];
	ikev2_sa_args_t *args = NULL;
	pkt_t *req = NULL;
	ikev2_child_sa_t *csa = NULL;
	ikev2_spi_proto_t satype = satype_to_ikev2(samsg->sadb_msg_satype);
	uint32_t spi = saext->sadb_sa_spi;
	boolean_t inbound = !!(saext->sadb_sa_flags & SADB_X_SAFLAGS_INBOUND);

	VERIFY(IS_WORKER);
	VERIFY(!MUTEX_HELD(&sa->i2sa_queue_lock));
	VERIFY(MUTEX_HELD(&sa->i2sa_lock));

	/*
	 * We should only initiate a child SA rekey in response to a kernel
	 * message.
	 */
	VERIFY(PMSG_FROM_KERNEL(pmsg));

	/*
	 * We shouldn't try to initiate any other exchanges until we've
	 * authenticated.
	 */
	VERIFY(sa->flags & I2SA_AUTHENTICATED);

	/* We must use the inbound SPI for the REKEY_SA notification */
	if ((csa = ikev2_sa_get_child(sa, spi, inbound)) != NULL) {
		if (!inbound) {
			if (csa->i2c_pair == NULL) {
				/* XXX: Log */
				parsedmsg_free(pmsg);
				return;
			}
			csa = csa->i2c_pair;
			spi = csa->i2c_spi;
		}
	} else {
		(void) bunyan_info(log,
		    "Received SADB_EXPIRE message for non-existent child SA; "
		    "ignoring",
		    BUNYAN_T_STRING, "satype", ikev2_spi_str(satype),
		    BUNYAN_T_STRING, "spi", enum_printf("%" PRIx32, spi),
		    BUNYAN_T_END);
		parsedmsg_free(pmsg);
		return;
	}
	args->i2a_old_csa = csa;

	(void) bunyan_debug(log, "Starting rekey CREATE_CHILD_SA exchange",
	    BUNYAN_T_STRING, "satype", ikev2_spi_str(satype),
	    BUNYAN_T_STRING, "spi", enum_printf("%" PRIx32, spi),
	    BUNYAN_T_END);

	if ((args = ikev2_sa_args_new(B_TRUE)) == NULL) {
		(void) bunyan_error(log,
		    "No memory to perform CREATE_CHILD_SA exchange",
		    BUNYAN_T_END);
		goto fail;
	}

	args->i2a_i2sa = sa;
	args->i2a_pmsg = pmsg;
	args->i2a_sadb_msg = pmsg->pmsg_samsg;
	args->i2a_dh = sa->i2sa_rule->rule_p2_dh;
	args->i2a_old_csa = csa;

	req = ikev2_pkt_new_exchange(sa, IKEV2_EXCH_CREATE_CHILD_SA);
	if (req == NULL)
		goto fail;

	VERIFY(ikev2_add_notify_full(req, satype, spi, IKEV2_N_REKEY_SA,
	    NULL, 0));

	if (!ikev2_create_child_sa_init_common(sa, req, args)) {
		ikev2_pkt_free(req);
		goto fail;
	}

	if (!ikev2_send_req(req, ikev2_rekey_child_sa_init_resp, args))
		goto fail;

	return;

fail:
	/* XXX: Do we need to reply to SADB_EXPIRE messages if we failed? */
	pfkey_send_error(pmsg->pmsg_samsg, ENOMEM);
	ikev2_sa_args_free(args);
}
#endif

/* We are the initiator, shared bits for IKE_AUTH and CREATE_CHILD_SA */
static boolean_t
ikev2_create_child_sa_init_common(ikev2_sa_t *restrict sa, pkt_t *restrict req,
    ikev2_sa_args_t *restrict csa)
{
	parsedmsg_t *pmsg = csa->i2a_pmsg;
	ikev2_dh_t dh = csa->i2a_dh;
	ikev2_spi_proto_t proto;
	uint32_t spi = 0;
	uint8_t satype = csa->i2a_sadb_msg->sadb_msg_satype;
	boolean_t transport_mode = PMSG_IS_TRANSPORT(pmsg);

	csa->i2a_child[CSA_IN].csa_child->i2c_transport = transport_mode;
	csa->i2a_child[CSA_OUT].csa_child->i2c_transport = transport_mode;

	proto = satype_to_ikev2(satype);

	if (!pfkey_getspi(pmsg, satype, &spi)) {
		goto fail;
	}

	/* Stash until we get our reply */
	csa->i2a_spi = spi;
	csa->i2a_child[CSA_IN].csa_child->i2c_spi = spi;

	/* XXX: IPcomp (when we add support) */

	if (transport_mode && !ikev2_add_notify(req,
	    IKEV2_N_USE_TRANSPORT_MODE))
		goto fail;

	if (!ikev2_add_notify(req, IKEV2_N_ESP_TFC_PADDING_NOT_SUPPORTED))
		goto fail;

	if (!ikev2_add_notify(req, IKEV2_N_NON_FIRST_FRAGMENTS_ALSO))
		goto fail;

	if (!ikev2_sa_from_acquire(req, pmsg, spi, dh))
		goto fail;

	/*
	 * For the piggy-backed child SA in an IKE_AUTH exchange, the original
	 * nonces and DH keys from the IKE_SA_INIT packet are used instead of
	 * generating new ones.
	 */
	if (!IS_AUTH(csa)) {
		if (!ikev2_create_nonce(csa, B_TRUE, IKEV2_NONCE_DEFAULT))
			goto fail;
		if (!ikev2_add_nonce(req, csa->i2a_nonce_i,
		    csa->i2a_nonce_i_len))
			goto fail;

		if (csa->i2a_dh != IKEV2_DH_NONE &&
		    !ikev2_add_ke(req, csa->i2a_dh, csa->i2a_pubkey))
			goto fail;
	}

	if (!add_ts_init(req, pmsg))
		goto fail;

	return (B_TRUE);

fail:
	(void) pfkey_delete(satype, spi, pmsg->pmsg_sau, pmsg->pmsg_dau,
	    B_FALSE);
	return (B_FALSE);
}

/*
 * We are the responder, we are doing the child SA creation that
 * occurs during an IKE_AUTH exchange.
 */
boolean_t
ikev2_create_child_sa_resp_auth(pkt_t *restrict req, pkt_t *restrict resp)
{
	ikev2_sa_args_t *csa = req->pkt_sa->sa_init_args;

	VERIFY3U(pkt_header(resp)->exch_type, ==, IKEV2_EXCH_IKE_AUTH);

	csa->i2a_is_auth = B_TRUE;

	/*
	 * The create child SA operation within an IKE_AUTH exchange cannot
	 * do a second DH keyexchange.  Instead the exchanged key from the
	 * IKE_SA_INIT exchange is re-used only for this child SA.
	 */
	csa->i2a_dh = IKEV2_DH_NONE;

	return (ikev2_create_child_sa_resp_common(req, resp, csa));
}

/* We are the responder in a CREATE_CHILD_SA exchange */
void
ikev2_create_child_sa_resp(pkt_t *restrict req)
{
	ikev2_sa_t *i2sa = req->pkt_sa;
	pkt_t *resp = NULL;
	ikev2_sa_args_t *csa = NULL;

	if (!(i2sa->flags & I2SA_AUTHENTICATED)) {
		(void) bunyan_info(log,
		    "Received CREATE_CHILD_SA request on unauthenciated IKE SA;"
		    " discarding", BUNYAN_T_END);
		return;
	}

	if ((resp = ikev2_pkt_new_response(req)) == NULL) {
		(void) bunyan_error(log,
		    "No memory to respond to CREATE_CHILD_SA request",
		    BUNYAN_T_END);
		return;
	}

	if ((csa = ikev2_sa_args_new(B_TRUE)) == NULL) {
		/*
		 * There's no specific error notification for this situation,
		 * however NO_PROPOSAL_CHOSEN is despite it's name a general
		 * catch-all 'error' notification, so we use that.
		 */
		(void) bunyan_error(log,
		    "No memory to perform CREATE_CHILD_SA exchange; "
		    "sending NO_PROPOSAL_CHOSEN", BUNYAN_T_END);

		VERIFY(ikev2_add_notify(resp, IKEV2_N_NO_PROPOSAL_CHOSEN));
		(void) ikev2_send_resp(resp);
		return;
	}

	/*
	 * TODO: Check if REKEY_SA notification is present, if so, delete old
	 * SAs after we send our response back (we get no acknowledgement of
	 * our reply, so we just have to do it.
	 *
	 * Also, check if we have have initiated a rekey request, and do the
	 * 'lowest nonce wins' bit form RFC7296 2.8.1
	 */
	csa->i2a_dh = i2sa->i2sa_rule->rule_p2_dh;

	if (ikev2_create_child_sa_resp_common(req, resp, csa))
		(void) ikev2_send_resp(resp);
	else
		ikev2_pkt_free(resp);

	ikev2_sa_args_free(csa);
}

/*
 * We are the responder (shared bits between IKE_AUTH and CREATE_CHILD_SA).
 * A fatal error (where we cannot continue) return B_FALSE.  Otherwise
 * return B_TRUE if we should send the response.
 */
static boolean_t
ikev2_create_child_sa_resp_common(pkt_t *restrict req, pkt_t *restrict resp,
    ikev2_sa_args_t *restrict csa)
{
	ikev2_sa_t *sa = req->pkt_sa;
	parsedmsg_t *pmsg = NULL;
	ikev2_spi_proto_t satype = IKEV2_PROTO_NONE;
	uint32_t spi = 0;
	ikev2_sa_match_t match = { 0 };
	ts_t ts_i = { 0 };
	ts_t ts_r = { 0 };
	boolean_t narrowed = B_FALSE;
	boolean_t transport_mode = B_FALSE;

	if (pkt_get_notify(req, IKEV2_N_USE_TRANSPORT_MODE, NULL) != NULL)
		transport_mode = B_TRUE;

	csa->i2a_child[CSA_IN].csa_child->i2c_transport = transport_mode;
	csa->i2a_child[CSA_OUT].csa_child->i2c_transport = transport_mode;

	if (csa->i2a_is_auth)
		check_natt_addrs(req, transport_mode);

	if (!get_resp_policy(req, transport_mode, csa))
		goto fail;

	if ((pmsg = csa->i2a_pmsg) == NULL) {
		if (!ikev2_add_notify(resp, IKEV2_N_TS_UNACCEPTABLE))
			goto fail;
		return (B_TRUE);
	}
	csa->i2a_sadb_msg = pmsg->pmsg_samsg;

	if (!ikev2_sa_select_acq(pmsg, csa->i2a_dh, req, &match)) {
		(void) bunyan_info(log,
		    "No proposals matched from initiator",
		    BUNYAN_T_END);

		goto reply_with_fail;
	}
	satype = match.ism_satype;

	if (!IS_AUTH(csa) && ikev2_get_dhgrp(req) != match.ism_dh) {
		if (!ikev2_invalid_ke(resp, match.ism_dh))
			goto fail;
		return (B_TRUE);
	}

	sadb_to_ts(get_sadb_addr(pmsg, B_FALSE), &ts_i);
	sadb_to_ts(get_sadb_addr(pmsg, B_TRUE), &ts_r);

	if (!ts_negotiate(req, &ts_i, &ts_r, &narrowed)) {
		if (!ikev2_add_notify(resp, IKEV2_N_TS_UNACCEPTABLE))
			goto fail;
		return (B_TRUE);
	}

	if (!pfkey_getspi(pmsg, satype, &spi))
		goto reply_with_fail;

	csa->i2a_child[CSA_IN].csa_child->i2c_spi = spi;
	ikev2_set_child_type(csa->i2a_child, B_FALSE, satype);
	ikev2_save_child_results(csa->i2a_child, &match);
	ikev2_save_child_ts(csa->i2a_child, &ts_i, &ts_r);

	if (!IS_AUTH(csa)) {
		if (!ikev2_create_nonce(csa, B_FALSE, IKEV2_NONCE_DEFAULT))
			goto reply_with_fail;
		ikev2_save_nonce(csa, req);

		if (!dh_genpair(csa->i2a_dh, &csa->i2a_pubkey,
		    &csa->i2a_privkey))
			goto reply_with_fail;
		if (!ikev2_ke(csa, req))
			goto reply_with_fail;
	}

	if (!generate_keys(sa, csa))
		goto reply_with_fail;

	if (!ikev2_create_child_sas(sa, csa))
		goto reply_with_fail;

	if (transport_mode &&
	    !ikev2_add_notify(resp, IKEV2_N_USE_TRANSPORT_MODE))
		goto fail;

	/* We currently don't support TFC PADDING */
	if (!ikev2_add_notify(resp, IKEV2_N_ESP_TFC_PADDING_NOT_SUPPORTED))
		goto fail;

	/* and we always include non-first fragments */
	if (!ikev2_add_notify(resp, IKEV2_N_NON_FIRST_FRAGMENTS_ALSO))
		goto fail;

	if (!ikev2_sa_add_result(resp, &match, spi))
		goto fail;

	/*
	 * For the piggy-backed child SA in an IKE_AUTH exchange, the original
	 * nonces and DH keys from the IKE_SA_INIT packet are used instead of
	 * generating new ones.
	 */
	if (!IS_AUTH(csa)) {
		if (!ikev2_add_nonce(resp, csa->i2a_nonce_r,
		    csa->i2a_nonce_r_len))
			goto fail;

		if (csa->i2a_dh != IKEV2_DH_NONE &&
		    !ikev2_add_ke(resp, csa->i2a_dh, csa->i2a_pubkey))
			goto fail;
	}

	if (!add_ts_resp(resp, &ts_i, &ts_r))
		goto fail;

	if (narrowed && !ikev2_add_notify(resp, IKEV2_N_ADDITIONAL_TS_POSSIBLE))
		goto fail;

	/* XXX: Other notifications? */

	return (B_TRUE);

reply_with_fail:
	(void) bunyan_info(log,
	    "Sending NO_PROPOSAL_CHOSEN due to error during processing",
	    BUNYAN_T_END);
	if (ikev2_add_notify(resp, IKEV2_N_NO_PROPOSAL_CHOSEN))
		return (B_TRUE);

	(void) bunyan_error(log,
	    "Could not add NO_PROPOSAL_CHOSEN notification to reply",
	    BUNYAN_T_END);

fail:
	(void) pfkey_delete(satype, spi, pmsg->pmsg_sau, pmsg->pmsg_dau,
	    B_FALSE);
	return (B_FALSE);
}

/*
 * We are initiator, this is the response from the peer.
 */
void
ikev2_create_child_sa_init_resp_auth(ikev2_sa_t *restrict i2sa,
    pkt_t *restrict resp, void *restrict arg)
{
	ikev2_create_child_sa_init_resp_common(i2sa, resp, arg);
}

static void
ikev2_create_child_sa_init_resp(ikev2_sa_t *restrict i2sa, pkt_t *restrict resp,
    void *restrict arg)
{
	ikev2_create_child_sa_init_resp_common(i2sa, resp, arg);
	ikev2_sa_args_free(arg);
}

#ifdef notyet
static void
ikev2_rekey_child_sa_init_resp(ikev2_sa_t *restrict i2sa, pkt_t *restrict resp,
    void *restrict arg)
{
	ikev2_sa_args_t *sa_arg = arg;

	/*
	 * TODO: Check if peer initiated a rekey on the same pair of SAs,
	 * check nonce values and if our nonce values were larger, delete
	 * the pair we created (RFC7296 2.8.1)
	 */
	ikev2_create_child_sa_init_resp_common(i2sa, resp, arg);
	ikev2_sa_args_free(arg);
}
#endif

static void
ikev2_create_child_sa_init_resp_common(ikev2_sa_t *restrict i2sa,
    pkt_t *restrict resp, void *restrict arg)
{
	ikev2_sa_args_t *csa = arg;
	parsedmsg_t *pmsg = csa->i2a_pmsg;
	pkt_notify_t *invalid_ke = NULL;
	ikev2_sa_match_t match = { 0 };
	ts_t ts_i = { 0 };
	ts_t ts_r = { 0 };
	boolean_t narrowed = B_FALSE;

	if (resp == NULL) {
		uint8_t satype = pmsg->pmsg_samsg->sadb_msg_satype;
		if (PMSG_FROM_KERNEL(pmsg))
			pfkey_send_error(pmsg->pmsg_samsg, ETIME);

		(void) pfkey_delete(satype, csa->i2a_spi,
		    pmsg->pmsg_sau, pmsg->pmsg_dau, B_FALSE);

		return;
	}

	if (pkt_get_notify(resp, IKEV2_N_NO_PROPOSAL_CHOSEN, NULL) != NULL) {
		(void) bunyan_info(log,
		    "Remote peer responded with NO_PROPOSAL_CHOSEN",
		    BUNYAN_T_END);
		goto remote_fail;
	}

	if (pkt_get_notify(resp, IKEV2_N_TS_UNACCEPTABLE, NULL) != NULL) {
		(void) bunyan_info(log,
		    "Remote peer responded to TS_UNACCEPTABLE",
		    BUNYAN_T_END);
		goto remote_fail;
	}

	if ((invalid_ke = pkt_get_notify(resp, IKEV2_N_INVALID_KE_PAYLOAD,
	    NULL)) != NULL) {
		if (invalid_ke->pn_len < sizeof (uint16_t)) {
			(void) bunyan_warn(log,
			    "Received INVALID_KE_PAYLOAD notification with an "
			    "invalid dhgrp payload", BUNYAN_T_END);
			goto remote_fail;
		}

		/*
		 * Currently, we only support specifying a single DH group
		 * for additional non-IKE child SAs.  If we allow specifing
		 * multiple P2 DH groups in a rule, we could optionally
		 * elect to perform a new CREATE_CHILD_SA exchange on this
		 * failure if the requested group still complies with our
		 * policy.
		 */
		uint16_t grp = BE_IN16(invalid_ke->pn_ptr);

		(void) bunyan_warn(log,
		    "Policy mismatch: peer sent INVALID_KE_PAYLOAD "
		    "notification",
		    BUNYAN_T_STRING, "dhgrp", ikev2_dh_str(grp),
		    BUNYAN_T_END);
		goto remote_fail;
	}

	if (!ikev2_sa_check_acquire(pmsg, csa->i2a_dh, resp, &match)) {
		(void) bunyan_warn(log,
		    "Peer tried to select a transform not in the original"
		    "proposed set", BUNYAN_T_END);
		goto fail;
	}

	/*
	 * This is not fatal -- the traffic we wanted to send can be sent,
	 * but the responder has chosen a subset of our policy, so we want
	 * to log this.
	 */
	if (pkt_get_notify(resp,
	    IKEV2_N_ADDITIONAL_TS_POSSIBLE, NULL) != NULL) {
		(void) bunyan_warn(log,
		    "Policy mismatch with peer", BUNYAN_T_END);
		/* XXX: Log more details */
	}

	if (csa->i2a_is_auth)
		check_natt_addrs(resp, TRANSPORT_MODE(csa));

	sadb_to_ts(get_sadb_addr(pmsg, B_TRUE), &ts_i);
	sadb_to_ts(get_sadb_addr(pmsg, B_FALSE), &ts_r);

	if (!ts_negotiate(resp, &ts_i, &ts_r, &narrowed)) {
		(void) bunyan_warn(log,
		    "Responder sent traffic selectors not in our policy",
		    BUNYAN_T_END);
		goto fail;
	}

	ikev2_set_child_type(csa->i2a_child, B_TRUE, match.ism_satype);
	ikev2_save_child_results(csa->i2a_child, &match);
	ikev2_save_child_ts(csa->i2a_child, &ts_i, &ts_r);

	if (!IS_AUTH(csa)) {
		ikev2_save_nonce(csa, resp);

		if (!ikev2_ke(csa, resp))
			goto fail;
	}

	if (!generate_keys(i2sa, csa))
		goto fail;

	if (!ikev2_create_child_sas(i2sa, csa))
		goto fail;

	return;

fail:
	/*
	 * TODO: If the creation of our child SAs fails for some reason, we
	 * probably want to do an INFORMATIONAL exchange for the peer to delete
	 * the ones they just created.  While we normally decouple the IPsec
	 * SAs (so that if in.ikev2d exits, the IPsec SAs can persist through
	 * the end of their lifetime, or until in.ikev2d is restarted and it
	 * receives an INITIAL_CONTACT notification), in this situation we
	 * already know that we will not be able to send traffic, so there
	 * is no point in the peer keeping their IPsec SAs to us around.
	 */
	;

remote_fail:
	if (PMSG_FROM_KERNEL(pmsg))
		pfkey_send_error(pmsg->pmsg_samsg, EINVAL);
}

static void ikev2_hard_expire_reply(ikev2_sa_t *restrict, pkt_t *restrict,
    void *restrict);

void
ikev2_hard_expire(ikev2_sa_t *restrict i2sa, parsedmsg_t *pmsg)
{
	sadb_sa_t *saext = (sadb_sa_t *)pmsg->pmsg_exts[SADB_EXT_SA];
	ikev2_child_sa_t *csa = NULL;
	pkt_t *req = NULL;
	uint64_t spi = 0;
	ikev2_spi_proto_t satype;

	if (saext == NULL) {
		(void) bunyan_info(log,
		    "Received an SADB_EXPIRE message without an SA extension",
		    BUNYAN_T_END);
		goto fail;
	}

	/*
	 * Since we control the lifetimes on our end, we always set both
	 * SAs in a pair to the same lifetime, so they should expire at
	 * effectively the same time (since each SA is created in a separate
	 * pf_key(7P) message, there is possibly a small delay that we can
	 * ignore).  We must only send the outbound (to us) SPIs in a delete
	 * request, so we ignore hard expires of inbound SAs
	 */
	if (saext->sadb_sa_flags & SADB_X_SAFLAGS_INBOUND) {
		parsedmsg_free(pmsg);
		return;
	}

	satype = satype_to_ikev2(pmsg->pmsg_samsg->sadb_msg_satype);
	spi = saext->sadb_sa_spi;

	csa = ikev2_sa_get_child(i2sa, spi, B_FALSE);
	if (csa == NULL) {
		/*
		 * It (for now at least) appears possible there could be a small
		 * race where the peer causes us to delete an SA, but a hard
		 * expire message still ends up being queued.  There's no harm
		 * if it's already deleted, so we just log it.
		 */
		(void) bunyan_info(log,
		    "Received an SADB_EXPIRE message for a non-existent SA",
		    BUNYAN_T_STRING, "satype", ikev2_spi_str(satype),
		    BUNYAN_T_STRING, "spi", enum_printf("%" PRIx64, spi),
		    BUNYAN_T_END);

		goto fail;
	}
	csa->i2c_moribund = B_TRUE;

	req = ikev2_pkt_new_exchange(i2sa, IKEV2_EXCH_INFORMATIONAL);
	if (req == NULL)
		goto fail;

	/* This is the second payload, it should fit */
	VERIFY(ikev2_add_delete(req, satype, &spi, 1));

	parsedmsg_free(pmsg);
	pmsg = NULL;

	if (!ikev2_send_req(req, ikev2_hard_expire_reply, csa))
		goto fail;

	return;

fail:
	ikev2_pkt_free(req);
	parsedmsg_free(pmsg);
}

void
ikev2_handle_delete(ikev2_sa_t *restrict i2sa, pkt_payload_t *restrict delpay,
    pkt_t *restrict resp)
{
	VERIFY3U(delpay->pp_type, ==, IKEV2_PAYLOAD_DELETE);
	ikev2_delete_t *del = (ikev2_delete_t *)delpay->pp_ptr;
	uint32_t *spiptr = (uint32_t *)(del + 1);
	uint64_t *spiresp = NULL;
	struct sockaddr_storage src = { 0 };
	struct sockaddr_storage dst = { 0 };
	sockaddr_u_t srcu = { .sau_ss = &src };
	sockaddr_u_t dstu = { .sau_ss = &dst };
	ikev2_spi_proto_t i2satype = del->del_protoid;
	uint16_t nspi = BE_IN16(&del->del_nspi);
	uint16_t nspiresp = 0;
	uint8_t satype = 0;
	uint8_t spilen = del->del_spisize;

	switch (i2satype) {
	case IKEV2_PROTO_NONE:
	case IKEV2_PROTO_FC_ESP_HEADER:
	case IKEV2_PROTO_FC_CT_AUTH:
	case IKEV2_PROTO_IKE:
		(void) bunyan_info(log,
		    "Unsupported SA type in DELETE payload",
		    BUNYAN_T_STRING, "satype", ikev2_spi_str(i2satype),
		    BUNYAN_T_END);
		return;
	case IKEV2_PROTO_AH:
	case IKEV2_PROTO_ESP:
		if (spilen != sizeof (uint32_t)) {
			(void) bunyan_error(log,
			    "Unexpected SPI size in DELETE payload",
			    BUNYAN_T_UINT32, "spisize", (uint32_t)spilen,
			    BUNYAN_T_UINT32, "expected",
			    (uint32_t)sizeof (uint32_t), BUNYAN_T_END);
			return;
		}
		satype = ikev2_to_satype(del->del_protoid);
		break;
	}

	spiresp = umem_calloc(nspi, sizeof (uint64_t), UMEM_DEFAULT);
	if (spiresp == NULL) {
		(void) bunyan_error(log, "No memory for DELETE response",
		    BUNYAN_T_END);
		(void) ikev2_add_notify(resp, IKEV2_N_TEMPORARY_FAILURE);
		return;
	}

	/* The SPIs in DELETE payloads are always inbound */
	sockaddr_copy(SSTOSA(&i2sa->raddr), &src, B_FALSE);
	sockaddr_copy(SSTOSA(&i2sa->laddr), &dst, B_FALSE);

	for (uint16_t i = 0; i < nspi; i++, spiptr++) {
		ikev2_child_sa_t *csa = NULL;
		uint32_t spi = BE_IN32(spiptr);

		csa = ikev2_sa_get_child(i2sa, spi, B_TRUE);
		if (csa == NULL) {
			(void) ikev2_add_notify_full(resp, i2satype, spi,
			    IKEV2_N_CHILD_SA_NOT_FOUND, NULL, 0);
			(void) bunyan_info(log,
			    "SPI not found in DELETE payload",
			    BUNYAN_T_STRING, "spi",
			    enum_printf("%" PRIx32, spi), BUNYAN_T_END);
			continue;
		}

		/*
		 * RFC7296 1.4.1 If we've already sent a DELETE request
		 * (which from our perspective be the outbound aka paired
		 * SPI), we don't send the SPI back in a delete payload
		 */
		if (csa->i2c_pair != NULL && !csa->i2c_moribund) {
			ikev2_child_sa_t *pair = csa->i2c_pair;

			spiresp[nspiresp++] = pair->i2c_spi;
			ikev2_sa_delete_child(i2sa, pair);
		}

		ikev2_sa_delete_child(i2sa, csa);
		(void) pfkey_delete(satype, spi, srcu, dstu, B_TRUE);
	}

	(void) ikev2_add_delete(resp, i2satype, spiresp, nspiresp);
	umem_cfree(spiresp, nspiresp, sizeof (uint64_t));
}

static void
ikev2_hard_expire_reply(ikev2_sa_t *restrict i2sa, pkt_t *restrict reply,
    void *restrict arg)
{
	ikev2_child_sa_t *csa = arg;

	/*
	 * The reply should at best only send back the SPI of the pairs we
	 * sent.  Since we already link our SPIs via the pair extension
	 * we really don't care about the SPIs sent back.
	 */
	if (csa->i2c_pair != NULL)
		ikev2_sa_delete_child(i2sa, csa->i2c_pair);
	ikev2_sa_delete_child(i2sa, csa);

	if (reply == NULL)
		return;

	/* There's no action we can do on an error, just log it */
	for (size_t i = 0; i < reply->pkt_notify_count; i++) {
		pkt_notify_t *n = pkt_notify(reply, i);

		if (IKEV2_NOTIFY_ERROR(n->pn_type)) {
			char msg[128] = { 0 };

			(void) snprintf(msg, sizeof (msg),
			    "Received %s error from a DELETE request",
			    ikev2_notify_str(n->pn_type));

			(void) bunyan_info(log, msg, BUNYAN_T_END);
		}
	}

}

/*
 * Generate an SA payload from a regular SADB_ACQUIRE message.
 *	pkt	The packet the payload is being added to
 *	pmsg	The parsed SADB_ACQUIRE message
 *	spi	The outbound SPI to include in each proposal in the SA payload
 *	dh	The DH group to include in each proposal (or IKEV2_DH_NONE to
 *		not request a new DH key exchange.
 *
 * Returns B_TRUE if payload as successfully added, B_FALSE on error.
 */
static boolean_t
ikev2_sa_from_acquire(pkt_t *restrict pkt, parsedmsg_t *restrict pmsg,
    uint32_t spi, ikev2_dh_t dh)
{
	sadb_msg_t *samsg = pmsg->pmsg_samsg;
	sadb_prop_t *prop;
	sadb_comb_t *comb, *end;
	size_t propnum = 0;
	ikev2_spi_proto_t spi_type = IKEV2_PROTO_NONE;
	boolean_t ok;
	pkt_sa_state_t pss;

	VERIFY3U(samsg->sadb_msg_type, ==, SADB_ACQUIRE);

	switch (samsg->sadb_msg_satype) {
	case SADB_SATYPE_AH:
		spi_type = IKEV2_PROTO_AH;
		break;
	case SADB_SATYPE_ESP:
		spi_type = IKEV2_PROTO_ESP;
		break;
	default:
		(void) bunyan_error(log,
		    "Unknown/unexpected SA type received from kernel; aborting "
		    "IPsec SA creation",
		    BUNYAN_T_UINT32, "satype",
		    (uint32_t)samsg->sadb_msg_satype);
		return (B_FALSE);
	}

	prop = (sadb_prop_t *)pmsg->pmsg_exts[SADB_EXT_PROPOSAL];
	VERIFY3U(prop->sadb_prop_exttype, ==, SADB_EXT_PROPOSAL);

	ok = ikev2_add_sa(pkt, &pss);

	end = (sadb_comb_t *)((uint64_t *)prop + prop->sadb_prop_len);
	for (comb = (sadb_comb_t *)(prop + 1); comb < end; comb++) {
		/* RFC7296 3.3.1 proposal numbers start with 1 */
		ok &= ikev2_add_prop(&pss, ++propnum, spi_type, spi);

		if (comb->sadb_comb_encrypt != SADB_EALG_NONE) {
			ikev2_xf_encr_t encr;
			uint16_t minbits, maxbits;

			encr = ikev2_pfkey_to_encr(comb->sadb_comb_encrypt);
			minbits = comb->sadb_comb_encrypt_minbits;
			maxbits = comb->sadb_comb_encrypt_maxbits;
			ok &= ikev2_add_xf_encr(&pss, encr, minbits, maxbits);
		}

		if (comb->sadb_comb_auth != SADB_AALG_NONE) {
			ikev2_xf_auth_t xf_auth;
			size_t keylen;

			xf_auth = ikev2_pfkey_to_auth(comb->sadb_comb_auth);
			VERIFY3S(xf_auth, <=, IKEV2_XF_AUTH_MAX);

			keylen = SADB_8TO1(auth_data(xf_auth)->ad_keylen);
			VERIFY3U(comb->sadb_comb_auth_minbits, ==, keylen);
			VERIFY3U(comb->sadb_comb_auth_maxbits, ==, keylen);

			ok &= ikev2_add_xform(&pss, IKEV2_XF_AUTH, xf_auth);
		}

		if (dh != IKEV2_DH_NONE)
			ok &= ikev2_add_xform(&pss, IKEV2_XF_DH, dh);

		/* We currently don't support ESNs */
		ok &= ikev2_add_xform(&pss, IKEV2_XF_ESN, IKEV2_ESN_NONE);
	}

	return (ok);
}

static boolean_t ikev2_sa_select_ecomb(sadb_x_ecomb_t *restrict, ikev2_dh_t,
    pkt_payload_t *restrict, uint_t, ikev2_sa_match_t *restrict);
static boolean_t ikev2_sa_select_prop(sadb_x_ecomb_t *restrict, ikev2_dh_t,
    ikev2_sa_proposal_t *restrict, uint_t, ikev2_sa_match_t *restrict);
static boolean_t ikev2_sa_select_encr_attr(sadb_x_algdesc_t *restrict,
    ikev2_transform_t *restrict, ikev2_sa_match_t *restrict);

/*
 * Select an SA proposal from the initiator.
 *	pmsg	Our local policy (an extended SADB_ACQUIRE message)
 *	req	The initiator's request packet
 *	m	Where the matching parameters are written
 *
 * Returns B_TRUE if a match was found, B_FALSE otherwise.
 *
 * An SA payload contains one or more proposals.  Each proposal contains a
 * protocol (SA type -- AH, ESP, etc.) and SPI value followed by the list of
 * allowable transforms for the proposal.  While unusual, there doesn't appear
 * to be anything in RFC7296 that forbids an initiator from proposing different
 * protocols in an SA payload.  As it happens, when we query the kernel for
 * the local policy using an SADB_X_INVERSE_ACQUIRE, it returns extended
 * ACQUIRE messages (which will contain the policy for all SA types between
 * the given addresses), but we can only choose a single proposal (or none),
 * thus must also potentially decide on what type of SA to create.
 *
 * To solve these issues, we check for matches for all supported SA types
 * (AH and ESP).  If only one SA type has a match, it is used.  If multiple
 * SA types match, we use an ESP match over an AH match.  If none match, we
 * fail and nothing is chosen.
 */
static boolean_t
ikev2_sa_select_acq(parsedmsg_t *restrict pmsg, ikev2_dh_t dh,
    pkt_t *restrict req, ikev2_sa_match_t *restrict m)
{
	/* In order of preference */
	static const uint_t sa_types[] = { SADB_SATYPE_ESP, SADB_SATYPE_AH };

	pkt_payload_t *sa_pay = pkt_get_payload(req, IKEV2_PAYLOAD_SA, NULL);
	sadb_prop_t *eprop = (sadb_prop_t *)pmsg->pmsg_exts[SADB_X_EXT_EPROP];
	sadb_x_ecomb_t *ecomb = NULL;

	if (sa_pay == NULL) {
		(void) bunyan_warn(log,
		    "CREATE_CHILD_SA request is missing an SA payload; "
		    "cannot create IPsec SA", BUNYAN_T_END);
		return (B_FALSE);
	}

	/* get_resp_policy fails if an SADB_X_EXT_EPROP extension is missing */
	VERIFY3P(eprop, !=, NULL);

	ecomb = (sadb_x_ecomb_t *)(eprop + 1);

	for (size_t i = 0; i < eprop->sadb_x_prop_numecombs; i++) {
		sadb_x_algdesc_t *alg = (sadb_x_algdesc_t *)(ecomb + 1);

		(void) bunyan_debug(log, "Checking extended combination",
		    BUNYAN_T_UINT32, "idx", (uint32_t)i,
		    BUNYAN_T_END);

		for (size_t j = 0; j < ARRAY_SIZE(sa_types); j++) {
			if (ikev2_sa_select_ecomb(ecomb, dh, sa_pay,
			    sa_types[j], m))
				return (B_TRUE);
		}

		ecomb = (sadb_x_ecomb_t *)(alg + ecomb->sadb_x_ecomb_numalgs);
	}

	return (B_FALSE);
}

static boolean_t
ikev2_sa_select_ecomb(sadb_x_ecomb_t *restrict ecomb, ikev2_dh_t dh,
    pkt_payload_t *restrict sa, uint_t satype, ikev2_sa_match_t *restrict m)
{
	sadb_x_algdesc_t *alg = NULL;
	ikev2_sa_proposal_t *i2prop = NULL;

	(void) bunyan_debug(log, "Checking proposals for satype",
	    BUNYAN_T_STRING, "satype", ikev2_spi_str(satype),
	    BUNYAN_T_END);

	FOREACH_PROP(i2prop, sa) {
		if (i2prop->proto_protoid != satype)
			continue;

		bzero(m, sizeof (*m));

		m->ism_spi = ikev2_prop_spi(i2prop);
		m->ism_satype = satype;
		m->ism_propnum = i2prop->proto_proposalnr;

		(void) bunyan_debug(log, "Checking proposal",
		    BUNYAN_T_UINT32, "proposal_num", (uint32_t)m->ism_propnum,
		    BUNYAN_T_STRING, "protocol", ikev2_spi_str(m->ism_satype),
		    BUNYAN_T_STRING, "spi", enum_printf("0x%08x", m->ism_spi),
		    BUNYAN_T_END);

		/* Found a proposal with the SA type we're interested in */
		if (ikev2_sa_select_prop(ecomb, dh, i2prop, satype, m))
			return (B_TRUE);
	}

	return (B_FALSE);
}

static boolean_t
ikev2_sa_select_prop(sadb_x_ecomb_t *restrict ecomb, ikev2_dh_t dh,
    ikev2_sa_proposal_t *restrict i2prop, uint_t satype,
    ikev2_sa_match_t *restrict m)
{
	sadb_x_algdesc_t *alg = (sadb_x_algdesc_t *)(ecomb + 1);
	ikev2_transform_t *xf = NULL;

	VERIFY3U(i2prop->proto_protoid, ==, satype);

	for (size_t i = 0; i < ecomb->sadb_x_ecomb_numalgs; i++, alg++) {
		ikev2_xf_type_t algtype = 0;
		uint16_t sadb_id = 0;

		if (alg->sadb_x_algdesc_satype != satype)
			continue;

		/* Odd, but treat 'no alg' the same as if it wasn't present */
		if (alg->sadb_x_algdesc_alg == 0)
			continue;

		switch (alg->sadb_x_algdesc_algtype) {
		case SADB_X_ALGTYPE_CRYPT:
			algtype = IKEV2_XF_ENCR;
			sadb_id = ikev2_pfkey_to_encr(alg->sadb_x_algdesc_alg);
			break;
		case SADB_X_ALGTYPE_AUTH:
			algtype = IKEV2_XF_AUTH;
			sadb_id = ikev2_pfkey_to_auth(alg->sadb_x_algdesc_alg);
			break;
		default:
			(void) bunyan_warn(log,
			    "Received an extended proposal from the kernel "
			    " with an unknown algtype; discarding",
			    BUNYAN_T_UINT32, "algtype",
			    (uint32_t)alg->sadb_x_algdesc_alg, BUNYAN_T_END);
			return (B_FALSE);
		}

		m->ism_have |= SEEN(algtype);

		FOREACH_XF(xf, i2prop) {
			uint16_t xfid = BE_IN16(&xf->xf_id);

			/*
			 * Make note of the types of transforms seen in the
			 * IKEv2 proposal.  Any unknown transform types
			 * cause us to reject the proposal (RFC7296 3.3.6)
			 */
			switch ((ikev2_xf_type_t)xf->xf_type) {
			case IKEV2_XF_DH:
			case IKEV2_XF_ESN:
				/*
				 * SADB proposals do not support indicating a
				 * DH group or the use of ESNs.  These
				 * transforms are handled after the rest.
				 */
				continue;
			case IKEV2_XF_PRF:
				/* Never valid for a child SA creation */
				(void) bunyan_warn(log,
				    "Proposal contained PRF transform",
				    BUNYAN_T_END);
				return (B_FALSE);
			default:
				(void) bunyan_debug(log,
				    "Unknown transform type",
				    BUNYAN_T_UINT32, "xftype",
				    (uint32_t)xf->xf_type, BUNYAN_T_END);
				break;
			case IKEV2_XF_ENCR:
			case IKEV2_XF_AUTH:
				/* Ignore 'none' ids */
				if (xfid != 0)
					m->ism_seen |= SEEN(xf->xf_type);
				break;
			}

			if (xf->xf_type != algtype)
				continue;

			(void) bunyan_debug(log, "Checking transform",
			    BUNYAN_T_STRING, "xftype",
			    ikev2_xf_type_str(xf->xf_type),
			    BUNYAN_T_STRING, "xfval",
			    ikev2_xf_str(xf->xf_type, xfid), BUNYAN_T_END);

			/*
			 * Use the first match found for a given transform
			 * type.  The mechanisms given to us by the kernel
			 * are in the same order the policies were added
			 * via ipsecconf(1M), so this allows the operator
			 * supplied order to act as the preference in which
			 * to pick mechanisms.
			 */
			if (SA_MATCHES(m, xf->xf_type))
				continue;

			if (sadb_id != xfid)
				continue;

			switch ((ikev2_xf_type_t)xf->xf_type) {
			case IKEV2_XF_ENCR: {
				const encr_data_t *ed = NULL;

				if ((ed = encr_data(xfid)) == NULL)
					return (B_FALSE);
				if (!ikev2_sa_select_encr_attr(alg, xf, m))
					return (B_FALSE);

				m->ism_encr = xfid;
				m->ism_encr_saltlen =
				    alg->sadb_x_algdesc_reserved;
				if (m->ism_encr_keylen == 0)
					m->ism_encr_keylen = ed->ed_keydefault;

				m->ism_match |= SEEN(xf->xf_type);
				break;
			}
			case IKEV2_XF_PRF:
				/*
				 * Our local policy should NEVER allow us to
				 * have a PRF match on an IPsec SA.  PRFs are
				 * only neogitated for IKE SAs.
				 */
				INVALID(xf->xf_type);
				break;
			case IKEV2_XF_AUTH:
				if (auth_data(xfid) == NULL)
					return (B_FALSE);
				if (XF_HAS_ATTRS(xf))
					return (B_FALSE);

				m->ism_auth = xfid;
				m->ism_match |= SEEN(xf->xf_type);
				break;
			case IKEV2_XF_DH:
			case IKEV2_XF_ESN:
				continue;
			}

			(void) bunyan_debug(log, "Transform match",
			    BUNYAN_T_STRING, "xftype",
			    ikev2_xf_type_str(xf->xf_type),
			    BUNYAN_T_STRING, "xfval",
			    ikev2_xf_str(xf->xf_type, xfid), BUNYAN_T_END);
		}
	}

	/* Check DH and ESN if everything else has matched */
	if (!SA_MATCH(m))
		return (B_FALSE);

	/* ESN transform is always required for AH and ESN */
	m->ism_have |= SEEN(IKEV2_XF_ESN);

	if (dh != IKEV2_DH_NONE)
		m->ism_have |= SEEN(IKEV2_XF_DH);

	FOREACH_XF(xf, i2prop) {
		uint16_t id = BE_IN16(&xf->xf_id);

		if (xf->xf_type != IKEV2_XF_DH && xf->xf_type != IKEV2_XF_ESN)
			continue;

		(void) bunyan_debug(log, "Checking transform",
		    BUNYAN_T_STRING, "xftype", ikev2_xf_type_str(xf->xf_type),
		    BUNYAN_T_STRING, "xfval", ikev2_xf_str(xf->xf_type, id),
		    BUNYAN_T_END);

		if (SA_MATCHES(m, xf->xf_type))
			continue;

		switch (xf->xf_type) {
		case IKEV2_XF_DH:
			/* Ignore a none transform */
			if (id != IKEV2_DH_NONE)
				m->ism_seen |= SEEN(IKEV2_XF_DH);

			if (id != dh)
				continue;

			m->ism_match |= SEEN(IKEV2_XF_DH);
			m->ism_dh = id;
			break;
		case IKEV2_XF_ESN:
			m->ism_seen |= SEEN(IKEV2_XF_ESN);

			if (id != IKEV2_ESN_NONE)
				continue;

			m->ism_match |= SEEN(IKEV2_XF_ESN);
			m->ism_esn = B_FALSE;
			break;
		}

		if (SA_MATCH_HAS(m, xf->xf_type)) {
			(void) bunyan_debug(log, "Transform match",
			    BUNYAN_T_STRING, "xftype",
			    ikev2_xf_type_str(xf->xf_type),
			    BUNYAN_T_STRING, "xfval",
			    ikev2_xf_str(xf->xf_type, id),
			    BUNYAN_T_END);
		}
	}

	if (SA_MATCH(m)) {
		(void) bunyan_debug(log, "Propsal match",
		    BUNYAN_T_UINT32, "proposal_num", (uint32_t)m->ism_propnum,
		    BUNYAN_T_STRING, "protocol", ikev2_spi_str(m->ism_satype),
		    BUNYAN_T_STRING, "spi", enum_printf("0x%08x", m->ism_spi),
		    BUNYAN_T_STRING, "encr", ikev2_xf_encr_str(m->ism_encr),
		    BUNYAN_T_UINT32, "encr_keylen",
		    (uint32_t)m->ism_encr_keylen,
		    BUNYAN_T_STRING, "auth", ikev2_xf_auth_str(m->ism_auth),
		    BUNYAN_T_STRING, "dh", ikev2_dh_str(m->ism_dh),
		    BUNYAN_T_STRING, "esn", m->ism_esn ? "YES" : "NO",
		    BUNYAN_T_END);
		return (B_TRUE);
	}

	return (B_FALSE);
}

static boolean_t
ikev2_sa_select_encr_attr(sadb_x_algdesc_t *restrict alg,
    ikev2_transform_t *restrict xf, ikev2_sa_match_t *restrict m)
{
	ikev2_attribute_t *attr = NULL;
	const encr_data_t *ed = NULL;
	uint16_t xfid = BE_IN16(&xf->xf_id);

	ed = encr_data(xfid);
	VERIFY3U(alg->sadb_x_algdesc_algtype, ==, SADB_X_ALGTYPE_CRYPT);

	/*
	 * Currently, only a single attribute (IKEV2_XF_ATTR_KEYLEN) is
	 * defined.  It is only defined for encryption transforms.
	 * Unfortunately, encryption mechanism keylenghts are somewhat
	 * complicated.  Some mechanisms (e.g. AES) always require a
	 * keylength attribute, some (e.g. blowfish) can optionally specify a
	 * keylength while others (e.g. 3DES) have a fixed key size and should
	 * not include * a keylength attribute.
	 */

	/* Should there be a keylength included? */
	if (!XF_HAS_ATTRS(xf) && encr_keylen_req(ed)) {
		(void) bunyan_warn(log,
		    "Transform missing required key length attribute",
		    BUNYAN_T_STRING, "xftype", ikev2_xf_type_str(xf->xf_type),
		    BUNYAN_T_STRING, "xfid", ikev2_xf_str(xf->xf_type, xfid),
		    BUNYAN_T_END);
		return (B_FALSE);
	}

	FOREACH_ATTR(attr, xf) {
		uint16_t attr_type = BE_IN16(&attr->attr_type);
		uint16_t attr_len = BE_IN16(&attr->attr_length);
		boolean_t tv = B_FALSE;

		if (IKE_ATTR_GET_TYPE(attr_type) == IKE_ATTR_TV)
			tv = B_TRUE;

		attr_type = IKE_ATTR_GET_TYPE(attr_type);

		/* Unsupported attributes cause the transform to be rejected */
		if (attr_type != IKEV2_XF_ATTR_KEYLEN)
			return (B_FALSE);

		/*
		 * IKEV2_XF_ATTR_KEYLEN is a TV style attribute, so the length
		 * field contains the value instead of the length of the
		 * attribute.
		 */
		if (attr_len < alg->sadb_x_algdesc_minbits ||
		    attr_len > alg->sadb_x_algdesc_maxbits)
			return (B_FALSE);

		m->ism_encr_keylen = attr_len;
		(void) bunyan_debug(log, "Encryption keylength match",
		    BUNYAN_T_STRING, "xftype", ikev2_xf_type_str(xf->xf_type),
		    BUNYAN_T_STRING, "xfval", ikev2_xf_str(xf->xf_type, xfid),
		    BUNYAN_T_UINT32, "keylen", (uint32_t)attr_len,
		    BUNYAN_T_END);
	}

	return (B_TRUE);
}

/*
 * Verify that the chosen proposal from the responder conforms to our policy.
 *
 *	pmsg	The parsed SADB_ACQUIRE message with our policy
 *	dh	The DH group (if any) proposed to the responder
 *	resp	The responder's response packet
 *	m	The match structure.  Contents will be set to value of the
 *		responder's chosen proposal.
 *
 * Returns B_TRUE if the SA response was valid, B_FALSE otherwise.
 */
static boolean_t
ikev2_sa_check_acquire(parsedmsg_t *restrict pmsg, ikev2_dh_t dh,
    pkt_t *restrict resp, ikev2_sa_match_t *restrict m)
{
	const encr_data_t *ed = NULL;

	pkt_payload_t *sa_pay = pkt_get_payload(resp, IKEV2_PAYLOAD_SA, NULL);
	sadb_prop_t *prop = NULL;
	sadb_comb_t *comb = NULL, *end = NULL;
	ikev2_sa_proposal_t *i2prop = NULL;
	ikev2_transform_t *i2xf = NULL;
	ikev2_attribute_t *xfattr = NULL;

	bzero(m, sizeof (*m));

	prop = (sadb_prop_t *)pmsg->pmsg_exts[SADB_EXT_PROPOSAL];
	comb = (sadb_comb_t *)(prop + 1);
	end = (sadb_comb_t *)((uint64_t *)prop + prop->sadb_prop_len);

	i2prop = ikev2_prop_first(sa_pay);

	/*
	 * Responders MUST only send back one response with the proposal
	 * number set the proposal chosen, which for proposals we generate
	 * is just the position of the sadb_comb_t in the SADB_EXT_PROPOSAL
	 * extension (starting with 1 -- as proposal numbers MUST start with
	 * 1).  We can therefore just check that single sadb_comb_t (as long
	 * as it exists), and not have to check the entire SADB_EXT_PROPOSAL.
	 */
	for (size_t i = 1; i < i2prop->proto_proposalnr; i++, comb++) {
		if (comb < end)
			continue;

		(void) bunyan_warn(log,
		    "Responder sent an SA reply with an invalid proposal "
		    "number; aborting IPsec SA creation",
		    BUNYAN_T_UINT32, "proposal_num",
		    (uint32_t)i2prop->proto_proposalnr, BUNYAN_T_END);

		return (B_FALSE);
	}

	if (pmsg->pmsg_samsg->sadb_msg_satype != i2prop->proto_protoid) {
		(void) bunyan_warn(log,
		    "SA reply contains a different SA type than what was sent; "
		    "aborting IPsec SA creation",
		    BUNYAN_T_STRING, "satype",
		    ikev2_spi_str(i2prop->proto_protoid), BUNYAN_T_END);
		return (B_FALSE);
	}

	m->ism_propnum = i2prop->proto_proposalnr;
	m->ism_satype = i2prop->proto_protoid;
	m->ism_spi = ikev2_prop_spi(i2prop);

	if (comb->sadb_comb_auth != SADB_AALG_NONE)
		m->ism_seen |= SEEN(IKEV2_XF_AUTH);
	if (comb->sadb_comb_auth != SADB_EALG_NONE)
		m->ism_seen |= SEEN(IKEV2_XF_ENCR);

	FOREACH_XF(i2xf, i2prop) {
		uint16_t id = BE_IN16(&i2xf->xf_id);

		switch (i2xf->xf_type) {
		case IKEV2_XF_PRF:
			goto invalid_xf;
		case IKEV2_XF_ESN:
			if (id != IKEV2_ESN_NONE)
				goto invalid_xf;

			m->ism_esn = B_FALSE;
			break;
		case IKEV2_XF_AUTH:
			if (id != ikev2_pfkey_to_auth(comb->sadb_comb_auth))
				goto invalid_xf;

			m->ism_auth = id;
			break;
		case IKEV2_XF_DH:
			if (id != dh)
				goto invalid_xf;

			m->ism_dh = id;
			break;
		case IKEV2_XF_ENCR:
			if (id != comb->sadb_comb_encrypt)
				goto invalid_xf;

			m->ism_encr = id;
			ed = encr_data(id);
#ifdef notyet
			m->ism_encr_saltlen = comb->sadb_comb_saltlen;
#else
			/*
			 * Typically, the same mechanisms for use in ESP/AH
			 * are also defined for IKEv2, and are used in a
			 * similar manner, so using the IKEv2 defined salt
			 * length for mechanisms works.  However, the definition
			 * of a mechanism for IKEv2 use tends to lag that of
			 * AH/ESP, and it is also possible in the future that
			 * the use in IKEv2 might differ, so using our value
			 * is not a good long term solution.  Once OS-6525
			 * is fixed, the kernel will include the salt length
			 * for the mechanism in an SADB_ACQUIRE message, so
			 * we will use that instead.
			 */
			m->ism_encr_saltlen = ed->ed_saltlen;
#endif

			FOREACH_ATTR(xfattr, i2xf) {
				uint16_t type = BE_IN16(&xfattr->attr_type);
				uint16_t len = BE_IN16(&xfattr->attr_length);

				type = IKE_ATTR_GET_TYPE(type);
				if (type != IKEV2_XF_ATTR_KEYLEN) {
					(void) bunyan_error(log,
					    "Responder replied with an unknown "
					    "encryption attribute",
					    BUNYAN_T_UINT32, "attrtype",
					    (uint32_t)type, BUNYAN_T_END);
					return (B_FALSE);
				}

				if (!encr_keylen_allowed(ed)) {
					(void) bunyan_error(log,
					    "Responder replied with an invalid "
					    "keysize", BUNYAN_T_END);
					return (B_FALSE);
				}

				if (len < comb->sadb_comb_encrypt_minbits ||
				    len > comb->sadb_comb_encrypt_maxbits) {
					uint32_t min, max;
					min = comb->sadb_comb_encrypt_minbits;
					max = comb->sadb_comb_encrypt_maxbits;

					(void) bunyan_error(log,
					    "Responder replied with a keysize "
					    "outside the allowed range",
					    BUNYAN_T_UINT32, "keylen",
					    (uint32_t)len,
					    BUNYAN_T_UINT32, "keymin", min,
					    BUNYAN_T_UINT32, "keymax", max,
					    BUNYAN_T_END);

					return (B_FALSE);
				}

				m->ism_encr_keylen = len;
			}

			if (!XF_HAS_ATTRS(i2xf) && encr_keylen_req(ed)) {
				(void) bunyan_error(log,
				    "Responder reply is missing a required "
				    "keysize", BUNYAN_T_END);

				return (B_FALSE);
			}

			if (m->ism_encr_keylen == 0)
				m->ism_encr_keylen = ed->ed_keydefault;

			break;
		}
		m->ism_match |= SEEN(i2xf->xf_type);
	}

	return (SA_MATCH(m));

invalid_xf:
	(void) bunyan_warn(log,
	    "SA reply contains a transform that was not in the proposed set; "
	    "aborting IPsec SA creation",
	    BUNYAN_T_STRING, "satype", ikev2_spi_str(i2prop->proto_protoid),
	    BUNYAN_T_UINT32, "proposal_num", (uint32_t)i2prop->proto_proposalnr,
	    BUNYAN_T_STRING, "xftype", ikev2_xf_type_str(i2xf->xf_type),
	    BUNYAN_T_STRING, "xfid",
	    ikev2_xf_str(i2xf->xf_type, BE_IN16(&i2xf->xf_id)),
	    BUNYAN_T_END);
	return (B_FALSE);
}

/*
 * Translate the addresses from our ACQUIRE message into IKEv2 traffic
 * selectors and add them to our request.
 */
static boolean_t
add_ts_init(pkt_t *restrict req, parsedmsg_t *restrict pmsg)
{
	ikev2_pkt_ts_state_t tstate = { 0 };
	ts_t ts = { 0 };
	sadb_address_t *addr = NULL;

	if (!ikev2_add_ts_i(req, &tstate))
		return (B_FALSE);

#ifdef notyet
	/*
	 * RFC7296  2.9 -- If we know the source/dest IP of the packet that
	 * triggered the SA creation requests (i.e. ACQUIRE), we include
	 * those IPs as the first traffic selector in the TS{i,r} payloads.
	 * Followed the the traffic selectors for our policy.
	 */
	addr = (sadb_address_t *)pmsg->pmsg_exts[SADB_X_EXT_ADDRESS_OPS];
	if (addr != NULL && !ts_add(&tstate, sadb_to_ts(addr, &ts)))
		return (B_FALSE);
#endif

	addr = get_sadb_addr(pmsg, B_TRUE);
	if (!ts_add(&tstate, sadb_to_ts(addr, &ts)))
		return (B_FALSE);

	bzero(&tstate, sizeof (tstate));
	if (!ikev2_add_ts_r(req, &tstate))
		return (B_FALSE);

#ifdef notyet
	addr = (sadb_address_t *)pmsg->pmsg_exts[SADB_X_EXT_ADDRESS_OPD];
	if (addr != NULL && !ts_add(&tstate, sadb_to_ts(addr, &ts)))
		return (B_FALSE);
#endif

	addr = get_sadb_addr(pmsg, B_FALSE);
	if (!ts_add(&tstate, sadb_to_ts(addr, &ts)))
		return (B_FALSE);

	return (B_TRUE);
}

static boolean_t
add_ts_resp(pkt_t *restrict resp, const ts_t *restrict ts_i,
    const ts_t *restrict ts_r)
{
	ikev2_pkt_ts_state_t tss = { 0 };
	boolean_t ok = B_FALSE;

	(void) bunyan_trace(log, "add_ts_resp: enter", BUNYAN_T_END);

	if (!ikev2_add_ts_i(resp, &tss) || !ts_add(&tss, ts_i))
		goto done;

	if (!ikev2_add_ts_r(resp, &tss) || !ts_add(&tss, ts_r))
		goto done;

	ok = B_TRUE;

done:
	(void) bunyan_trace(log, "add_ts_resp: exit",
	    BUNYAN_T_BOOLEAN, "success", ok,
	    BUNYAN_T_END);

	return (ok);
}

/*
 * Queries kernel for IPsec policy for IPs in TS{i,r} payloads from initiator.
 * Result in saved in csa->i2a_pmsg (set to NULL if no policy found).
 *
 * If there was an error looking up the policy (not found is not considered
 * an error), return B_FALSE, otherwise B_TRUE.
 */
static boolean_t
get_resp_policy(pkt_t *restrict pkt, boolean_t transport_mode,
    ikev2_sa_args_t *restrict csa)
{
	ikev2_sa_t *i2sa = pkt->pkt_sa;
	pkt_payload_t *ts_ip = pkt_get_payload(pkt, IKEV2_PAYLOAD_TSi, NULL);
	pkt_payload_t *ts_rp = pkt_get_payload(pkt, IKEV2_PAYLOAD_TSr, NULL);
	ts_t ts_i = { 0 };
	ts_t ts_r = { 0 };

	/*
	 * We should only be called from the responder, so this packet should
	 * be from the initiator.
	 */
	VERIFY(I2P_INITIATOR(pkt));

	ts_first(ts_ip, &ts_i);
	ts_first(ts_rp, &ts_r);

	if (transport_mode) {
		if (pfkey_inverse_acquire(&ts_r, &ts_i, NULL, NULL,
		    &csa->i2a_pmsg)) {
			return (B_TRUE);
		}
	} else {
		/* IPPROTO_ENCAP is ipip */
		ts_t src = { .ts_proto = IPPROTO_ENCAP };
		ts_t dst = { .ts_proto = IPPROTO_ENCAP };

		/* We don't specify ports for the outer address */
		sockaddr_copy(SSTOSA(&i2sa->laddr), &src.ts_ss, B_FALSE);
		sockaddr_copy(SSTOSA(&i2sa->raddr), &dst.ts_ss, B_FALSE);

		if (pfkey_inverse_acquire(&src, &dst, &ts_r, &ts_i,
		    &csa->i2a_pmsg)) {
			return (B_TRUE);
		}
	}

	/* Error handling / logging */

	if (csa->i2a_pmsg == NULL || csa->i2a_pmsg->pmsg_samsg == NULL)
		return (B_FALSE);

	sadb_msg_t *m = csa->i2a_pmsg->pmsg_samsg;

	switch (m->sadb_msg_errno) {
	case ENOENT:
		(void) bunyan_warn(log,
		    "No policy found for proposed IPsec traffic",
		    BUNYAN_T_END);
		parsedmsg_free(csa->i2a_pmsg);
		csa->i2a_pmsg = NULL;
		return (B_TRUE);

	/* XXX: Other possible errors to explicitly handle? */
	default:
		TSTDERR(m->sadb_msg_errno, warn,
		    "Error while looking up IPsec policy",
		    BUNYAN_T_STRING, "diagmsg",
		    keysock_diag(m->sadb_x_msg_diagnostic),
		    BUNYAN_T_UINT32, "diagcode",
		    (uint32_t)m->sadb_x_msg_diagnostic);
	}

	parsedmsg_free(csa->i2a_pmsg);
	csa->i2a_pmsg = NULL;
	return (B_FALSE);
}

static void
check_natt_addrs(pkt_t *restrict pkt, boolean_t transport_mode)
{
	/*
	 * TODO: Check TSi[0] and TSr[0] in pkt.  If #TS > 1 (i.e.
	 * TS{i,r}[0] is the OPS/OPD), compare with ikev2_sa_t->{l,r}addr
	 * to and save to IKE SA if different (thus we know the NATed address)
	 */
}

static void
ikev2_set_child_type(ikev2_child_sa_state_t *restrict kids, boolean_t initiator,
    ikev2_spi_proto_t satype)
{
	for (size_t i = 0; i < 2; i++) {
		ikev2_child_sa_t *child = kids[i].csa_child;

		child->i2c_initiator = initiator;
		child->i2c_satype = satype;
	}
}

static void
ikev2_save_child_results(ikev2_child_sa_state_t *restrict kids,
    const ikev2_sa_match_t *restrict results)
{
	kids[CSA_OUT].csa_child->i2c_spi = results->ism_spi;

	for (size_t i = 0; i < 2; i++) {
		ikev2_child_sa_t *child = kids[i].csa_child;

		child->i2c_satype = results->ism_satype;
		child->i2c_encr = results->ism_encr;
		child->i2c_auth = results->ism_auth;
		child->i2c_encr_keylen = results->ism_encr_keylen;
		child->i2c_dh = results->ism_dh;
	}
}

static void
ikev2_save_child_ts(ikev2_child_sa_state_t *restrict kids,
    const ts_t *restrict ts_i, const ts_t *restrict ts_r)
{
	for (size_t i = 0; i < 2; i++) {
		ikev2_child_sa_t *child = kids[i].csa_child;

		child->i2c_ts_i = *ts_i;
		child->i2c_ts_r = *ts_r;
	}
}

/* Sends the pf_key(7P) messages to establish the IPsec SAs */
static boolean_t
ikev2_create_child_sas(ikev2_sa_t *restrict sa, ikev2_sa_args_t *restrict args)
{
	ikev2_child_sa_state_t *kid = args->i2a_child;

	/* We always create IPsec SAs in pairs, so there's _always_ 2 */
	for (size_t i = 0; i < 2; i++, kid) {
		ikev2_child_sa_t *csa = kid[i].csa_child;


		if (!pfkey_sadb_add_update(sa, csa, kid[i].csa_child_encr,
		    kid[i].csa_child_auth, args->i2a_pmsg))
			return (B_FALSE);

		ikev2_sa_add_child(sa, csa);
		kid[i].csa_child_added = B_TRUE;
		csa->i2c_birth = gethrtime();

		/*
		 * We want the two IPsec SAs to be paired in the kernel, but
		 * AFAIK when adding the SADB_X_EXT_PAIR to a SADB_{ADD,UPDATE}
		 * message, it must reference an existing SA, so we don't
		 * set i2c_pair until after we've created/added the first SA.
		 */
		kid[i ^ 1].csa_child->i2c_pair = kid[i ^ 0].csa_child;

		/* TODO: Log more keys */
		(void) bunyan_debug(log, "Created IPsec SA",
		    BUNYAN_T_POINTER, "csa", csa,
		    BUNYAN_T_STRING, "spi", enum_printf("0x%" PRIx32,
		    ntohl(csa->i2c_spi)),
		    BUNYAN_T_BOOLEAN, "inbound", csa->i2c_inbound,
		    BUNYAN_T_END);
	}

	return (B_TRUE);
}

static boolean_t
generate_keys(ikev2_sa_t *restrict i2sa, ikev2_sa_args_t *restrict csa)
{
	/*
	 * RFC7296 2.17 - If we are doing a DH key exchange, the order of the
	 * input material is g^ir (new) | Ni | Nr.  If there is no key exchange,
	 * the input is just Ni | Nr.
	 */
	struct {
		uint8_t *ptr;
		size_t len;
	} prfp_args[] = {
		{ NULL, 0 },		/* g^ir if doing a key exchange */
		{ csa->i2a_nonce_i, csa->i2a_nonce_i_len },
		{ csa->i2a_nonce_r, csa->i2a_nonce_r_len },
		{ NULL, 0 }
	};
	size_t idx = 1;		/* index of first arg to prfplus_init */
	prfp_t prfp = { 0 };
	ikev2_child_sa_state_t *init = NULL, *resp = NULL;
	size_t encrlen = 0, authlen = 0;
	boolean_t ret = B_FALSE;

	init = &csa->i2a_child[INITIATOR(csa) ? CSA_OUT : CSA_IN];
	resp = &csa->i2a_child[INITIATOR(csa) ? CSA_IN : CSA_OUT];

	(void) bunyan_trace(log, "Generating child SA keys",
	    BUNYAN_T_END);

	if (csa->i2a_dhkey != CK_INVALID_HANDLE) {
		CK_RV rv = CKR_OK;

		rv = pkcs11_ObjectToKey(p11h(), csa->i2a_dhkey,
		    (void **)&prfp_args[0].ptr, &prfp_args[0].len, B_FALSE);
		if (rv != CKR_OK) {
			PKCS11ERR(error, "pkcs11_ObjectToKey",
			    rv, BUNYAN_T_STRING, "objname", "gir");
			return (B_FALSE);
		}

		idx = 0;
	}

	ret = prfplus_init(&prfp, i2sa->prf, i2sa->sk_d,
	    prfp_args[idx].ptr, prfp_args[idx].len,
	    prfp_args[idx + 1].ptr, prfp_args[idx + 1].len,
	    prfp_args[idx + 2].ptr, prfp_args[idx + 2].len,
	    NULL);

	explicit_bzero(prfp_args[0].ptr, prfp_args[0].len);
	free(prfp_args[0].ptr);

	if (!ret)
		return (B_FALSE);

	/* Sanity checks that both pairs agree on algs and key lengths */
	VERIFY3S(init->csa_child->i2c_encr, ==, resp->csa_child->i2c_encr);
	VERIFY3S(init->csa_child->i2c_auth, ==, resp->csa_child->i2c_auth);
	VERIFY3U(init->csa_child->i2c_encr_keylen, ==,
	    resp->csa_child->i2c_encr_keylen);

	/*
	 * For all currently defined combined mode mechanisms, the salt
	 * generation works similar to how IKEv2 generates salt values --
	 * the appropriate size salt is created immediately after the
	 * encryption key.  Since in.ikev2d doesn't need to do anything
	 * with the child SA salt value, and since the kernel expects the
	 * salt value (when needed) to be appended to the encryption key
	 * in the pf_key(7P) extension when adding an IPsec SA, we just
	 * create a single 'key' that's the sum of both sizes so we don't
	 * need to do any appending of the two ourselves.  For non-combined
	 * mode ciphers, i2c_encr_saltlen will be 0, so things will work
	 * as expected.
	 */
	encrlen = init->csa_child->i2c_encr_keylen +
	    init->csa_child->i2c_encr_saltlen;
	encrlen = SADB_1TO8(encrlen);
	authlen = auth_data(init->csa_child->i2c_auth)->ad_keylen;

	VERIFY3U(encrlen, <=, ENCR_MAX);
	VERIFY3U(authlen, <=, AUTH_MAX);

	/*
	 * We always generate keys in the order of initiator first, then
	 * responder.  For each side, we always start with encryption keys
	 * then authentication keys.
	 */
	ret = prfplus(&prfp, init->csa_child_encr, encrlen) &&
	    prfplus(&prfp, init->csa_child_auth, authlen) &&
	    prfplus(&prfp, resp->csa_child_encr, encrlen) &&
	    prfplus(&prfp, resp->csa_child_auth, authlen);

done:
	prfplus_fini(&prfp);

	(void) bunyan_trace(log, "Finished generating keys",
	    BUNYAN_T_BOOLEAN, "success", ret,
	    BUNYAN_T_END);

	return (ret);
}

/*
 * Get the sadb address from a parsed message that will actually be subjected
 * to IPsec.  For transport mode, this is the SRC/DST address, for tunnel
 * mode, this is the inner SRC/DST address.  'src' determines if we want
 * the appropriate SRC or DST address.
 */
static sadb_address_t *
get_sadb_addr(parsedmsg_t *pmsg, boolean_t src)
{
	sadb_ext_t *ext = NULL;
	uint_t first = src ?
	    SADB_X_EXT_ADDRESS_INNER_SRC : SADB_X_EXT_ADDRESS_INNER_DST;
	uint_t alt = src ?  SADB_EXT_ADDRESS_SRC : SADB_EXT_ADDRESS_DST;

	/*
	 * If the kernel has send an ACQUIRE for a transport mode SA, it
	 * will not include any INNER_{SRC,DST} addresses.  However for
	 * tunnel mode, they are required, so we return the INNER addresses
	 * if present.  Note this is currently the only way AFAIK to
	 * distinguish between the two scenarios.
	 */
	ext = pmsg->pmsg_exts[first];
	if (ext == NULL) {
		ext = pmsg->pmsg_exts[alt];
		VERIFY3P(ext, !=, NULL);
		VERIFY3U(ext->sadb_ext_type, ==, alt);
	} else {
		VERIFY3U(ext->sadb_ext_type, ==, first);
	}

	return ((sadb_address_t *)ext);
}

#ifdef notyet
static void
ikev2_rekey_delete_old_kids(ikev2_sa_t *restrict i2sa,
    ikev2_sa_args_t *restrict args)
{
	ikev2_child_sa_t *csa = args->i2a_old_csa;
	uint8_t satype = ikev2_to_satype(csa->i2c_satype);

	(void) pfkey_delete(satype, csa->i2c_spi, src, dst, B_TRUE);
	ikev2_sa_delete_child(i2sa, csa->i2c_pair);
	ikev2_sa_delete_child(i2sa,csa);
}
#endif
