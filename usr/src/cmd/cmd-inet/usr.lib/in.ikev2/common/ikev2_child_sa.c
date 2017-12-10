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
#include "ikev2_pkt.h"
#include "ikev2_proto.h"
#include "ikev2_sa.h"
#include "pfkey.h"
#include "pkcs11.h"
#include "prf.h"
#include "range.h"
#include "worker.h"

/* Key length maxes in bytes for array sizing */
#define	ENCR_MAX	SADB_1TO8(IKEV2_ENCR_KEYLEN_MAX)
#define	AUTH_MAX	SADB_1TO8(IKEV2_AUTH_KEYLEN_MAX)

/* All the interim state to carry around while creating a pair of child SA. */
struct child_sa_args {
	ikev2_sa_t		*csa_i2sa;
	parsedmsg_t		*csa_pmsg;
	sadb_msg_t		*csa_srcmsg;

	ikev2_dh_t		csa_dh;
	ikev2_sa_result_t	csa_results;

	CK_OBJECT_HANDLE	csa_pubkey;
	CK_OBJECT_HANDLE	csa_privkey;
	CK_OBJECT_HANDLE	csa_dhkey;

	ikev2_child_sa_t	*csa_child_in;
	uint8_t			csa_child_in_encr[ENCR_MAX];
	uint8_t			csa_child_in_auth[AUTH_MAX];
	boolean_t		csa_added_child_in;

	ikev2_child_sa_t	*csa_child_out;
	uint8_t			csa_child_out_encr[ENCR_MAX];
	uint8_t			csa_child_out_auth[AUTH_MAX];
	boolean_t		csa_added_child_out;

	uint8_t			csa_nonce_i[IKEV2_NONCE_MAX];
	size_t			csa_nonce_i_len;
	uint8_t			csa_nonce_r[IKEV2_NONCE_MAX];
	size_t			csa_nonce_r_len;

	boolean_t		csa_is_auth;
};
#define	INITIATOR(args) ((args)->csa_child_in->i2c_transport)
#define	TRANSPORT_MODE(args) ((args)->csa_child_in->i2c_transport)

static boolean_t ikev2_create_child_sa_init_common(ikev2_sa_t *restrict,
    pkt_t *restrict req, struct child_sa_args *restrict);
static void ikev2_create_child_sa_resp_common(pkt_t *restrict, pkt_t *restrict,
    struct child_sa_args *restrict);

static boolean_t add_ts_init(pkt_t *restrict, parsedmsg_t *restrict);
static boolean_t add_ts_resp(pkt_t *restrict, pkt_t *restrict,
    struct child_sa_args *restrict);
static boolean_t add_ts_resp_one(pkt_payload_t *restrict,
    sadb_address_t *restrict, pkt_t *restrict,
    struct sockaddr_storage *restrict, uint8_t *restrict);
static boolean_t ts_negotiate(pkt_payload_t *restrict,
    const struct sockaddr_storage *restrict, uint8_t,
    struct sockaddr_storage *restrict, uint8_t *restrict);
static boolean_t add_sadb_address(ikev2_pkt_ts_state_t *restrict,
    const sadb_address_t *restrict);

static boolean_t generate_keys(struct child_sa_args *);
static boolean_t create_keymat(ikev2_sa_t *restrict, boolean_t,
    uint8_t *restrict, size_t,
    uint8_t *restrict, size_t, prfp_t *restrict);
static boolean_t ikev2_create_child_sas(struct child_sa_args *);
static void ikev2_save_child_results(struct child_sa_args *restrict,
    const ikev2_sa_result_t *restrict);
static void check_natt_addrs(pkt_t *restrict, boolean_t);
static ikev2_ts_t *first_ts_addr(pkt_payload_t *restrict,
    struct sockaddr_storage *restrict, uint8_t *);

static boolean_t ikev2_child_add_dh(struct child_sa_args *restrict,
    pkt_t *restrict);
static boolean_t ikev2_child_ke(struct child_sa_args *restrict,
    pkt_t *restrict);
static boolean_t ikev2_child_add_nonce(struct child_sa_args *restrict,
    pkt_t *restrict);
static void ikev2_child_save_nonce(struct child_sa_args *restrict,
    pkt_t *restrict);

static struct child_sa_args *create_csa_args(ikev2_sa_t *restrict, boolean_t,
    boolean_t);
static void csa_args_free(struct child_sa_args *);
static uint8_t get_satype(parsedmsg_t *);
static sadb_address_t *get_sadb_addr(parsedmsg_t *, boolean_t);

/*
 * We are the initiator for an IKE_AUTH exchange, and are performing the
 * child SA creation that occurs during the IKE AUTH exchange.
 */
void *
ikev2_create_child_sa_init_auth(ikev2_sa_t *restrict sa, pkt_t *restrict req,
    parsedmsg_t *pmsg)
{
	struct child_sa_args *csa = NULL;

	VERIFY(IS_WORKER);
	VERIFY(!MUTEX_HELD(&sa->i2sa_queue_lock));
	VERIFY(MUTEX_HELD(&sa->i2sa_lock));
	VERIFY3U(pkt_header(req)->exch_type, ==, IKEV2_EXCH_IKE_AUTH);

	VERIFY(sa->flags & I2SA_INITIATOR);

	if ((csa = create_csa_args(sa, B_TRUE, B_TRUE)) == NULL) {
		pfkey_send_error(pmsg->pmsg_samsg, ENOMEM);
		parsedmsg_free(pmsg);
		return (NULL);
	}

	csa->csa_pmsg = pmsg;
	csa->csa_srcmsg = PMSG_FROM_KERNEL(pmsg) ? pmsg->pmsg_samsg : NULL;

	if (!ikev2_create_child_sa_init_common(sa, req, csa)) {
		csa_args_free(csa);
		return (NULL);
	}

	return (csa);
}

/* We are the initiator in a CREATE_CHILD_SA exchange */
void
ikev2_create_child_sa_init(ikev2_sa_t *restrict sa, parsedmsg_t *restrict pmsg)
{
	struct child_sa_args *csa = NULL;
	pkt_t *req = NULL;

	VERIFY(IS_WORKER);
	VERIFY(!MUTEX_HELD(&sa->i2sa_queue_lock));
	VERIFY(MUTEX_HELD(&sa->i2sa_lock));

	/*
	 * This entry point into CREATE_CHILD_SA should only be for kernel
	 * originated ACQUIRES.
	 */
	VERIFY(PMSG_FROM_KERNEL(pmsg));

	(void) bunyan_debug(log, "Starting CREATE_CHILD_SA exchange",
	    BUNYAN_T_END);

	if ((csa = create_csa_args(sa, B_FALSE, B_TRUE)) == NULL)
		goto fail;

	csa->csa_pmsg = pmsg;
	csa->csa_srcmsg = pmsg->pmsg_samsg;

	req = ikev2_pkt_new_exchange(sa, IKEV2_EXCH_CREATE_CHILD_SA);
	if (req == NULL)
		goto fail;

	/* This is the first payload, there should always be space for it */
	VERIFY(ikev2_add_sk(req));

	if (!ikev2_create_child_sa_init_common(sa, req, csa))
		goto fail;
	if (!ikev2_send_req(req, ikev2_create_child_sa_init_resp, csa))
		goto fail;
	return;

fail:
	pfkey_send_error(pmsg->pmsg_samsg, ENOMEM);
	parsedmsg_free(pmsg);
	csa_args_free(csa);
}

/* We are the initiator, shared bits for IKE_AUTH and CREATE_CHILD_SA */
static boolean_t
ikev2_create_child_sa_init_common(ikev2_sa_t *restrict sa, pkt_t *restrict req,
    struct child_sa_args *restrict csa)
{
	parsedmsg_t *pmsg = csa->csa_pmsg;
	sockaddr_u_t src = { .sau_ss = &sa->laddr };
	sockaddr_u_t dest = { .sau_ss = &sa->raddr };
	ikev2_dh_t dh = IKEV2_DH_NONE;
	uint8_t satype = get_satype(pmsg);
	ikev2_spi_proto_t proto = satype_to_ikev2(satype);
	uint32_t spi = 0;
	boolean_t transport_mode = B_FALSE;

	if (pmsg->pmsg_isau.sau_ss == NULL) {
		transport_mode = B_TRUE;
	} else {
		sadb_ext_t *isrc =
		    pmsg->pmsg_exts[SADB_X_EXT_ADDRESS_INNER_SRC];

		csa->csa_child_in->i2c_inner_proto =
		    csa->csa_child_out->i2c_inner_proto =
		    ((sadb_address_t *)isrc)->sadb_address_proto;
	}

	csa->csa_child_in->i2c_transport = csa->csa_child_out->i2c_transport =
	    transport_mode;
	csa->csa_child_in->i2c_satype = csa->csa_child_out->i2c_satype = satype;

	if (!pfkey_getspi(csa->csa_srcmsg, pmsg->pmsg_sau, pmsg->pmsg_dau,
	    satype, &spi)) {
		goto fail;
	}
	csa->csa_child_out->i2c_spi = spi;

	/* XXX: IPcomp (when we add support) */

	if (transport_mode && !ikev2_add_notify(req, proto, spi,
	    IKEV2_N_USE_TRANSPORT_MODE, NULL, 0))
		goto fail;

	if (!ikev2_add_notify(req, proto, spi,
	    IKEV2_N_ESP_TFC_PADDING_NOT_SUPPORTED, NULL, 0))
		goto fail;

	if (!ikev2_add_notify(req, proto, spi,
	    IKEV2_N_NON_FIRST_FRAGMENTS_ALSO, NULL, 0))
		goto fail;

	if (!ikev2_sa_from_acquire(req, pmsg, spi, dh))
		goto fail;

	if (!ikev2_child_add_nonce(csa, req))
		goto fail;

	if (!ikev2_child_add_dh(csa, req))
		goto fail;

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
void
ikev2_create_child_sa_resp_auth(pkt_t *restrict req, pkt_t *restrict resp)
{
	VERIFY3U(pkt_header(resp)->exch_type, ==, IKEV2_EXCH_IKE_AUTH);
	struct child_sa_args *csa;

	if ((csa = create_csa_args(req->pkt_sa, B_TRUE, B_FALSE)) == NULL) {
		/*
		 * XXX: While TEMPORARY_FAILURE seems like it'd be a better
		 * response, RFC7296 seems to imply that it is only used in
		 * conjunction with a rekey operation, and not during an
		 * IKE_AUTH request.  For now at least, we will reply with
		 * the generic catch-all NO_PROPOSAL_CHOSEN.
		 */
		(void) ikev2_no_proposal_chosen(resp, IKEV2_PROTO_IKE);
		return;
	}

	ikev2_create_child_sa_resp_common(req, resp, csa);
	csa_args_free(csa);
}

/* We are the responder in a CREATE_CHILD_SA exchange */
void
ikev2_create_child_sa_resp(pkt_t *restrict req)
{
	pkt_t *resp = ikev2_pkt_new_response(req);

	if (resp == NULL) {
		ikev2_pkt_free(req);
		return;
	}
	/* It's the first payload, it should fit */
	VERIFY(ikev2_add_sk(resp));

	struct child_sa_args *csa = create_csa_args(req->pkt_sa,
	    B_FALSE, B_FALSE);

	if (csa == NULL) {
		/* See above -- this is the best we can respond with */
		(void) ikev2_no_proposal_chosen(resp, IKEV2_PROTO_IKE);
		(void) ikev2_send_resp(resp);
		ikev2_pkt_free(req);
		return;
	}

	ikev2_create_child_sa_resp_common(req, resp, csa);

	csa_args_free(csa);
	ikev2_pkt_free(req);
}

static boolean_t get_resp_policy(pkt_t *restrict,
    struct child_sa_args *restrict);

/*
 * We are the responder (shared bits between IKE_AUTH and CREATE_CHILD_SA).
 */
static void
ikev2_create_child_sa_resp_common(pkt_t *restrict req, pkt_t *restrict resp,
    struct child_sa_args *restrict csa)
{
	ikev2_sa_t *sa = req->pkt_sa;
	parsedmsg_t *pmsg = NULL;
	ikev2_spi_proto_t proto = IKEV2_PROTO_NONE;
	uint32_t spi = 0;

	if (pkt_get_notify(req, IKEV2_N_USE_TRANSPORT_MODE, NULL) != NULL) {
		csa->csa_child_in->i2c_transport =
		    csa->csa_child_out->i2c_transport = B_TRUE;
	}

	if (csa->csa_is_auth)
		check_natt_addrs(req, TRANSPORT_MODE(csa));

	if (!get_resp_policy(req, csa))
		goto fail;

	if ((pmsg = csa->csa_pmsg) == NULL) {
		/*
		 * XXX: Should we pick off the protocol from the SA payload and
		 * use that instead for the protocol?  However, it's possible
		 * the initiator has proposed multiple different SPIs in it's
		 * SA payload, so there's no indication if one of those values
		 * should be used.
		 */
		if (!ikev2_add_notify(resp, IKEV2_PROTO_IKE, 0,
		    IKEV2_N_TS_UNACCEPTABLE, NULL, 0))
			goto fail;
		goto done;
	}

	if (!ikev2_sa_match_acquire(pmsg, csa->csa_dh, req,
	    &csa->csa_results)) {
		if (!ikev2_no_proposal_chosen(resp, csa->csa_results.sar_proto))
			goto fail;
		goto done;
	}
	proto = csa->csa_results.sar_proto;

	if (!csa->csa_is_auth && ikev2_get_dhgrp(req) !=
	    csa->csa_results.sar_dh) {
		if (!ikev2_invalid_ke(resp, proto, 0, csa->csa_results.sar_dh))
			goto fail;
		goto done;
	}

	if (!pfkey_getspi(NULL, pmsg->pmsg_sau, pmsg->pmsg_dau, proto, &spi))
		goto fail;

	csa->csa_child_out->i2c_spi = spi;
	ikev2_save_child_results(csa, &csa->csa_results);

	if (TRANSPORT_MODE(csa) &&
	    !ikev2_add_notify(resp, proto, spi, IKEV2_N_USE_TRANSPORT_MODE,
	    NULL, 0))
		goto fail;

	/* We currently don't support TFC PADDING */
	if (!ikev2_add_notify(resp, proto, spi,
	    IKEV2_N_ESP_TFC_PADDING_NOT_SUPPORTED, NULL, 0))
		goto fail;

	/* and we always include non-first fragments */
	if (!ikev2_add_notify(resp, proto, spi,
	    IKEV2_N_NON_FIRST_FRAGMENTS_ALSO, NULL, 0))
		goto fail;

	if (!ikev2_sa_add_result(resp, &csa->csa_results, spi))
		goto fail;

	if (!ikev2_child_add_nonce(csa, resp))
		goto fail;
	ikev2_child_save_nonce(csa, req);

	if (!ikev2_child_add_dh(csa, resp) || !ikev2_child_ke(csa, req))
		goto fail;

	if (!add_ts_resp(req, resp, csa))
		goto fail;

	if (!generate_keys(csa))
		goto fail;

	if (!ikev2_create_child_sas(csa))
		goto fail;

	/* XXX: on failures here we need to be sending appropriates NOTIFYS */

done:
	(void) ikev2_send_resp(resp);
	ikev2_pkt_free(req);
	return;

fail:
	(void) pfkey_delete(proto, spi, pmsg->pmsg_sau, pmsg->pmsg_dau,
	    B_FALSE);

	(void) bunyan_info(log, "Sending NO_PROPOSAL_CHOSEN due to error",
	    BUNYAN_T_END);

	if (!ikev2_no_proposal_chosen(resp, proto))
		ikev2_pkt_free(resp);
	else
		(void) ikev2_send_resp(resp);

	ikev2_pkt_free(req);
}

/*
 * We are initiator, this is the response from the peer.
 *
 * NOTE: Unlike the analogous functions in other exchanges, this one is
 * not static since in the case of an IKE_AUTH exchange, we call this
 * function after doing the IKE_AUTH specific handling as long as we've
 * successfully authenticated (if authentication fails, this is never called).
 *
 * For CREATE_CHILD_SA, this is directly invoked by ikev2_handle_response()
 * in ikev2_proto.c
 */
void
ikev2_create_child_sa_init_resp(ikev2_sa_t *restrict i2sa,
    pkt_t *restrict resp, void *restrict arg)
{
	struct child_sa_args *csa = arg;
	parsedmsg_t *pmsg = csa->csa_pmsg;
	ikev2_sa_result_t result = { 0 };

	if (resp == NULL) {
		if (PMSG_FROM_KERNEL(pmsg))
			pfkey_send_error(pmsg->pmsg_samsg, ETIME);
		csa_args_free(csa);
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

	/* XXX: INVALID_KE */

	if (!ikev2_sa_match_acquire(pmsg, csa->csa_dh, resp,
	    &csa->csa_results)) {
		(void) bunyan_warn(log,
		    "Peer tried to select a transform not in the original"
		    "proposed set", BUNYAN_T_END);
		goto fail;
	}

	ikev2_save_child_results(csa, &csa->csa_results);
	ikev2_child_save_nonce(csa, resp);

	if (!ikev2_child_ke(csa, resp))
		goto fail;

	if (!generate_keys(csa))
		goto fail;

	if (!ikev2_create_child_sas(csa))
		goto fail;

	csa_args_free(csa);
	ikev2_pkt_free(resp);
	return;

fail:
	/* TODO: Information exchange to delete child SAs */
	;

remote_fail:
	if (PMSG_FROM_KERNEL(pmsg))
		pfkey_send_error(pmsg->pmsg_samsg, EINVAL);
	ikev2_pkt_free(resp);
}

/*
 * Translate the addresses from our ACQUIRE message into IKEv2 traffic
 * selectors and add them to our request.
 */
static boolean_t
add_ts_init(pkt_t *restrict req, parsedmsg_t *restrict pmsg)
{
	ikev2_pkt_ts_state_t tstate = { 0 };
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
	if (addr != NULL && !add_sadb_address(&tstate, addr))
		return (B_FALSE);
#endif

	addr = get_sadb_addr(pmsg, B_TRUE);
	if (!add_sadb_address(&tstate, addr))
		return (B_FALSE);

	bzero(&tstate, sizeof (tstate));
	if (!ikev2_add_ts_r(req, &tstate))
		return (B_FALSE);

#ifdef notyet
	addr = (sadb_address_t *)pmsg->pmsg_exts[SADB_X_EXT_ADDRESS_OPD];
	if (addr != NULL && !add_sadb_address(&tstate, addr))
		return (B_FALSE);
#endif

	addr = get_sadb_addr(pmsg, B_FALSE);
	if (!add_sadb_address(&tstate, addr))
		return (B_FALSE);

	return (B_TRUE);
}

static boolean_t
add_ts_resp(pkt_t *restrict req, pkt_t *restrict resp,
    struct child_sa_args *restrict csa)
{
	parsedmsg_t *pmsg = csa->csa_pmsg;
	pkt_payload_t *tspay = NULL;
	sadb_address_t *src_addr = NULL, *dst_addr = NULL;
	ikev2_child_sa_t *in = csa->csa_child_in;
	ikev2_child_sa_t *out = csa->csa_child_out;
	struct sockaddr_storage ts_addr = { 0 };
	uint8_t ts_prefix = 0;
	uint8_t proto = 0;
	boolean_t transport = csa->csa_child_in->i2c_transport;

	src_addr = get_sadb_addr(pmsg, B_TRUE);
	dst_addr = get_sadb_addr(pmsg, B_FALSE);

	/* These come from our kernel policy, so they better match */
	VERIFY3U(src_addr->sadb_address_proto, ==,
	    dst_addr->sadb_address_proto);
	proto = src_addr->sadb_address_proto;

	tspay = pkt_get_payload(req, IKEV2_PAYLOAD_TSr, NULL);
	if (!add_ts_resp_one(tspay, src_addr, resp, &ts_addr, &ts_prefix))
		return (B_FALSE);

	if (transport) {
		in->i2c_lprefix = out->i2c_lprefix = ts_prefix;
		sockaddr_copy(&ts_addr, &in->i2c_laddr, B_TRUE);
		sockaddr_copy(&ts_addr, &out->i2c_laddr, B_TRUE);
	} else {
		in->i2c_inner_lprefix = out->i2c_inner_lprefix = ts_prefix;
		sockaddr_copy(&ts_addr, &in->i2c_inner_laddr, B_TRUE);
		sockaddr_copy(&ts_addr, &out->i2c_inner_laddr, B_TRUE);
	}

	tspay = pkt_get_payload(req, IKEV2_PAYLOAD_TSi, NULL);
	if (!add_ts_resp_one(tspay, dst_addr, resp, &ts_addr, &ts_prefix))
		return (B_FALSE);

	if (transport) {
		in->i2c_rprefix = out->i2c_rprefix = ts_prefix;
		sockaddr_copy(&ts_addr, &in->i2c_raddr, B_TRUE);
		sockaddr_copy(&ts_addr, &out->i2c_raddr, B_TRUE);
	} else {
		in->i2c_inner_rprefix = out->i2c_inner_rprefix = ts_prefix;
		sockaddr_copy(&ts_addr, &in->i2c_inner_raddr, B_TRUE);
		sockaddr_copy(&ts_addr, &out->i2c_inner_raddr, B_TRUE);
	}

	if (!transport) {
		ikev2_sa_t *i2sa = csa->csa_i2sa;
		struct sockaddr_storage *laddr = &i2sa->laddr;
		struct sockaddr_storage *raddr = &i2sa->raddr;

		sockaddr_copy(laddr, &in->i2c_laddr, B_FALSE);
		sockaddr_copy(laddr, &out->i2c_laddr, B_FALSE);
		sockaddr_copy(raddr, &in->i2c_raddr, B_FALSE);
		sockaddr_copy(raddr, &out->i2c_raddr, B_FALSE);

		in->i2c_addr_proto = out->i2c_addr_proto = 0;
		in->i2c_inner_proto = out->i2c_inner_proto = proto;
		in->i2c_lprefix = out->i2c_lprefix = 0;
		in->i2c_rprefix = out->i2c_rprefix = 0;
	} else {
		in->i2c_addr_proto = out->i2c_addr_proto = proto;
	}

	return (B_TRUE);
}

static boolean_t
add_ts_resp_one(pkt_payload_t *restrict tspay,
    sadb_address_t *restrict sadb_addr, pkt_t *restrict resp,
    struct sockaddr_storage *restrict ts_addr, uint8_t *restrict ts_prefixp)
{
	struct sockaddr_storage *restrict acq_addr =
	    (struct sockaddr_storage *restrict)(sadb_addr + 1);
	size_t acq_prefix = sadb_addr->sadb_address_prefixlen;
	uint8_t proto = sadb_addr->sadb_address_proto;
	ikev2_pkt_ts_state_t tstate = { 0 };
	sockrange_t res_range = { 0 };

	/*
	 * If the INVERSE_ACQUIRE returns successfully, there must be some
	 * non-NULL intersection between the proposed addresses and our
	 * policy, even if it's just a single IP.
	 */
	VERIFY(ts_negotiate(tspay, acq_addr, acq_prefix, ts_addr, ts_prefixp));
	net_to_range(SSTOSA(ts_addr), *ts_prefixp, &res_range);

	if (!ikev2_add_ts_r(resp, &tstate))
		return (B_FALSE);
	if (!ikev2_add_ts(&tstate, proto, &res_range))
		return (B_FALSE);

	return (B_TRUE);
}

static boolean_t
check_ts_resp(pkt_t *restrict resp, parsedmsg_t *restrict pmsg)
{
	return (B_TRUE);
}

/*
 * Take a TS{i,r} payload and an address/mask from an ACQUIRE or INVERSE_ACQUIRE
 * and calculate what the resulting address/mask that satisifies both policies.
 */
static boolean_t
ts_negotiate(pkt_payload_t *restrict ts_pay,
    const struct sockaddr_storage *restrict acq_addr, uint8_t acq_prefix,
    struct sockaddr_storage *restrict result, uint8_t *restrict result_prefixp)
{
	ikev2_ts_t *ts = NULL;
	ikev2_ts_iter_t iter = { 0 };
	sockrange_t range = { 0 };
	sockrange_t acq = { 0 };
	sockrange_t res_range = { 0 };

	bzero(result, sizeof (*result));
	*result_prefixp = 0;

	/*
	 * The first traffic selector is what is used during the
	 * INVERSE_ACQUIRE request, however what we get back from the kernel
	 * is a network address + netmask e.g. 192.168.1.0/24 or 10.1.2.3/32
	 * and not an address range (with arbitrary start and ending addresses
	 * as with the traffic selectors).
	 *
	 * This is possibly more permissive than what the peer is proposing.
	 * Therefore, we first constrain the two ranges (TS[0] and ACQUIRE
	 * address) to the intersection of the two.  However, if the original
	 * packet selector was sent, it is sent as the first traffic selector
	 * and the result can be too narrow (i.e. the result will be a single
	 * IP address).  If this is the case, there should be at least one
	 * more traffic selector present, and we should attempt to widen our
	 * range, however the result should never be wider (but may be narrower)
	 * than the range given from the ACQUIRE response from the kernel.
	 * As such, we look through the subsequent selectors looking for the
	 * largest intersection between a given traffic selector and the ACQUIRE
	 * address range.
	 *
	 * Some examples to illustrate:
	 *
	 * Assume our local policy returns an address of 192.168.5.0/24
	 * This could be a source or destination address, the logic is the
	 * same.
	 *
	 * If the initiator sends:
	 *	192.168.5.0 - 192.168.5.255
	 *
	 * We should respond with:
	 *	192.168.5.0 - 192.168.5.255
	 *
	 * If the initiator sends:
	 *	192.168.5.15 - 192.168.5.15
	 *	192.168.5.0 - 192.168.5.255
	 *
	 * We should respond with:
	 *	192.168.5.0 - 192.168.5.255
	 *
	 * If the initiator sends:
	 *	192.168.5.15 - 192.168.5.15
	 *	192.168.4.0 - 192.168.4.255
	 *
	 * We should respond with:
	 *	192.168.5.0 - 192.168.5.255
	 *
	 *	TBD: Should we check to see if there is a policy for
	 *	192.168.4.0/24 and return ADDITIONAL_TS_POSSIBLE w/ our
	 *	response?
	 *
	 * If the initiator sends:
	 *	192.168.5.0 - 192.168.5.127
	 *
	 * We should respond with:
	 *	192.168.5.0 - 192.168.5.127
	 *
	 */

	net_to_range(SSTOSA(acq_addr), acq_prefix, &acq);
	range_log(log, BUNYAN_L_TRACE, "acquire address", &acq);

	ts = ikev2_ts_iter(ts_pay, &iter, &range);
	range_log(log, BUNYAN_L_TRACE, "TS[0] address", &range);

	range_intersection(&acq, &range, &res_range);
	range_log(log, BUNYAN_L_TRACE, "acquire & TS[0]", &res_range);

	while ((ts = ikev2_ts_iter_next(&iter, &range)) != NULL) {
		sockrange_t cmp = { 0 };

		/* cmp = intersection(acq, range) */
		range_intersection(&range, &acq, &cmp);
		if (range_is_empty(&cmp))
			continue;

		if (range_cmp_size(&cmp, &res_range) > 0)
			bcopy(&cmp, &res_range, sizeof (cmp));
	}

	if (range_is_empty(&res_range)) {
		(void) bunyan_trace(log, "Resulting range is empty",
		    BUNYAN_T_END);
		return (B_FALSE);
	}

	range_log(log, BUNYAN_L_TRACE, "resulting range", &res_range);

	/*
	 * As the kernel cannot deal with arbitrary ranges in it's policy,
	 * we must potentially again narrow the result until range (without
	 * changing the starting address) can be expressed as start_addr/mask
	 */
	range_to_net(&res_range, SSTOSA(result), result_prefixp);

	/* XXX: Log */
	return (B_TRUE);
}

/*
 * Take a pf_key(7P) sadb_address extension and convert it into
 * an IKEv2 traffic selector that is added to the TS{i,r} payload being
 * constructed using tstate.
 *
 * An sadb_address consists of an IPv4 or IPv6 address and port, a protocol
 * (TCP, UDP, etc.), and a prefix length. There currently is no way to express
 * a range of ports -- either a specific port is given or 0 for any.  To
 * translate to an IKEv2 traffic selector, we merely use the prefix length to
 * map the address into a subnet range, and then either use the single port
 * or 0-UINT16_MAX for the port range (if 0 was given for the port).
 */
static boolean_t
add_sadb_address(ikev2_pkt_ts_state_t *restrict tstate,
    const sadb_address_t *restrict addr)
{
	sockrange_t range = { 0 };
	uint8_t proto = addr->sadb_address_proto;
	uint8_t prefixlen = addr->sadb_address_prefixlen;

	/*
	 * pf_key uses a prefix length of 0 for single addresses
	 * (instead of 32 or 128). Sigh.
	 */
	if (prefixlen == 0)
		prefixlen = ss_addrbits((struct sockaddr_storage *)(addr + 1));

	net_to_range((struct sockaddr *)(addr + 1), prefixlen, &range);

	return (ikev2_add_ts(tstate, proto, &range));
}

static boolean_t
ikev2_child_add_nonce(struct child_sa_args *restrict csa, pkt_t *restrict pkt)
{
	if (csa->csa_is_auth)
		return (B_TRUE);

	pkt_payload_t *nonce = NULL;
	size_t noncelen = ikev2_prf_outlen(csa->csa_i2sa->prf) / 2;

	if (!ikev2_add_nonce(pkt, NULL, noncelen))
		return (B_FALSE);

	nonce = pkt_get_payload(pkt, IKEV2_PAYLOAD_NONCE, NULL);
	if (INITIATOR(csa)) {
		bcopy(nonce->pp_ptr, csa->csa_nonce_i, nonce->pp_len);
		csa->csa_nonce_i_len = nonce->pp_len;
	} else {
		bcopy(nonce->pp_ptr, csa->csa_nonce_r, nonce->pp_len);
		csa->csa_nonce_r_len = nonce->pp_len;
	}
	return (B_TRUE);
}

static void
ikev2_child_save_nonce(struct child_sa_args *restrict csa, pkt_t *restrict pkt)
{
	if (csa->csa_is_auth)
		return;

	pkt_payload_t *nonce = pkt_get_payload(pkt, IKEV2_PAYLOAD_NONCE, NULL);

	if (INITIATOR(csa)) {
		bcopy(nonce->pp_ptr, csa->csa_nonce_r, nonce->pp_len);
		csa->csa_nonce_r_len = nonce->pp_len;
	} else {
		bcopy(nonce->pp_ptr, csa->csa_nonce_i, nonce->pp_len);
		csa->csa_nonce_i_len = nonce->pp_len;
	}
}

static boolean_t
ikev2_child_add_dh(struct child_sa_args *restrict csa, pkt_t *restrict pkt)
{
	if (csa->csa_is_auth || csa->csa_dh == IKEV2_DH_NONE)
		return (B_TRUE);

	if (!dh_genpair(csa->csa_dh, &csa->csa_pubkey, &csa->csa_privkey))
		return (B_FALSE);

	if (!ikev2_add_ke(pkt, csa->csa_dh, csa->csa_pubkey))
		return (B_FALSE);

	return (B_TRUE);
}

static boolean_t
ikev2_child_ke(struct child_sa_args *restrict csa, pkt_t *restrict pkt)
{
	if (csa->csa_is_auth || csa->csa_dh == IKEV2_DH_NONE)
		return (B_TRUE);

	pkt_payload_t *ke_pay = pkt_get_payload(pkt, IKEV2_PAYLOAD_KE, NULL);
	uint8_t *ke = ke_pay->pp_ptr + sizeof (ikev2_ke_t);
	size_t kelen = ke_pay->pp_len - sizeof (ikev2_ke_t);

	if (!dh_derivekey(csa->csa_privkey, ke, kelen, &csa->csa_dhkey))
		return (B_FALSE);

	return (B_TRUE);
}

/*
 * Queries kernel for IPsec policy for IPs in TS{i,r} payloads from initiator.
 * Result in saved in csa->csa_pmsg (set to NULL if no policy found).
 *
 * If there was an error looking up the policy (not found is not considered
 * an error), return B_FALSE, otherwise B_TRUE.
 */
static boolean_t
get_resp_policy(pkt_t *restrict pkt, struct child_sa_args *restrict csa)
{
	ikev2_sa_t *i2sa = pkt->pkt_sa;
	pkt_payload_t *ts_ip = pkt_get_payload(pkt, IKEV2_PAYLOAD_TSi, NULL);
	pkt_payload_t *ts_rp = pkt_get_payload(pkt, IKEV2_PAYLOAD_TSr, NULL);
	struct sockaddr_storage ss_src = { 0 };
	struct sockaddr_storage ss_dst = { 0 };
	struct sockaddr_storage ss_isrc = { 0 };
	struct sockaddr_storage ss_idst = { 0 };
	sockaddr_u_t src = { .sau_ss = &ss_src };
	sockaddr_u_t dst = { .sau_ss = &ss_dst };
	sockaddr_u_t isrc = { .sau_ss = &ss_isrc };
	sockaddr_u_t idst = { .sau_ss = &ss_idst };
	ikev2_ts_t *ts_i = NULL;
	ikev2_ts_t *ts_r = NULL;
	uint8_t ts_proto = 0, tsi_prefix = 0, tsr_prefix = 0;

	sockaddr_copy(&i2sa->raddr, &ss_dst, B_FALSE);
	sockaddr_copy(&i2sa->laddr, &ss_src, B_FALSE);

	if (TRANSPORT_MODE(csa)) {
		isrc.sau_ss = NULL;
		idst.sau_ss = NULL;
	} else {
		ts_i = first_ts_addr(ts_ip, &ss_idst, &tsi_prefix);
		ts_r = first_ts_addr(ts_rp, &ss_isrc, &tsr_prefix);

		if (ts_i->ts_protoid != ts_r->ts_protoid) {
			/* XXX: log */
			return (B_FALSE);
		}
		ts_proto = ts_i->ts_protoid;
	}

	if (pfkey_inverse_acquire(src, dst, ts_proto, isrc, tsi_prefix,
	    idst, tsr_prefix, &csa->csa_pmsg))
		return (B_TRUE);

	if (csa->csa_pmsg == NULL || csa->csa_pmsg->pmsg_samsg == NULL)
		return (B_FALSE);

	sadb_msg_t *m = csa->csa_pmsg->pmsg_samsg;

	switch (m->sadb_msg_errno) {
	case ENOENT:
		(void) bunyan_warn(log,
		    "No policy found for proposed IPsec traffic",
		    BUNYAN_T_END);
		parsedmsg_free(csa->csa_pmsg);
		csa->csa_pmsg = NULL;
		return (B_TRUE);
	/* XXX: Other possible errors? */
	default:
		TSTDERR(m->sadb_msg_errno, warn,
		    "Error while looking up IPsec policy",
		    BUNYAN_T_STRING, "diagmsg",
		    keysock_diag(m->sadb_x_msg_diagnostic),
		    BUNYAN_T_UINT32, "diagcode",
		    (uint32_t)m->sadb_x_msg_diagnostic);
	}
	parsedmsg_free(csa->csa_pmsg);
	csa->csa_pmsg = NULL;
	return (B_FALSE);
}

static void
check_natt_addrs(pkt_t *restrict pkt, boolean_t transport_mode)
{
	ikev2_sa_t *i2sa = pkt->pkt_sa;

	if (pkt_header(pkt)->exch_type != IKEV2_EXCH_IKE_AUTH)
		return;

	if (transport_mode) {
		pkt_payload_t *ts_ip = NULL;
		pkt_payload_t *ts_rp = NULL;
		ikev2_ts_t *ts_i = NULL;
		ikev2_ts_t *ts_r = NULL;
		struct sockaddr_storage loc = { 0 };
		struct sockaddr_storage rem = { 0 };
		boolean_t init = !!(i2sa->flags & I2SA_INITIATOR);

		ts_ip = pkt_get_payload(pkt, IKEV2_PAYLOAD_TSi, NULL);
		ts_rp = pkt_get_payload(pkt, IKEV2_PAYLOAD_TSr, NULL);

		ts_i = first_ts_addr(ts_ip, init ? &loc : &rem, NULL);
		ts_r = first_ts_addr(ts_rp, init ? &rem : &loc, NULL);

		/*
		 * XXX: The results here should match the NAT_DETECTION_*
		 * notification checks (but those can't tell us the actual
		 * internal IPs).  What to do if there's a mismatch?
		 */
		if (!SA_ADDR_EQ(&i2sa->laddr, &loc)) {
			if (!(i2sa->flags & I2SA_NAT_LOCAL)) {
				/* TODO: log */
			}
			sockaddr_copy(&loc, &i2sa->lnatt, B_TRUE);
		}
		if (!SA_ADDR_EQ(&i2sa->raddr, &rem)) {
			if (!(i2sa->flags & I2SA_NAT_REMOTE)) {
				/* TODO: log */
			}
			sockaddr_copy(&rem, &i2sa->rnatt, B_TRUE);
		}
	}

	if (i2sa->lnatt.ss_family != AF_UNSPEC) {
		(void) bunyan_info(log, "Local NATT address",
		    ss_bunyan(&i2sa->lnatt), "address", ss_addr(&i2sa->lnatt),
		    BUNYAN_T_END);
	}
	if (i2sa->rnatt.ss_family != AF_UNSPEC) {
		(void) bunyan_info(log, "Remote NATT address",
		    ss_bunyan(&i2sa->rnatt), "address", ss_addr(&i2sa->rnatt),
		    BUNYAN_T_END);
	}
}

static void
ikev2_save_child_results(struct child_sa_args *restrict csa,
    const ikev2_sa_result_t *restrict results)
{
	ikev2_child_sa_t *in = csa->csa_child_in;
	ikev2_child_sa_t *out = csa->csa_child_out;

	/*
	 * The outbound SPI is set from the SADB_GETSPI call, the inbound is
	 * taken from the peer's SA payload (saved in ikev2_sa_result_t)
	 */
	in->i2c_spi = results->sar_spi;

	in->i2c_satype = out->i2c_satype = results->sar_proto;
	in->i2c_encr = out->i2c_encr = results->sar_encr;
	in->i2c_auth = out->i2c_auth = results->sar_auth;
	in->i2c_encr_keylen = out->i2c_encr_keylen = results->sar_encr_keylen;
	in->i2c_dh = out->i2c_dh = results->sar_dh;
}

/* Sends the pf_key(7P) messages to establish the IPsec SAs */
static boolean_t
ikev2_create_child_sas(struct child_sa_args *restrict csa)
{
	ikev2_sa_t *sa = csa->csa_i2sa;
	sadb_msg_t *samsg = NULL;

	if (PMSG_FROM_KERNEL(csa->csa_pmsg))
		samsg = csa->csa_pmsg->pmsg_samsg;

	if (!pfkey_sadb_add_update(sa, csa->csa_child_in,
	    csa->csa_child_in_encr, csa->csa_child_in_auth, samsg))
		return (B_FALSE);

	ikev2_sa_add_child(sa, csa->csa_child_in);
	csa->csa_added_child_in = B_TRUE;
	csa->csa_child_out->i2c_pair = csa->csa_child_in;

	if (!pfkey_sadb_add_update(sa, csa->csa_child_out,
	    csa->csa_child_out_encr, csa->csa_child_out_auth, samsg))
		return (B_FALSE);

	ikev2_sa_add_child(sa, csa->csa_child_out);
	csa->csa_added_child_out = B_TRUE;
	csa->csa_child_in->i2c_pair = csa->csa_child_out;

	return (B_TRUE);
}

static boolean_t
generate_keys(struct child_sa_args *csa)
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
		{ csa->csa_nonce_i, csa->csa_nonce_i_len },
		{ csa->csa_nonce_r, csa->csa_nonce_r_len },
		{ NULL, 0 }
	};
	size_t idx = 1;		/* index of first arg to prfplus_init */
	prfp_t prfp = { 0 };
	uint8_t *init_encr = NULL, *init_auth = NULL;
	uint8_t *resp_encr = NULL, *resp_auth = NULL;
	size_t encrlen = 0, authlen = 0;
	boolean_t ret = B_FALSE;

	if (INITIATOR(csa)) {
		init_encr = csa->csa_child_out_encr;
		init_auth = csa->csa_child_out_auth;
		resp_encr = csa->csa_child_in_encr;
		resp_auth = csa->csa_child_in_auth;
	} else {
		init_encr = csa->csa_child_in_encr;
		init_auth = csa->csa_child_in_auth;
		resp_encr = csa->csa_child_out_encr;
		resp_auth = csa->csa_child_out_auth;
	}

	if (csa->csa_dhkey != CK_INVALID_HANDLE) {
		CK_RV rv = CKR_OK;

		rv = pkcs11_ObjectToKey(p11h(), csa->csa_dhkey,
		    (void **)&prfp_args[0].ptr, &prfp_args[0].len, B_FALSE);
		if (rv != CKR_OK) {
			PKCS11ERR(error, "pkcs11_ObjectToKey",
			    rv, BUNYAN_T_STRING, "objname", "gir");
			return (B_FALSE);
		}

		idx = 0;
	}

	ret = prfplus_init(&prfp, csa->csa_i2sa->prf, csa->csa_i2sa->sk_d,
	    prfp_args[idx].ptr, prfp_args[idx].len,
	    prfp_args[idx + 1].ptr, prfp_args[idx + 1].len,
	    prfp_args[idx + 2].ptr, prfp_args[idx + 2].len,
	    NULL);

	explicit_bzero(prfp_args[0].ptr, prfp_args[0].len);
	free(prfp_args[0].ptr);

	if (!ret)
		return (B_FALSE);

	/* Sanity checks that both pairs agree on algs and key lengths */
	VERIFY3S(csa->csa_child_in->i2c_encr, ==, csa->csa_child_out->i2c_encr);
	VERIFY3S(csa->csa_child_in->i2c_auth, ==, csa->csa_child_out->i2c_auth);
	VERIFY3U(csa->csa_child_in->i2c_encr_keylen, ==,
	    csa->csa_child_out->i2c_encr_keylen);

	encrlen = SADB_1TO8(csa->csa_child_in->i2c_encr_keylen);
	authlen = auth_data[csa->csa_child_in->i2c_auth].ad_keylen;

	VERIFY3U(encrlen, <=, ENCR_MAX);
	VERIFY3U(authlen, <=, AUTH_MAX);

	/*
	 * We always generate keys in the order of initiator first, then
	 * responder.  For each side, we always start with encryption keys
	 * then authentication keys.
	 */
	ret = prfplus(&prfp, init_encr, encrlen) &&
	    prfplus(&prfp, init_auth, authlen) &&
	    prfplus(&prfp, resp_encr, encrlen) &&
	    prfplus(&prfp, resp_auth, authlen);

done:
	prfplus_fini(&prfp);
	return (ret);
}


static struct child_sa_args *
create_csa_args(ikev2_sa_t *restrict i2sa, boolean_t is_auth,
    boolean_t initiator)
{
	struct child_sa_args *csa = umem_zalloc(sizeof (*csa), UMEM_DEFAULT);

	if (csa == NULL) {
		(void) bunyan_warn(log,
		   "Unable to allocate memory for child sa negotiation",
		    BUNYAN_T_END);
		return (NULL);
	}

	csa->csa_i2sa = i2sa;
	csa->csa_child_in = ikev2_child_sa_alloc(B_TRUE);
	csa->csa_child_out = ikev2_child_sa_alloc(B_FALSE);
	if (csa->csa_child_in == NULL || csa->csa_child_out == NULL) {
		(void) bunyan_warn(log,
		    "Unable to allocate memory for child SAs",
		    BUNYAN_T_END);
		csa_args_free(csa);
		return (NULL);
	}

	csa->csa_is_auth = is_auth;

	/*
	 * RFC7296 2.17 - For an IKE_AUTH exchange, we reuse the nonces
	 * from the IKE_SA_INIT exchange.  For a CREATE_CHILD_SA
	 * exchange, we create new ones when we add the payloads to
	 * our outgoing packet.  We also can only perform an optional DH
	 * key exchange during a CREATE_CHILD_SA exchange -- for an IKE_AUTH
	 * exchange, we cannot perform a DH key exchange (we instead rely on
	 * the exchange done during the IKE_SA_INIT exchange).
	 */
	if (is_auth) {
		pkt_payload_t *ni = NULL;
		pkt_payload_t *nr = NULL;

		ni = pkt_get_payload(i2sa->init_i, IKEV2_PAYLOAD_NONCE, NULL);
		nr = pkt_get_payload(i2sa->init_r, IKEV2_PAYLOAD_NONCE, NULL);

		bcopy(ni->pp_ptr, csa->csa_nonce_i, ni->pp_len);
		bcopy(nr->pp_ptr, csa->csa_nonce_r, nr->pp_len);
		csa->csa_nonce_i_len = ni->pp_len;
		csa->csa_nonce_r_len = nr->pp_len;
	} else {
		csa->csa_dh = i2sa->i2sa_rule->rule_p2_dh;
	}

	csa->csa_child_in->i2c_initiator = csa->csa_child_out->i2c_initiator =
	    initiator;

	return (csa);
}

static void
csa_args_free(struct child_sa_args *csa)
{
	if (csa == NULL)
		return;

	pkcs11_destroy_obj("child dh_pubkey", &csa->csa_pubkey);
	pkcs11_destroy_obj("child dh_privkey", &csa->csa_privkey);
	pkcs11_destroy_obj("child gir", &csa->csa_dhkey);

	if (!csa->csa_added_child_in)
		ikev2_child_sa_free(csa->csa_i2sa, csa->csa_child_in);
	if (!csa->csa_added_child_out)
		ikev2_child_sa_free(csa->csa_i2sa, csa->csa_child_out);

	explicit_bzero(csa, sizeof (*csa));
	umem_free(csa, sizeof (*csa));
}

/*
 * XXX: Just return the first non-UNSPEC SATYPE found.
 * This is very temporary until more of the CREATE_CHILD_SA stuff is complete.
 */
static uint8_t
get_satype(parsedmsg_t *pmsg)
{
	sadb_msg_t *msg = pmsg->pmsg_samsg;
	sadb_prop_t *prop = (sadb_prop_t *)pmsg->pmsg_exts[SADB_X_EXT_EPROP];
	sadb_x_ecomb_t *ecomb = NULL;

	if (prop == NULL || msg->sadb_msg_satype != SADB_SATYPE_UNSPEC)
		return (msg->sadb_msg_satype);

	ecomb = (sadb_x_ecomb_t *)(prop + 1);
	for (size_t i = 0; i < prop->sadb_x_prop_numecombs; i++) {
		sadb_x_algdesc_t *alg = (sadb_x_algdesc_t *)(ecomb + 1);

		for (size_t j = 0; j < ecomb->sadb_x_ecomb_numalgs;
		   j++, alg++) {
			if (alg->sadb_x_algdesc_satype != SADB_SATYPE_UNSPEC)
				return (alg->sadb_x_algdesc_satype);
		}

		prop = (sadb_prop_t *)alg;
	}

	return (SADB_SATYPE_UNSPEC);
}

/*
 * Get the sadb address from a parsed message that will actually be subjected
 * to IPsec.  For transport mode, this is the SRC/DST address, while for
 * tunnel mode, this is the inner SRC/DST address.  'src' determines if
 * we want the appropirate SRC or DST address.
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

static ikev2_ts_t *
first_ts_addr(pkt_payload_t *restrict tspay,
    struct sockaddr_storage *restrict addr,
    uint8_t *prefixp)
{
	ikev2_ts_t *ts = NULL;
	ikev2_ts_iter_t iter = { 0 };
	sockrange_t range = { 0 };
	uint8_t prefix = 0;

	VERIFY(tspay->pp_type == IKEV2_PAYLOAD_TSi ||
	    tspay->pp_type == IKEV2_PAYLOAD_TSr);

	ts = ikev2_ts_iter(tspay, &iter, &range);
	range_to_net(&range, SSTOSA(addr), &prefix);
	if (prefixp != NULL) {
		VERIFY3U(prefix, <=, UINT8_MAX);
		*prefixp = prefix;
	}
	return (ts);
}
