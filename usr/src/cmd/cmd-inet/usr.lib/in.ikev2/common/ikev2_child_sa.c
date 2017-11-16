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
#include "worker.h"

struct child_sa_args {
	parsedmsg_t		*csa_pmsg;
	sadb_msg_t		*csa_srcmsg;
	uint8_t			csa_nonce_i[IKEV2_NONCE_MAX];
	size_t			csa_nonce_i_len;
	uint8_t			csa_nonce_r[IKEV2_NONCE_MAX];
	size_t			csa_nonce_r_len;
	uint32_t		csa_local_spi;
	uint32_t		csa_remote_spi;
	ikev2_dh_t		csa_dh;
	ikev2_sa_result_t	csa_results;
	boolean_t		csa_is_auth;
	boolean_t		csa_transport_mode;
};

static boolean_t ikev2_create_child_sa_init_common(ikev2_sa_t *restrict,
    pkt_t *restrict req, struct child_sa_args *restrict);
static void save_p1_nonces(ikev2_sa_t *restrict,
    struct child_sa_args *restrict);
static boolean_t create_keymat(ikev2_sa_t *restrict, boolean_t,
    uint8_t *restrict, size_t,
    uint8_t *restrict, size_t, prfp_t *restrict);
static boolean_t ikev2_create_child_sas(ikev2_sa_t *restrict,
    struct child_sa_args *restrict, boolean_t);
static boolean_t add_ts_init(pkt_t *restrict, parsedmsg_t *restrict);
static boolean_t add_ts_resp(pkt_t *restrict, pkt_t *restrict,
    parsedmsg_t *restrict);
static boolean_t resp_inv_acquire(pkt_t *restrict,
    struct child_sa_args *restrict);
static void check_natt_addrs(pkt_t *restrict, boolean_t);
static uint8_t get_satype(parsedmsg_t *);
static sadb_address_t *get_sadb_addr(parsedmsg_t *, boolean_t);

void *
ikev2_create_child_sa_init_auth(ikev2_sa_t *restrict sa, pkt_t *restrict req,
    parsedmsg_t *pmsg)
{
	struct child_sa_args *csa = NULL;

	VERIFY(IS_WORKER);
	VERIFY(!MUTEX_HELD(&sa->i2sa_queue_lock));
	VERIFY(MUTEX_HELD(&sa->i2sa_lock));
	VERIFY3U(pkt_header(req)->exch_type, ==, IKEV2_EXCH_IKE_AUTH);

	csa = umem_zalloc(sizeof (*csa), UMEM_DEFAULT);
	if (csa == NULL) {
		(void) bunyan_error(log,
		    "No memory to perform CREATE_CHILD_SA exchange",
		    BUNYAN_T_END);
		pfkey_send_error(pmsg->pmsg_samsg, ENOMEM);
		parsedmsg_free(pmsg);
		return (NULL);
	}

	csa->csa_is_auth = B_TRUE;
	csa->csa_pmsg = pmsg;
	csa->csa_srcmsg = PMSG_FROM_KERNEL(pmsg) ? pmsg->pmsg_samsg : NULL;

	save_p1_nonces(sa, csa);

	if (!ikev2_create_child_sa_init_common(sa, req, csa)) {
		explicit_bzero(csa, sizeof (*csa));
		umem_free(csa, sizeof (*csa));
		return (NULL);
	}

	return (csa);
}

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

	csa = umem_zalloc(sizeof (*csa), UMEM_DEFAULT);
	if (csa == NULL) {
		(void) bunyan_error(log,
		    "No memory to perform CREATE_CHILD_SA exchange",
		    BUNYAN_T_END);
		goto fail;
	}

	csa->csa_pmsg = pmsg;
	csa->csa_srcmsg = pmsg->pmsg_samsg;
	csa->csa_dh = sa->i2sa_rule->rule_p2_dh;

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
	if (csa != NULL) {
		explicit_bzero(csa, sizeof (*csa));
		umem_free(csa, sizeof (*csa));
	}
}

/* We are the initiator */
static boolean_t
ikev2_create_child_sa_init_common(ikev2_sa_t *restrict sa, pkt_t *restrict req,
    struct child_sa_args *restrict csa)
{
	parsedmsg_t *pmsg = csa->csa_pmsg;
	sockaddr_u_t src = { .sau_ss = &sa->laddr };
	sockaddr_u_t dest = { .sau_ss = &sa->raddr };
	ikev2_dh_t dh = IKEV2_DH_NONE;
	ikev2_spi_proto_t proto = satype_to_ikev2(get_satype(pmsg));
	uint8_t satype;
	boolean_t transport_mode = B_FALSE;

	if (pmsg->pmsg_isau.sau_ss == NULL)
		csa->csa_transport_mode = transport_mode = B_TRUE;

	satype = get_satype(pmsg);
	if (!pfkey_getspi(csa->csa_srcmsg, pmsg->pmsg_sau, pmsg->pmsg_dau,
	    satype, &csa->csa_local_spi)) {
		goto fail;
	}

	/* XXX: IPcomp (when we add support) */

	if (transport_mode && !ikev2_add_notify(req, proto, csa->csa_local_spi,
	    IKEV2_N_USE_TRANSPORT_MODE, NULL, 0))
		goto fail;

	if (!ikev2_add_notify(req, proto, csa->csa_local_spi,
	    IKEV2_N_ESP_TFC_PADDING_NOT_SUPPORTED, NULL, 0))
		goto fail;

	if (!ikev2_add_notify(req, proto, csa->csa_local_spi,
	    IKEV2_N_NON_FIRST_FRAGMENTS_ALSO, NULL, 0))
		goto fail;

	if (!ikev2_sa_from_acquire(req, pmsg, csa->csa_local_spi, dh))
		goto fail;

	if (!csa->csa_is_auth) {
		pkt_payload_t *nonce = NULL;
		size_t noncelen = ikev2_prf_outlen(sa->prf) / 2;

		if (!ikev2_add_nonce(req, NULL, noncelen))
			goto fail;

		nonce = pkt_get_payload(req, IKEV2_PAYLOAD_NONCE, NULL);
		(void) memcpy(csa->csa_nonce_i, nonce->pp_ptr, nonce->pp_len);
		csa->csa_nonce_i_len = nonce->pp_len;
	}

	if (!add_ts_init(req, pmsg))
		goto fail;

	return (B_TRUE);

fail:
	(void) pfkey_delete(satype, csa->csa_local_spi, pmsg->pmsg_sau,
	    pmsg->pmsg_dau, B_FALSE);

	return (B_FALSE);
}

static void ikev2_create_child_sa_resp_common(pkt_t *restrict, pkt_t *restrict,
    struct child_sa_args *restrict);

void
ikev2_create_child_sa_resp_auth(pkt_t *restrict req, pkt_t *restrict resp)
{
	struct child_sa_args csa = { .csa_is_auth = B_TRUE };

	VERIFY3U(pkt_header(resp)->exch_type, ==, IKEV2_EXCH_IKE_AUTH);

	save_p1_nonces(req->pkt_sa, &csa);
	ikev2_create_child_sa_resp_common(req, resp, &csa);
}

void
ikev2_create_child_sa_resp(pkt_t *restrict req)
{
	struct child_sa_args csa = { 0 };
	pkt_t *resp = ikev2_pkt_new_response(req);

	if (resp == NULL) {
		ikev2_pkt_free(req);
		return;
	}

	/* It's the first payload, it should fit */
	VERIFY(ikev2_add_sk(resp));
	csa.csa_dh = req->pkt_sa->i2sa_rule->rule_p2_dh;
	ikev2_create_child_sa_resp_common(req, resp, &csa);
}

/*
 * We are the responder.
 */
static void
ikev2_create_child_sa_resp_common(pkt_t *restrict req, pkt_t *restrict resp,
    struct child_sa_args *restrict csa)
{
	ikev2_sa_t *sa = req->pkt_sa;
	parsedmsg_t *pmsg = NULL;

	if (pkt_get_notify(req, IKEV2_N_USE_TRANSPORT_MODE, NULL) != NULL)
		csa->csa_transport_mode = B_TRUE;

	if (csa->csa_is_auth)
		check_natt_addrs(req, csa->csa_transport_mode);

	if (!resp_inv_acquire(req, csa))
		goto fail;

	if ((pmsg = csa->csa_pmsg) == NULL) {
		/*
		 * XXX: Should we pick off the protocol from the SA payload and
		 * use that instead?
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
	csa->csa_remote_spi = csa->csa_results.sar_spi;

	if (!csa->csa_is_auth && ikev2_get_dhgrp(req) !=
	    csa->csa_results.sar_dh) {
		if (!ikev2_invalid_ke(resp, csa->csa_results.sar_proto, 0,
		    csa->csa_results.sar_dh))
			goto fail;
		goto done;
	}

	if (!pfkey_getspi(NULL, pmsg->pmsg_sau, pmsg->pmsg_dau,
	    csa->csa_results.sar_proto, &csa->csa_local_spi))
		goto fail;

	if (csa->csa_transport_mode &&
	    !ikev2_add_notify(resp, csa->csa_results.sar_proto,
	    csa->csa_local_spi, IKEV2_N_USE_TRANSPORT_MODE, NULL, 0))
		goto fail;

	/* We currently don't support TFC PADDING */
	if (!ikev2_add_notify(resp, csa->csa_results.sar_proto,
	    csa->csa_local_spi, IKEV2_N_ESP_TFC_PADDING_NOT_SUPPORTED, NULL, 0))
		goto fail;

	/* and we always include non-first fragments */
	if (!ikev2_add_notify(resp, csa->csa_results.sar_proto,
	    csa->csa_local_spi, IKEV2_N_NON_FIRST_FRAGMENTS_ALSO, NULL, 0))
		goto fail;

	if (!ikev2_sa_add_result(resp, &csa->csa_results, csa->csa_local_spi))
		goto fail;

	if (!csa->csa_is_auth) {
		pkt_payload_t *ni = NULL, *nr = NULL;
		size_t noncelen = ikev2_prf_outlen(sa->prf) / 2;

		if (!ikev2_add_nonce(resp, NULL, noncelen))
			goto fail;

		ni = pkt_get_payload(req, IKEV2_PAYLOAD_NONCE, NULL);
		nr = pkt_get_payload(resp, IKEV2_PAYLOAD_NONCE, NULL);

		bcopy(ni->pp_ptr, csa->csa_nonce_i, ni->pp_len);
		bcopy(nr->pp_ptr, csa->csa_nonce_r, nr->pp_len);
		csa->csa_nonce_i_len = ni->pp_len;
		csa->csa_nonce_r_len = nr->pp_len;
	}

	if (!csa->csa_is_auth && csa->csa_results.sar_dh != IKEV2_DH_NONE) {
		pkt_payload_t *ke_i = NULL;
		uint8_t *ke = NULL;
		size_t kelen = 0;

		ke_i = pkt_get_payload(req, IKEV2_PAYLOAD_KE, NULL);

		/*
		 * XXX: If we ever support window sizes > 1, and can have
		 * multiple CREATE_CHILD_SA exchanges in flight, we will
		 * probably need to change this to support multiple DH
		 * keys
		 */
		if (ke_i == NULL || ke_i->pp_len <= sizeof (ikev2_ke_t)) {
			(void) bunyan_info(log,
			    "CREATE_CHILD_SA initiator negotiated a DH group "
			    "but didn't provide a public key", BUNYAN_T_END);
			goto fail;
		}

		/* Skip over fixed portion of payload */
		ke = ke_i->pp_ptr + sizeof (ikev2_ke_t);
		kelen = ke_i->pp_len - sizeof (ikev2_ke_t);

		if (!dh_genpair(csa->csa_results.sar_dh, &sa->dh_pubkey,
		    &sa->dh_privkey))
			goto fail;
		if (!dh_derivekey(sa->dh_privkey, ke, kelen, &sa->dh_key))
			goto fail;
		if (!ikev2_add_ke(resp, csa->csa_results.sar_dh, sa->dh_pubkey))
			goto fail;
	}

	if (!add_ts_resp(req, resp, pmsg))
		goto fail;

	if (!ikev2_create_child_sas(sa, csa, B_FALSE))
		goto fail;

	/* XXX: on failures here we need to be sending appropriates NOTIFYS */

done:
	(void) ikev2_send_resp(resp);
	/* Don't reuse the same DH key for additional child SAs */
	pkcs11_destroy_obj("child dh_pubkey", &sa->dh_pubkey);
	pkcs11_destroy_obj("child dh_privkey", &sa->dh_privkey);
	pkcs11_destroy_obj("child gir", &sa->dh_key);
	ikev2_pkt_free(req);
	return;

fail:
	pkcs11_destroy_obj("child dh_pubkey", &sa->dh_pubkey);
	pkcs11_destroy_obj("child dh_privkey", &sa->dh_privkey);
	pkcs11_destroy_obj("child gir", &sa->dh_key);

	(void) bunyan_info(log, "Sending NO_PROPOSAL_CHOSEN due to error",
	    BUNYAN_T_END);

	if (!ikev2_no_proposal_chosen(resp, csa->csa_results.sar_proto))
		ikev2_pkt_free(resp);
	else
		(void) ikev2_send_resp(resp);

	ikev2_pkt_free(req);
}

/*
 * We are initiator, this is the response from the peer.
 *
 * NOTE: Unlike the analogous functions in other exchanges, this one is
 * not static since in the case of an IKE_AUTH exchange, we chain this
 * function after doing the IKE_AUTH specific handling.
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
		explicit_bzero(csa, sizeof (*csa));
		umem_free(csa, sizeof (*csa));
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

	if (!ikev2_sa_match_acquire(pmsg, csa->csa_dh, resp,
	    &csa->csa_results)) {
		/* TODO: log */
		(void) bunyan_warn(log, "SA no likey", BUNYAN_T_END);
		goto fail;
	}
	csa->csa_remote_spi = csa->csa_results.sar_spi;

	if (!csa->csa_is_auth) {
		pkt_payload_t *nr = NULL;

		nr = pkt_get_payload(resp, IKEV2_PAYLOAD_NONCE, NULL);
		if (nr == NULL) {
			/* TODO: log */
			(void) bunyan_warn(log, "No nonce is here",
			    BUNYAN_T_END);
			goto fail;
		}

		(void) memcpy(csa->csa_nonce_r, nr->pp_ptr, nr->pp_len);
		csa->csa_nonce_r_len = nr->pp_len;
	}

	if (!csa->csa_is_auth && csa->csa_results.sar_dh != IKEV2_DH_NONE) {
		pkt_payload_t *ke = NULL;
		uint8_t *kep = NULL;
		size_t kelen = 0;

		ke = pkt_get_payload(resp, IKEV2_PAYLOAD_KE, NULL);
		if (ke == NULL || ke->pp_len <= sizeof (ikev2_ke_t)) {
			/* TODO: log */
			(void) bunyan_warn(log, "Where's the KE?",
			    BUNYAN_T_END);
			goto fail;
		}

		kep = ke->pp_ptr + sizeof (ikev2_ke_t);
		kelen = ke->pp_len - sizeof (ikev2_ke_t);

		if (!dh_derivekey(i2sa->dh_privkey, kep, kelen, &i2sa->dh_key))
			goto fail;
	}

	if (!ikev2_create_child_sas(i2sa, csa, B_TRUE))
		goto fail;

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
 * This takes a pf_key(7P) sadb_address extension and converts it into
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
	struct sockaddr_storage ss_start = { 0 };
	struct sockaddr_storage ss_end = { 0 };
	uint8_t proto = addr->sadb_address_proto;
	uint8_t prefixlen = addr->sadb_address_prefixlen;

	const char *msg = (tstate->i2ts_idx->pp_type == IKEV2_PAYLOAD_TSi) ?
	    "Adding to TSi payload" : "Adding to TSr payload";

	/*
	 * pf_key uses a mask of 0 for single addresses (instead of /32 or /128)
	 */
	if (prefixlen == 0)
		prefixlen = ss_addrbits((struct sockaddr_storage *)(addr + 1));

	net_to_range((struct sockaddr_storage *)(addr + 1), prefixlen,
	    &ss_start, &ss_end);

	return (ikev2_add_ts(tstate, proto, &ss_start, &ss_end));
}

static boolean_t
add_ts_init(pkt_t *restrict req, parsedmsg_t *restrict pmsg)
{
	ikev2_pkt_ts_state_t tstate = { 0 };
	sadb_address_t *addr = NULL;

	if (!ikev2_add_ts_i(req, &tstate))
		return (B_FALSE);

#ifdef notyet
	addr = (sadb_address_t *)pmsg->pmsg_exts[SADB_X_EXT_ADDRESS_OPS];
	if (addr != NULL && !add_sadb_address(&tstate, addr))
		return (B_FALSE);
#endif
	addr = get_sadb_addr(pmsg, B_TRUE);
	if (!add_sadb_address(&tstate, addr))
		return (B_FALSE);

	(void) memset(&tstate, 0, sizeof (tstate));
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

static void resp_ts_negotiate_one(struct sockaddr_storage *restrict,
    struct sockaddr_storage *restrict, pkt_payload_t *restrict,
    const struct sockaddr_storage *restrict, uint8_t);

static boolean_t
add_ts_resp(pkt_t *restrict req, pkt_t *restrict resp,
    parsedmsg_t *restrict pmsg)
{
	pkt_payload_t *tspay = NULL;
	sadb_address_t *addr = NULL;
	struct sockaddr_storage *acq_addr = NULL;
	ikev2_pkt_ts_state_t tstate = { 0 };
	struct sockaddr_storage start = { 0 };
	struct sockaddr_storage end = { 0 };
	uint8_t proto = 0;
	uint8_t prefixlen = 0;

	tspay = pkt_get_payload(req, IKEV2_PAYLOAD_TSr, NULL);

	addr = get_sadb_addr(pmsg, B_TRUE);
	proto = addr->sadb_address_proto;
	acq_addr = (struct sockaddr_storage *)(addr + 1);
	prefixlen = addr->sadb_address_prefixlen;
	if (prefixlen == 0)
		prefixlen = ss_addrbits(acq_addr);
	resp_ts_negotiate_one(&start, &end, tspay, acq_addr, prefixlen);

	/*
	 * If the INVERSE_ACQUIRE returns successfully, there must be some
	 * non-NULL intersection between the proposed addresses and our
	 * policy, even if it's just a single IP.
	 */
	VERIFY(!range_is_zero(&start, &end));

	if (!ikev2_add_ts_r(resp, &tstate))
		return (B_FALSE);
	if (!ikev2_add_ts(&tstate, proto, &start, &end))
		return (B_FALSE);

	tspay = pkt_get_payload(req, IKEV2_PAYLOAD_TSi, NULL);
	addr = get_sadb_addr(pmsg, B_FALSE);
	proto = addr->sadb_address_proto;
	acq_addr = (struct sockaddr_storage *)(addr + 1);
	prefixlen = addr->sadb_address_prefixlen;
	if (prefixlen == 0)
		prefixlen = ss_addrbits(acq_addr);
	resp_ts_negotiate_one(&start, &end, tspay, acq_addr, prefixlen);

	/* Same argument as above */
	VERIFY(!range_is_zero(&start, &end));

	if (!ikev2_add_ts_i(resp, &tstate))
		return (B_FALSE);
	if (!ikev2_add_ts(&tstate, proto, &start, &end))
		return (B_FALSE);

	return (B_TRUE);
}

static void
resp_ts_negotiate_one(struct sockaddr_storage *restrict res_start,
    struct sockaddr_storage *restrict res_end, pkt_payload_t *restrict ts_pay,
    const struct sockaddr_storage *restrict acq_addr, uint8_t acq_mask)
{
	ikev2_ts_t *ts = NULL;
	ikev2_ts_iter_t iter = { 0 };
	struct sockaddr_storage start = { 0 };
	struct sockaddr_storage end = { 0 };
	struct sockaddr_storage acq_start = { 0 };
	struct sockaddr_storage acq_end = { 0 };

	bzero(res_start, sizeof (*res_start));
	bzero(res_end, sizeof (*res_end));

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
	 * range, however the result should never be wider (but may be narrower
	 * than the range given from the ACQUIRE response from the kernel).
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

	net_to_range(acq_addr, acq_mask, &acq_start, &acq_end);
	log_range(log, BUNYAN_L_DEBUG, "acquire address", &acq_start, &acq_end);

	ts = ikev2_ts_iter(ts_pay, &iter, &start, &end);
	log_range(log, BUNYAN_L_DEBUG, "TS[0] address", &start, &end);

	range_intersection(res_start, res_end, &start, &end, &acq_start,
	    &acq_end);
	log_range(log, BUNYAN_L_DEBUG, "acquire ∩ TS[0]", res_start, res_end);

	while ((ts = ikev2_ts_iter_next(&iter, &start, &end)) != NULL) {
		struct sockaddr_storage cmp_start = { 0 };
		struct sockaddr_storage cmp_end = { 0 };
		int cmp;

		range_intersection(&cmp_start, &cmp_end, res_start, res_end,
		    &acq_start, &acq_end);

		if (range_is_zero(&cmp_start, &cmp_end))
			continue;

		cmp = range_cmp_size(&cmp_start, &cmp_end, res_start, res_end);

		if (cmp > 0) {
			bcopy(&cmp_start, res_start, sizeof (*res_start));
			bcopy(&cmp_end, res_end, sizeof (*res_end));
		}
	}

	/*
	 * As the kernel cannot deal with arbitrary ranges in it's policy,
	 * we must potentially again narrow the result until range (without
	 * changing the starting address) can be expressed as start_addr/mask
	 */
	range_clamp(res_start, res_end);
}

/*
 * Queries kernel for IPsec policy for IPs in TS{i,r} payloads and
 * saves result in csa (may be NULL if no policy found).
 *
 * Return B_FALSE if there was an error looking up the policy (note: no policy
 * found is not considered an error), B_TRUE otherwise.
 */
static boolean_t
resp_inv_acquire(pkt_t *restrict pkt, struct child_sa_args *restrict csa)
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
	ikev2_ts_iter_t iter_i = { 0 };
	ikev2_ts_iter_t iter_r = { 0 };
	ikev2_ts_t *ts_i = NULL;
	ikev2_ts_t *ts_r = NULL;

	sockaddr_copy(&i2sa->raddr, &ss_dst, B_FALSE);
	sockaddr_copy(&i2sa->laddr, &ss_src, B_FALSE);

	if (csa->csa_transport_mode) {
		isrc.sau_ss = NULL;
		idst.sau_ss = NULL;
	} else {
		ts_i = ikev2_ts_iter(ts_ip, &iter_i, &ss_idst, NULL);
		ts_r = ikev2_ts_iter(ts_rp, &iter_r, &ss_isrc, NULL);
	}

	if (pfkey_inverse_acquire(src, dst, isrc, idst, &csa->csa_pmsg))
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

	if (transport_mode) {
		pkt_payload_t *ts_ip = NULL;
		pkt_payload_t *ts_rp = NULL;
		ikev2_ts_t *ts_i = NULL;
		ikev2_ts_t *ts_r = NULL;
		ikev2_ts_iter_t iter_i = { 0 };
		ikev2_ts_iter_t iter_r = { 0 };
		struct sockaddr_storage loc = { 0 };
		struct sockaddr_storage rem = { 0 };
		boolean_t init = !!(i2sa->flags & I2SA_INITIATOR);

		ts_ip = pkt_get_payload(pkt, IKEV2_PAYLOAD_TSi, NULL);
		ts_rp = pkt_get_payload(pkt, IKEV2_PAYLOAD_TSr, NULL);

		ts_i = ikev2_ts_iter(ts_ip, &iter_i, init ? &loc : &rem, NULL);
		ts_r = ikev2_ts_iter(ts_rp, &iter_r, init ? &rem : &loc, NULL);

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

/* Sends the pf_key(7P) messages to establish the IPsec SAs */
static boolean_t
ikev2_create_child_sas(ikev2_sa_t *restrict sa,
    struct child_sa_args *restrict csa, boolean_t initiator)
{
	ikev2_sa_result_t *results = &csa->csa_results;
	uint8_t *encrkey_i = NULL, *encrkey_r = NULL;
	uint8_t *authkey_i = NULL, *authkey_r = NULL;
	size_t encrlen = 0;
	size_t authlen = 0;
	prfp_t prfp = { 0 };
	boolean_t ret = B_FALSE;
	boolean_t use_dh = B_FALSE;

	if (results->sar_encr != IKEV2_ENCR_NONE) {
		encrlen = results->sar_encr_keylen;
		if (encrlen == 0)
			encrlen = encr_data[results->sar_encr].ed_keydefault;
		encrlen = SADB_1TO8(encrlen);

		encrkey_i = umem_zalloc(encrlen, UMEM_DEFAULT);
		encrkey_r = umem_zalloc(encrlen, UMEM_DEFAULT);
		if (encrkey_i == NULL || encrkey_r == NULL) {
			/* TODO: log */
			goto done;
		}
	}

	if (results->sar_auth != IKEV2_XF_AUTH_NONE) {
		authlen = auth_data[results->sar_auth].ad_keylen;
		authkey_i = umem_zalloc(authlen, UMEM_DEFAULT);
		authkey_r = umem_zalloc(authlen, UMEM_DEFAULT);
		if (authkey_i == NULL || authkey_r == NULL) {
			/* TODO: log */
			goto done;
		}
	}

	if (!csa->csa_is_auth && results->sar_dh != IKEV2_DH_NONE)
		use_dh = B_TRUE;

	if (!create_keymat(sa, use_dh, csa->csa_nonce_i, csa->csa_nonce_i_len,
	    csa->csa_nonce_r, csa->csa_nonce_r_len, &prfp))
		goto done;

	if (encrkey_i != NULL && !prfplus(&prfp, encrkey_i, encrlen))
		goto done;
	if (authkey_i != NULL && !prfplus(&prfp, authkey_i, authlen))
		goto done;
	if (encrkey_r != NULL && !prfplus(&prfp, encrkey_r, encrlen))
		goto done;
	if (authkey_r != NULL && !prfplus(&prfp, authkey_r, authlen))
		goto done;

	if (!pfkey_sadb_add_update(sa, csa->csa_local_spi, results,
	    csa->csa_pmsg,
	    initiator ? encrkey_i : encrkey_r, encrlen,
	    initiator ? authkey_i : authkey_r, authlen,
	    0, initiator, B_FALSE))
		goto done;

	if (!pfkey_sadb_add_update(sa, csa->csa_remote_spi, results,
	    csa->csa_pmsg,
	    initiator ? encrkey_r : encrkey_i, encrlen,
	    initiator ? authkey_r : authkey_i, authlen,
	    csa->csa_local_spi, initiator, B_TRUE))
		goto done;

	ret = B_TRUE;

done:
	if (encrkey_i != NULL) {
		explicit_bzero(encrkey_i, encrlen);
		umem_free(encrkey_i, encrlen);
	}
	if (encrkey_r != NULL) {
		explicit_bzero(encrkey_r, encrlen);
		umem_free(encrkey_r, encrlen);
	}
	if (authkey_i != NULL) {
		explicit_bzero(authkey_i, authlen);
		umem_free(authkey_i, authlen);
	}
	if (authkey_r != NULL) {
		explicit_bzero(authkey_r, authlen);
		umem_free(authkey_r, authlen);
	}
	prfplus_fini(&prfp);
	return (ret);
}

static boolean_t
create_keymat(ikev2_sa_t *restrict sa, boolean_t use_dh,
    uint8_t *restrict ni, size_t ni_len,
    uint8_t *restrict nr, size_t nr_len, prfp_t *restrict prfp)
{
	boolean_t ret = B_FALSE;

	if (use_dh) {
		uint8_t *gir = NULL;
		size_t girlen = 0;
		CK_RV rv = CKR_OK;

		rv = pkcs11_ObjectToKey(p11h(), sa->dh_key, (void **)&gir,
		    &girlen, B_FALSE);
		if (rv != CKR_OK) {
			PKCS11ERR(error, "pkcs11_ObjectToKey",
			    rv, BUNYAN_T_STRING, "objname", "gir");
			return (B_FALSE);
		}

		ret = prfplus_init(prfp, sa->prf, sa->sk_d,
		    gir, girlen, ni, ni_len, nr, nr_len, NULL);

		explicit_bzero(gir, girlen);
		free(gir);
	} else {
		ret = prfplus_init(prfp, sa->prf, sa->sk_d,
		    ni, ni_len, nr, nr_len, NULL);
	}
	return (ret);
}

static void
save_p1_nonces(ikev2_sa_t *restrict i2sa, struct child_sa_args *restrict csa)
{
	pkt_payload_t *ni = NULL;
	pkt_payload_t *nr = NULL;

	ni = pkt_get_payload(i2sa->init_i, IKEV2_PAYLOAD_NONCE, NULL);
	nr = pkt_get_payload(i2sa->init_r, IKEV2_PAYLOAD_NONCE, NULL);

	bcopy(ni->pp_ptr, csa->csa_nonce_i, ni->pp_len);
	bcopy(nr->pp_ptr, csa->csa_nonce_r, nr->pp_len);
	csa->csa_nonce_i_len = ni->pp_len;
	csa->csa_nonce_r_len = nr->pp_len;
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

static sadb_address_t *
get_sadb_addr(parsedmsg_t *pmsg, boolean_t src)
{
	sadb_ext_t *ext = NULL;
	uint_t first = src ?
	    SADB_X_EXT_ADDRESS_INNER_SRC : SADB_X_EXT_ADDRESS_INNER_DST;
	uint_t alt = src ?  SADB_EXT_ADDRESS_SRC : SADB_EXT_ADDRESS_DST;

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
