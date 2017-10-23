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

static void ikev2_create_child_sa_inbound_init(pkt_t *restrict,
    pkt_t *restrict);
static void ikev2_create_child_sa_inbound_resp(pkt_t *);

void
ikev2_create_child_sa_inbound(pkt_t *restrict pkt, pkt_t *restrict resp)
{
	VERIFY(IS_WORKER);
	VERIFY(MUTEX_HELD(&pkt->pkt_sa->i2sa_lock));

	if (pkt_header(pkt)->flags & IKEV2_FLAG_INITIATOR) {
		ikev2_create_child_sa_inbound_init(pkt, resp);
	} else {
		VERIFY3P(resp, ==, NULL);
		ikev2_create_child_sa_inbound_resp(pkt);
	}
}

/*
 * We are the responder.
 */
static void
ikev2_create_child_sa_inbound_init(pkt_t *restrict req, pkt_t *restrict resp)
{
	ikev2_sa_t *sa = req->pkt_sa;
	parsedmsg_t *pmsg = NULL;
	pkt_payload_t *ts_i = NULL;
	pkt_payload_t *ts_r = NULL;
	sockaddr_u_t src, dest, isrc, idest;
	ikev2_sa_result_t result = { 0 };
	uint32_t spi = 0;
	ikev2_dh_t dh = IKEV2_DH_NONE;
	boolean_t transport_mode = B_FALSE;

	if (resp != NULL) {
		VERIFY3U(pkt_header(resp)->exch_type, ==, IKEV2_EXCH_IKE_AUTH);
	} else {
		resp = ikev2_pkt_new_response(req);
		if (resp == NULL)
			goto fail;
		if (!ikev2_add_sk(resp))
			goto fail;

		dh = sa->i2sa_rule->rule_p2_dh;
	}

	ts_i = pkt_get_payload(req, IKEV2_PAYLOAD_TSi, NULL);
	ts_r = pkt_get_payload(req, IKEV2_PAYLOAD_TSr, NULL);

	/* We are the responder, so source is the initiator, dest is us */
	src.sau_ss = &sa->raddr;
	dest.sau_ss = &sa->laddr;

	if (pkt_get_notify(req, IKEV2_N_USE_TRANSPORT_MODE, NULL) != NULL) {
		isrc.sau_ss = NULL;
		idest.sau_ss = NULL;
		transport_mode = B_TRUE;
	} else {
		/* XXX: Extract inner src/dest from TS payloads */
	}

	if (!pfkey_inverse_acquire(src, dest, isrc, idest, &pmsg))
		goto fail;

	if (!ikev2_sa_match_acquire(pmsg, dh, req, &result)) {
		if (!ikev2_no_proposal_chosen(resp, result.sar_proto))
			goto fail;
		goto done;
	}

	if (ikev2_get_dhgrp(req) != result.sar_dh) {
		if (!ikev2_invalid_ke(resp, result.sar_proto, 0, result.sar_dh))
			goto fail;
		goto done;
	}

	if (transport_mode && !ikev2_add_notify(resp, result.sar_proto,
	    result.sar_spi, IKEV2_N_USE_TRANSPORT_MODE, NULL, 0))
		goto fail;
	/* We currently never support this */
	if (!ikev2_add_notify(resp, result.sar_proto, result.sar_spi,
	    IKEV2_N_ESP_TFC_PADDING_NOT_SUPPORTED, NULL, 0))
		goto fail;
	if (!ikev2_add_notify(resp, result.sar_proto, result.sar_spi,
	    IKEV2_N_NON_FIRST_FRAGMENTS_ALSO, NULL, 0))
		goto fail;
	if (!ikev2_sa_add_result(resp, &result))
		goto fail;

	if (pkt_header(resp)->exch_type != IKEV2_EXCH_IKE_AUTH) {
		pkt_payload_t *ke_i = pkt_get_payload(req, IKEV2_PAYLOAD_KE,
		    NULL);

		if (!ikev2_add_nonce(resp, NULL, ikev2_prf_keylen(sa->prf) / 2))
			goto fail;
		/*
		 * XXX: If we ever support window sizes > 1, and can have
		 * multiple CREATE_CHILD_SA exchanges in flight, we will
		 * probably need to change this to support multiple DH
		 * keys
		 */
		if (result.sar_dh != IKEV2_DH_NONE) {
			if (ke_i == NULL) {
				/* XXX: msg */
				goto fail;
			}
			if (!dh_genpair(result.sar_dh, &sa->dh_pubkey,
			    &sa->dh_privkey, sa->i2sa_log))
				goto fail;
			if (!dh_derivekey(sa->dh_privkey,
			    ke_i->pp_ptr + sizeof (ikev2_ke_t),
			    ke_i->pp_len - sizeof (ikev2_ke_t), &sa->dh_key,
			    sa->i2sa_log))
				goto fail;
			if (!ikev2_add_ke(resp, result.sar_dh,
			    sa->dh_pubkey))
				goto fail;
		}
	}
	/* XXX: TSi & TSr payloads */

	/* XXX: Create IPsec SA */

done:
	if (!ikev2_send(resp, B_FALSE))
		goto fail;

	/* Don't reuse the same DH key for additional child SAs */
	pkcs11_destroy_obj("child dh_pubkey", &sa->dh_pubkey, sa->i2sa_log);
	pkcs11_destroy_obj("child dh_privkey", &sa->dh_privkey, sa->i2sa_log);
	pkcs11_destroy_obj("child gir", &sa->dh_key, sa->i2sa_log);
	ikev2_pkt_free(req);
	return;

fail:
	pkcs11_destroy_obj("child dh_pubkey", &sa->dh_pubkey, sa->i2sa_log);
	pkcs11_destroy_obj("child dh_privkey", &sa->dh_privkey, sa->i2sa_log);
	pkcs11_destroy_obj("child gir", &sa->dh_key, sa->i2sa_log);
	ikev2_pkt_free(req);
	ikev2_pkt_free(resp);
}

void
ikev2_create_child_sa_outbound(ikev2_sa_t *restrict sa, pkt_t *restrict req)
{
	VERIFY(IS_WORKER);
	VERIFY(MUTEX_HELD(&sa->i2sa_lock));

	parsedmsg_t *pmsg = list_head(&sa->i2sa_pending);
	sockaddr_u_t src = { .sau_ss = &sa->laddr };
	sockaddr_u_t dest = { .sau_ss = &sa->raddr };
	ikev2_dh_t dh = IKEV2_DH_NONE;
	ikev2_spi_proto_t proto =
	    satype_to_ikev2(pmsg->pmsg_samsg->sadb_msg_satype);
	uint32_t spi = 0;
	boolean_t transport_mode = B_FALSE;

	if (pmsg->pmsg_isau.sau_ss == NULL)
		transport_mode = B_TRUE;

	if (req != NULL) {
		VERIFY3U(pkt_header(req)->exch_type, ==, IKEV2_EXCH_IKE_AUTH);
	} else {
		req = ikev2_pkt_new_exchange(sa, IKEV2_EXCH_CREATE_CHILD_SA);
		if (req == NULL)
			return;

		dh = sa->i2sa_rule->rule_p2_dh;
		if (!ikev2_add_sk(req))
			goto fail;
	}

	if (!pfkey_getspi(src, dest, pmsg->pmsg_samsg->sadb_msg_satype, &spi))
		goto fail;
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
	if (!ikev2_send(req, B_FALSE))
		goto fail;

fail:
	/* XXX: Delete larval IPsec SA */
	ikev2_pkt_free(req);
}

static void
ikev2_create_child_sa_inbound_resp(pkt_t *resp)
{
}

static boolean_t
create_keymat(ikev2_sa_t *restrict sa, pkt_payload_t *restrict ni,
    pkt_payload_t *restrict nr, prfp_t *restrict prfp)
{
	boolean_t ret = B_FALSE;

	if (sa->dh_key != CK_INVALID_HANDLE) {
		uint8_t *gir = NULL;
		size_t girlen = 0;
		CK_RV rv = CKR_OK;

		rv = pkcs11_ObjectToKey(p11h(), sa->dh_key, (void **)&gir,
		    &girlen, B_FALSE);
		if (rv != CKR_OK) {
			PKCS11ERR(error, sa->i2sa_log, "pkcs11_ObjectToKey",
			    rv, BUNYAN_T_STRING, "objname", "gir");
			return (B_FALSE);
		}

		ret = prfplus_init(prfp, sa->prf, sa->sk_d, sa->i2sa_log,
		    gir, girlen,
		    ni->pp_ptr, ni->pp_len,
		    nr->pp_ptr, nr->pp_len,
		    NULL);

		explicit_bzero(gir, girlen);
		free(gir);
	} else {
		ret = prfplus_init(prfp, sa->prf, sa->sk_d, sa->i2sa_log,
		    ni->pp_ptr, ni->pp_len,
		    nr->pp_ptr, nr->pp_len,
		    NULL);
	}
	return (ret);
}
