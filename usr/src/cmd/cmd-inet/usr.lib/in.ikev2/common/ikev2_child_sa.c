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

#include <sys/debug.h>
#include "config.h"
#include "ikev2.h"
#include "ikev2_common.h"
#include "ikev2_pkt.h"
#include "ikev2_proto.h"
#include "ikev2_sa.h"
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
	ikev2_sa_result_t result = { 0 };
	uint32_t spi = 0;
	ikev2_dh_t dh = IKEV2_DH_NONE;

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

	/* XXX: inverse acquire */

	if (!ikev2_sa_match_acquire(pmsg, dh, req, &result)) {
		int proto = 0, spi = 0; /* XXX: Set me! */

		ikev2_no_proposal_chosen(req, proto, spi);
		goto fail;
	}

	if (!ikev2_sa_add_result(resp, &result))
		goto fail;

	/* XXX: TSi & TSr payloads */

	/* XXX: Create IPsec SA */

	if (!ikev2_send(resp, B_FALSE))
		goto fail;

	ikev2_pkt_free(req);
	return;

fail:
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
	uint32_t spi = 0;

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
