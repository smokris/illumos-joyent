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

#include <pthread.h>
#include <umem.h>
#include <err.h>
#include <sys/debug.h>
#include <bunyan.h>
#include <time.h>
#include <string.h>
#include "defs.h"
#include "worker.h"
#include "pkt.h"
#include "timer.h"
#include "pkcs11.h"
#include "ikev2_proto.h"
#include "ikev2_sa.h"
#include "config.h"
#include "ikev2_pkt.h"
#include "ikev2_enum.h"

static boolean_t add_nat(pkt_t *, boolean_t);
static int check_nat(pkt_t *, pkt_notify_t *);

void
ikev2_sa_init_inbound(pkt_t *pkt)
{
	ikev2_sa_t *sa = pkt->pkt_sa;
	pkt_t *resp = NULL;
	sockaddr_u_t laddr = { .sau_ss = &sa->laddr };
	sockaddr_u_t raddr = { .sau_ss = &sa->raddr };

	resp = ikev2_pkt_new_response(pkt);
	if (resp == NULL) {
		ikev2_pkt_free(pkt);
		return;
	}

	sa->i2sa_rule = config_get_rule(&laddr, &raddr);
	if (sa->i2sa_rule == NULL) {
		sa->i2sa_cfg = config_get();
	} else {
		sa->i2sa_cfg = sa->i2sa_rule->rule_config;
		CONFIG_REFHOLD(sa->i2sa_cfg);
	}

	if (sa->i2sa_rule == NULL && sa->i2sa_cfg->cfg_xforms[0] == NULL) {
		if (ikev2_add_notify(resp, IKEV2_PROTO_IKE, 0,
		    IKEV2_N_NO_PROPOSAL_CHOSEN, 0, NULL, 0))
			(void) ikev2_send(resp, B_TRUE);

		ikev2_pkt_free(pkt);
		CONFIG_REFRELE(sa->i2sa_cfg);
		return;
	}
}

void
ikev2_sa_init_outbound(ikev2_sa_t *i2sa)
{
}

#define	NAT_LEN	(20)
static int
check_nat(pkt_t *pkt, pkt_notify_t *n)
{
	bunyan_logger_t *l = pkt->pkt_sa->i2sa_log;
	CK_SESSION_HANDLE h = p11h;
	sockaddr_u_t addr;
	CK_MECHANISM mech = { .mechanism = CKM_SHA_1 };
	buf_t buf[3];
	CK_BYTE data[NAT_LEN] = { 0 };
	buf_t out = { .b_ptr = data, .b_len = sizeof (data) };
	CK_LONG len = 0;
	CK_RV rv;

	switch (n->pn_type) {
	case IKEV2_N_NAT_DETECTION_SOURCE_IP:
		addr.sau_ss = &pkt->pkt_sa->laddr;
		break;
	case IKEV2_N_NAT_DETECTION_DESTINATION_IP:
		addr.sau_ss = &pkt->pkt_sa->raddr;
		break;
	default:
		INVALID(n->pn_type);
		/*NOTREACHED*/
		return (-1);
	}

	buf[0].b_ptr = (CK_BYTE_PTR)&pkt->pkt_raw;
	buf[0].b_len = 2 * sizeof (uint64_t);

	switch (addr.sau_ss->ss_family) {
	case AF_INET:
		buf[1].b_ptr = (CK_BYTE_PTR)&addr.sau_sin->sin_addr;
		buf[1].b_len = sizeof (in_addr_t);
		buf[2].b_ptr = (CK_BYTE_PTR)&addr.sau_sin->sin_port;
		buf[2].b_len = sizeof (addr.sau_sin->sin_port);
		break;
	case AF_INET6:
		buf[1].b_ptr = (CK_BYTE_PTR)&addr.sau_sin6->sin6_addr;
		buf[1].b_len = sizeof (in6_addr_t);
		buf[2].b_ptr = (CK_BYTE_PTR)&addr.sau_sin6->sin6_port;
		buf[2].b_len = sizeof (addr.sau_sin6->sin6_port);
		break;
	default:
		INVALID("addr.sau_ss->ss_family");
		return (-1);
	}

	if (n->pn_len != NAT_LEN) {
		bunyan_error(l, "Invalid notify payload size",
		    BUNYAN_T_STRING, "notify_type",
		    ikev2_notify_str(n->pn_type),
		    BUNYAN_T_UINT32, "payload_size", (uint32_t)n->pn_len,
		    BUNYAN_T_UINT32, "expected_size", (uint32_t)NAT_LEN,
		    BUNYAN_T_END);
		return (-1);
	}

	if (!pkcs11_digest(CKM_SHA_1, buf, ARRAY_SIZE(buf), &out, l))
		return (-1);

	VERIFY3U(n->pn_len, ==, sizeof (data));
	if (memcmp(n->pn_ptr, data, sizeof (data)) == 0)
		return (0);

	return (1);
}

static boolean_t
add_nat(pkt_t *pkt, boolean_t source)
{
	bunyan_logger_t *l = pkt->pkt_sa->i2sa_log;
	sockaddr_u_t addr;
	uint64_t spi[2];
	uchar_t data[NAT_LEN];
	ikev2_notify_type_t ntype;
	buf_t buf[3];
	buf_t out = { .b_ptr = data, .b_len = sizeof (data) };

	if (source)
		addr.sau_ss = &pkt->pkt_sa->laddr;
	else
		addr.sau_ss = &pkt->pkt_sa->raddr;

	spi[0] = htonll(pkt->pkt_header.initiator_spi);
	spi[1] = htonll(pkt->pkt_header.responder_spi);

	buf[0].b_ptr = (CK_BYTE_PTR)&spi;
	buf[0].b_len = sizeof (spi);

	switch (addr.sau_ss->ss_family) {
	case AF_INET:
		buf[1].b_ptr = (CK_BYTE_PTR)&addr.sau_sin->sin_addr;
		buf[1].b_len = sizeof (in_addr_t);
		buf[2].b_ptr = (CK_BYTE_PTR)&addr.sau_sin->sin_port;
		buf[2].b_len = sizeof (addr.sau_sin->sin_port);
		break;
	case AF_INET6:
		buf[1].b_ptr = (CK_BYTE_PTR)&addr.sau_sin6->sin6_addr;
		buf[1].b_len = sizeof (in6_addr_t);
		buf[2].b_ptr = (CK_BYTE_PTR)&addr.sau_sin6->sin6_port;
		buf[2].b_len = sizeof (addr.sau_sin6->sin6_port);
		break;
	default:
		INVALID("addr.sau_ss->ss_family");
		return (B_FALSE);
	}

	if (!pkcs11_digest(CKM_SHA_1, buf, ARRAY_SIZE(buf), &out, l))
		return (B_FALSE);

	if (source)
		ntype = IKEV2_N_NAT_DETECTION_SOURCE_IP;
	else
		ntype = IKEV2_N_NAT_DETECTION_DESTINATION_IP;

	if (!ikev2_add_notify(pkt, IKEV2_PROTO_IKE, 0, ntype, 0, data,
	    sizeof (data)))
		return (B_FALSE);

	return (B_TRUE);
}
