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

static boolean_t find_config(pkt_t *, pkt_t *, sockaddr_u_t, sockaddr_u_t);
static boolean_t add_nat(pkt_t *);
static boolean_t check_nats(pkt_t *);
static void check_vendor(pkt_t *);
static boolean_t add_vendor(pkt_t *);

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

	if (!find_config(pkt, resp, laddr, raddr)) {
		ikev2_pkt_free(pkt);
		return;
	}

	if (!check_nats(pkt)) {
		ikev2_pkt_free(pkt);
		return;
	}
	check_vendor(pkt);

}

void
ikev2_sa_init_outbound(ikev2_sa_t *i2sa)
{
	pkt_t *pkt = NULL;

	pkt = ikev2_pkt_new_initiator(i2sa, IKEV2_EXCH_IKE_SA_INIT);

	/* XXX: COOKIE */
	/* XXX: SA */
	/* XXX: KE */
	/* XXX: Ni */

	if (!add_nat(pkt) ||
	    !add_vendor(pkt)) {
		ikev2_pkt_free(pkt);
		/* XXX: destroy SA */
		return;
	}

	/* XXX: CERTREQ */
}

static boolean_t
find_config(pkt_t *pkt, pkt_t *resp, sockaddr_u_t laddr, sockaddr_u_t raddr)
{
	ikev2_sa_t *sa = pkt->pkt_sa;

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
		return (B_FALSE);
	}
	return (B_TRUE);
}

#define	NAT_LEN	(20)
/*
 * Check if the NAT {src,dest} payload matches our IP address.
 * Return 0 if match (i.e. no nat)
 *     1 if match
 *     -1 on error
 */
static int
check_one_nat(pkt_t *pkt, pkt_notify_t *n)
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

/*
 * Perform NAT detection and update IKEV2 SA accordingly.  Return B_FALSE on
 * error, B_TRUE if no error.
 */
static boolean_t
check_nats(pkt_t *pkt)
{
	ikev2_sa_t *sa = pkt->pkt_sa;
	boolean_t local_nat = B_TRUE;
	boolean_t remote_nat = B_TRUE;

	for (uint16_t i = 0; i < pkt->pkt_notify_count; i++) {
		pkt_notify_t *n = pkt_notify(pkt, i);
		int rc;

		/*
		 * While we know which IPs we send from, it's permissible
		 * that an implementation may not, and may instead send
		 * multiple NAT notification payloads.  Thus is any of them
		 * match, we know there is NOT nat involved for that direction.
		 */
		switch (n->pn_type) {
		case IKEV2_N_NAT_DETECTION_SOURCE_IP:
		case IKEV2_N_NAT_DETECTION_DESTINATION_IP:
			rc = check_one_nat(pkt, n);
			if (rc == -1)
				return (B_FALSE);
			if (rc == 0) {
				if (n->pn_type ==
				    IKEV2_N_NAT_DETECTION_SOURCE_IP)
					remote_nat = B_FALSE;
				else
					local_nat = B_FALSE;
			}
			break;
		}
	}

	if (local_nat) {
		sa->flags |= I2SA_NAT_LOCAL;
		bunyan_debug(sa->i2sa_log, "Local NAT detected", BUNYAN_T_END);
	}

	if (remote_nat) {
		sa->flags |= I2SA_NAT_REMOTE;
		bunyan_debug(sa->i2sa_log, "Remote NAT detected", BUNYAN_T_END);
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
	bunyan_logger_t *l = pkt->pkt_sa->i2sa_log;
	sockaddr_u_t addr[2];
	uint64_t spi[2];
	ikev2_notify_type_t ntype[2];
	buf_t buf[3];

	addr[0].sau_ss = &pkt->pkt_sa->laddr;
	addr[1].sau_ss = &pkt->pkt_sa->raddr;
	ntype[0] = IKEV2_N_NAT_DETECTION_SOURCE_IP;
	ntype[1] = IKEV2_N_NAT_DETECTION_DESTINATION_IP;

	/*
	 * These normally don't get converted to network byte order until
	 * the packet has finished construction, so we need to do local
	 * conversion for the NAT payload creation
	 */
	spi[0] = htonll(pkt->pkt_header.initiator_spi);
	spi[1] = htonll(pkt->pkt_header.responder_spi);

	buf[0].b_ptr = (CK_BYTE_PTR)&spi;
	buf[0].b_len = sizeof (spi);

	for (int i = 0; i < 2; i++) {
		uchar_t data[NAT_LEN] = { 0 };
		buf_t out = { .b_ptr = data, .b_len = sizeof (data) };

		switch (addr[i].sau_ss->ss_family) {
		case AF_INET:
			buf[1].b_ptr = (CK_BYTE_PTR)&addr[i].sau_sin->sin_addr;
			buf[1].b_len = sizeof (in_addr_t);
			buf[2].b_ptr = (CK_BYTE_PTR)&addr[i].sau_sin->sin_port;
			buf[2].b_len = sizeof (addr[i].sau_sin->sin_port);
			break;
		case AF_INET6:
			buf[1].b_ptr =
			    (CK_BYTE_PTR)&addr[i].sau_sin6->sin6_addr;
			buf[1].b_len = sizeof (in6_addr_t);
			buf[2].b_ptr =
			    (CK_BYTE_PTR)&addr[i].sau_sin6->sin6_port;
			buf[2].b_len = sizeof (addr[i].sau_sin6->sin6_port);
			break;
		default:
			INVALID("addr.sau_ss->ss_family");
			return (B_FALSE);
		}

		if (!pkcs11_digest(CKM_SHA_1, buf, ARRAY_SIZE(buf), &out, l))
			return (B_FALSE);

		if (!ikev2_add_notify(pkt, IKEV2_PROTO_IKE, 0, ntype[i], 0,
		     data, sizeof (data)))
			return (B_FALSE);
	}

	return (B_TRUE);
}

static void
check_vendor(pkt_t *pkt)
{
	ikev2_sa_t *sa = pkt->pkt_sa;

	for (uint16_t i = 0; i < pkt->pkt_payload_count; i++) {
		pkt_payload_t *pay = pkt_payload(pkt, i);

		if (pay->pp_type != IKEV2_PAYLOAD_VENDOR)
			continue;
		if (pay->pp_len != sizeof (VENDOR_STR_ILLUMOS_1))
			continue;

		if (memcmp(VENDOR_STR_ILLUMOS_1, pay->pp_ptr,
		    sizeof (VENDOR_STR_ILLUMOS_1)) == 0)
			sa->vendor = VENDOR_ILLUMOS_1;
	}
}

static boolean_t
add_vendor(pkt_t *pkt)
{
	return (ikev2_add_vendor(pkt, (uchar_t *)VENDOR_STR_ILLUMOS_1,
	    sizeof (VENDOR_STR_ILLUMOS_1)));
}
