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
#include "ikev2_common.h"
#include "prf.h"
#include "dh.h"

static void ikev2_sa_init_inbound_init(pkt_t *);
static void ikev2_sa_init_inbound_resp(pkt_t *);

static boolean_t find_config(pkt_t *, sockaddr_u_t, sockaddr_u_t);
static boolean_t add_nat(pkt_t *);
static boolean_t check_nats(pkt_t *);
static void check_vendor(pkt_t *);
static boolean_t add_vendor(pkt_t *);
static boolean_t add_cookie(pkt_t *restrict, void *restrict, size_t len);
static boolean_t ikev2_sa_keygen(ikev2_sa_result_t *restrict, pkt_t *restrict,
    pkt_t *restrict);

void
ikev2_sa_init_inbound(pkt_t *pkt)
{
	if (pkt->pkt_header.flags & IKEV2_FLAG_INITIATOR)
		ikev2_sa_init_inbound_init(pkt);
	else
		ikev2_sa_init_inbound_resp(pkt);
}

/*
 * New inbound IKE_SA_INIT exchange, we are the responder.
 */
static void
ikev2_sa_init_inbound_init(pkt_t *pkt)
{
	ikev2_sa_t *sa = pkt->pkt_sa;
	pkt_t *resp = NULL;
	sockaddr_u_t laddr = { .sau_ss = &sa->laddr };
	sockaddr_u_t raddr = { .sau_ss = &sa->raddr };
	pkt_payload_t *ke_i = pkt_get_payload(pkt, IKEV2_PAYLOAD_KE, NULL);
	ikev2_sa_result_t sa_result = { 0 };
	size_t noncelen = 0;

	/* Verify inbound sanity checks */
	VERIFY(!(sa->flags & I2SA_INITIATOR));
	VERIFY3P(ke_i, !=, NULL);

	bunyan_info(sa->i2sa_log,
	    "Starting new IKE_SA_INIT exchange as responder",
	    BUNYAN_T_END);

	if (!find_config(pkt, laddr, raddr))
		goto fail;
	if (!check_nats(pkt))
		goto fail;
	check_vendor(pkt);

	if (!ikev2_sa_match_rule(sa->i2sa_rule, pkt, &sa_result)) {
		/*
		 * It seems very unlikely that an initiator will be able to
		 * react and resend a new payload in this situation (as opposed
		 * to a DH group mismatch or if we were to respond with a
		 * cookie).  Therefore, we can delete the larval IKE SA.
		 */
		ikev2_no_proposal_chosen(sa, pkt, IKEV2_PROTO_IKE, 0);
		goto fail;
	}

	/*
	 * A bit annoying, but it's possible the negotiated DH group is
	 * different than the public key value that was sent in the IKE_SA_INIT
	 * exchange.  In that case, we respond with an INVALID_KE_PAYLOAD
	 * notification and include the result we want.  In this instance, we
	 * expect that the initiator will respond with a new KE payload
	 * containing the desired DH group (and otherwise identical).
	 * Therefore, keep the larval IKE SA around until we either proceed to
	 * an AUTH exchange, or we time out.
	 */
	if (ikev2_get_dhgrp(pkt) != sa_result.sar_dh) {
		ikev2_invalid_ke(pkt, IKEV2_PROTO_IKE, 0, sa_result.sar_dh);
		ikev2_pkt_free(pkt);
		return;
	}

	sa->init_r = pkt;

	/* RFC7296 2.10 nonce length should be at least half key size of PRF */
	noncelen = ikev2_prf_keylen(sa_result.sar_prf) / 2;

	/* But must still be within defined limits */
	if (noncelen < IKEV2_NONCE_MIN)
		noncelen = IKEV2_NONCE_MIN;
	if (noncelen > IKEV2_NONCE_MAX)
		noncelen = IKEV2_NONCE_MAX;

	resp = ikev2_pkt_new_response(pkt);
	if (resp == NULL)
		goto fail;

	/*
	 * The packet response functions take their SPI values from the
	 * initating packet, so for this one instance we must set it
	 * manually since the initiator doesn't yet know our local SPI.
	 */
	resp->pkt_header.responder_spi = I2SA_LOCAL_SPI(sa);

	if (!ikev2_sa_add_result(resp, &sa_result))
		goto fail;
	/*
	 * While premissible, we do not currently reuse DH exponentials.  Since
	 * generating them is a potentially an expensive operation, we wait
	 * until necessary to create them.
	 */
	if (!dh_genpair(sa_result.sar_dh, &sa->dh_pubkey, &sa->dh_privkey,
	    sa->i2sa_log))
		goto fail;
	if (!dh_derivekey(sa->dh_privkey, ke_i->pp_ptr + sizeof (ikev2_ke_t),
	    ke_i->pp_len - sizeof (ikev2_ke_t), &sa->dh_key, sa->i2sa_log))
		goto fail;
	if (!ikev2_add_ke(resp, sa_result.sar_dh, sa->dh_pubkey))
		goto fail;

	if (!ikev2_add_nonce(resp, NULL, noncelen))
		goto fail;
	if (!add_nat(resp))
		goto fail;

	/* XXX: CERTREQ? */
	/* XXX: other notifications */

	if (!add_vendor(resp))
		goto fail;

	if (!ikev2_sa_keygen(&sa_result, pkt, resp))
		goto fail;
	if (!ikev2_send(resp, B_FALSE))
		goto fail;
	return;

fail:
	(void) bunyan_error(sa->i2sa_log,
	    "Could not send response in IKE_SA_INIT exchange",
	    BUNYAN_T_END);

	sa->init_r = NULL;
	ikev2_sa_condemn(sa);
	ikev2_pkt_free(pkt);
	ikev2_pkt_free(resp);
	/* XXX: Anything else? */
}

/*
 * If we get a cookie request or a new DH group in response to our
 * initiated IKE_SA_INIT exchange, restart with the new parameters.
 *
 * XXX: Better name?
 */
static boolean_t
redo_init(pkt_t *pkt)
{
	ikev2_sa_t *sa = pkt->pkt_sa;
	pkt_notify_t *cookie = pkt_get_notify(pkt, IKEV2_N_COOKIE, NULL);
	pkt_notify_t *invalid_ke = pkt_get_notify(pkt,
	    IKEV2_N_INVALID_KE_PAYLOAD, NULL);

	if (cookie == NULL && invalid_ke == NULL)
		return (B_FALSE);

	pkt_t *out = sa->init_i;
	pkt_payload_t *nonce = pkt_get_payload(out, IKEV2_PAYLOAD_NONCE, NULL);
	ikev2_dh_t dh = IKEV2_DH_NONE;

	sa->init_i = NULL;

	if (invalid_ke != NULL) {
		if (invalid_ke->pn_len != sizeof (uint16_t)) {
			/*
			 * The notification does not have the correct format
			 */
			bunyan_info(sa->i2sa_log,
			    "INVALID_KE_PAYLOAD notification does not "
			    "include a 16-bit DH group payload",
			    BUNYAN_T_UINT32, "ntfylen",
			    (uint32_t)invalid_ke->pn_len, BUNYAN_T_END);

			/* We will just ignore it for now */
			ikev2_pkt_free(pkt);
			return (B_FALSE);
		}

		uint16_t val = BE_IN16(invalid_ke->pn_ptr);
		dh = val;
	}

	(void) cancel_timeout(TE_TRANSMIT, out, sa->i2sa_log);
	ikev2_sa_init_outbound(sa, cookie->pn_ptr, cookie->pn_len,
	    dh, nonce->pp_ptr, nonce->pp_len);

	ikev2_pkt_free(pkt);
	ikev2_pkt_free(out);
	return (B_TRUE);
}

/*
 * We initiated the IKE_SA_INIT exchange, this is the remote response
 */
static void
ikev2_sa_init_inbound_resp(pkt_t *pkt)
{
	ikev2_sa_t *sa = pkt->pkt_sa;
	pkt_payload_t *ke_r = pkt_get_payload(pkt, IKEV2_PAYLOAD_KE, NULL);
	ikev2_sa_result_t sa_result = { 0 };

	if (pkt_get_notify(pkt, IKEV2_N_NO_PROPOSAL_CHOSEN, NULL) != NULL) {
		bunyan_error(sa->i2sa_log,
		    "IKE_SA_INIT exchange failed, no proposal chosen",
		    BUNYAN_T_END);
		ikev2_sa_condemn(sa);
		ikev2_pkt_free(pkt);
		return;
	}

	/* Did we get a request for cookies or a new DH group? */
	if (redo_init(pkt))
		return;
	if (!check_nats(pkt))
		goto fail;
	check_vendor(pkt);

	if (!ikev2_sa_match_rule(sa->i2sa_rule, pkt, &sa_result)) {
		/*
		 * XXX: Tried to send back something that wasn't in the propsals
		 * we sent.  What should we do?  Just destroy the IKE SA?
		 * Ignore?  For now ignore and hope a valid answer comes
		 * back before we timeout.
		 */
		ikev2_pkt_free(pkt);
		return;
	}

	if (!dh_derivekey(sa->dh_privkey, ke_r->pp_ptr, ke_r->pp_len,
	    &sa->dh_key, sa->i2sa_log))
		goto fail;
	if (!ikev2_sa_keygen(&sa_result, sa->init_i, pkt))
		goto fail;

	ikev2_sa_set_remote_spi(sa, INBOUND_REMOTE_SPI(&pkt->pkt_header));
	sa->init_r = pkt;
	return;

fail:
	ikev2_sa_condemn(sa);
	ikev2_pkt_free(pkt);
	/* XXX: Anything else? */
}

/*
 * Start a new IKE_SA_INIT using the given larval refheld IKE SA.
 * The other parameters are normally NULL / 0 and are used when the response
 * requests a cookie or a new DH group.
 */
void
ikev2_sa_init_outbound(ikev2_sa_t *restrict i2sa, uint8_t *restrict cookie,
    size_t cookielen, ikev2_dh_t dh, uint8_t *restrict nonce, size_t noncelen)
{
	pkt_t *pkt = NULL;
	sockaddr_u_t laddr = { .sau_ss = &i2sa->laddr };
	sockaddr_u_t raddr = { .sau_ss = &i2sa->raddr };

	if (nonce == NULL) {
		bunyan_info(i2sa->i2sa_log,
		    "Starting new IKE_SA_INIT exchange as initiator",
		    BUNYAN_T_END);
	}

	VERIFY(i2sa->flags & I2SA_INITIATOR);

	pkt = ikev2_pkt_new_exchange(i2sa, IKEV2_EXCH_IKE_SA_INIT);

	if (!find_config(pkt, laddr, raddr))
		goto fail;

	if (!add_cookie(pkt, cookie, cookielen))
		goto fail;

	if (!ikev2_sa_from_rule(pkt, i2sa->i2sa_rule, 0))
		goto fail;

	/* These will do nothing if there isn't an existing key */
	pkcs11_destroy_obj("dh_pubkey", &i2sa->dh_pubkey, i2sa->i2sa_log);
	pkcs11_destroy_obj("dh_privkey", &i2sa->dh_privkey, i2sa->i2sa_log);

	/* Start with the first DH group in the first rule */
	if (dh == IKEV2_DH_NONE)
		dh = i2sa->i2sa_rule->rule_xf[0]->xf_dh;

	if (!dh_genpair(dh, &i2sa->dh_pubkey, &i2sa->dh_privkey,
	    i2sa->i2sa_log))
		goto fail;

	if (!ikev2_add_ke(pkt, dh, i2sa->dh_pubkey))
		goto fail;

	/*
	 * XXX: This is half the largest keysize of all the PRF functions
	 * we support.
	 */
	if (noncelen == 0)
		noncelen = 32;

	if (!ikev2_add_nonce(pkt, nonce, noncelen))
		goto fail;
	if (!add_nat(pkt))
		goto fail;
	if (!add_vendor(pkt))
		goto fail;

	/* XXX: CERTREQ */

	i2sa->init_i = pkt;

	if (!ikev2_send(pkt, B_FALSE))
		goto fail;

	I2SA_REFRELE(i2sa);
	return;

fail:
	i2sa->init_i = NULL;
	ikev2_sa_condemn(i2sa);
	ikev2_pkt_free(pkt);
	I2SA_REFRELE(i2sa);
}

static boolean_t
find_config(pkt_t *pkt, sockaddr_u_t laddr, sockaddr_u_t raddr)
{
	ikev2_sa_t *sa = pkt->pkt_sa;

	if (sa->i2sa_rule != NULL)
		goto done;

	sa->i2sa_rule = config_get_rule(laddr, raddr);

done:
	if (RULE_IS_DEFAULT(sa->i2sa_rule)) {
		bunyan_debug(sa->i2sa_log, "Using default rule", BUNYAN_T_END);
	} else {
		bunyan_debug(sa->i2sa_log, "Found rule",
		    BUNYAN_T_STRING, "label", sa->i2sa_rule->rule_label,
		    BUNYAN_T_END);
	}

	if (sa->i2sa_rule->rule_nxf == 0) {
		bunyan_debug(sa->i2sa_log, "No transforms found", BUNYAN_T_END);
		ikev2_no_proposal_chosen(sa, pkt, IKEV2_PROTO_IKE, 0);
		return (B_FALSE);
	}

	return (B_TRUE);
}

/*
 * Size of a SHA1 hash.  NAT detection always uses SHA1 to compute the
 * NAT detection payload contents.
 */
#define	NAT_LEN	(20)

/* Compute a NAT detection payload and place result into buf */
static boolean_t
compute_nat(uint64_t *restrict spi, struct sockaddr_storage *restrict addr,
    uint8_t *restrict buf, size_t buflen, bunyan_logger_t *l)
{
	const char *p11f = NULL;
	CK_SESSION_HANDLE h = p11h();
	CK_MECHANISM mech = {
		.mechanism = CKM_SHA_1,
		.pParameter = NULL_PTR,
		.ulParameterLen = 0
	};
	CK_BYTE_PTR addrp = (CK_BYTE_PTR)ss_addr(addr);
	CK_ULONG len = buflen;
	CK_RV ret = CKR_OK;
	size_t addrlen = (addr->ss_family == AF_INET) ?
	    sizeof (in_addr_t) : sizeof (in6_addr_t);
	uint16_t port = (uint16_t)ss_port(addr);

	VERIFY3U(buflen, >=, NAT_LEN);

	p11f = "C_DigestInit";
	ret = C_DigestInit(h, &mech);
	if (ret != CKR_OK)
		goto fail;

	/* Both SPIs (in order) */
	p11f = "C_DigestUpdate";
	ret = C_DigestUpdate(h, (CK_BYTE_PTR)spi, 2 * sizeof (uint64_t));
	if (ret != CKR_OK)
		goto fail;

	ret = C_DigestUpdate(h, addrp, addrlen);
	if (ret != CKR_OK)
		goto fail;

	ret = C_DigestUpdate(h, (CK_BYTE_PTR)&port, sizeof (port));
	if (ret != CKR_OK)
		goto fail;

	p11f = "C_DigestFinal";
	ret = C_DigestFinal(h, buf, &len);
	if (ret != CKR_OK)
		goto fail;

	return (B_TRUE);

fail:
	PKCS11ERR(error, l, p11f, ret);
	return (B_FALSE);
}

/*
 * Perform NAT detection and update IKEV2 SA accordingly.  Return B_FALSE on
 * error, B_TRUE if no error.
 */
static boolean_t
check_nats(pkt_t *pkt)
{
	ikev2_sa_t *sa = pkt->pkt_sa;
	struct {
		ikev2_notify_type_t	ntype;
		struct sockaddr_storage *addr;
		const char		*msg;
		uint32_t		flag;
	} params[] = {
		/*
		 * Since these are from the perspective of the remote system,
		 * we check the local address against the NAT destination IP
		 * and vice versa.
		 */
		{
			IKEV2_N_NAT_DETECTION_DESTINATION_IP,
			&pkt->pkt_sa->laddr,
			"Local NAT detected",
			I2SA_NAT_LOCAL
		},
		{
			IKEV2_N_NAT_DETECTION_SOURCE_IP,
			&pkt->pkt_sa->raddr,
			"Remote NAT detected",
			I2SA_NAT_REMOTE
		}
	};

	for (size_t i = 0; i < 2; i++) {
		pkt_notify_t *n = pkt_get_notify(pkt, params[i].ntype, NULL);
		uint8_t data[NAT_LEN] = { 0 };

		/* If notification isn't present, assume no NAT */
		if (n == NULL)
			continue;

		if (!compute_nat(pkt->pkt_raw, params[i].addr, data,
		    sizeof (data), sa->i2sa_log))
			return (B_FALSE);

		while (n != NULL) {
			/*
			 * XXX: Should these validation failures just ignore
			 * the individual payload, or discard the packet
			 * entirely?
			 */
			if (n->pn_proto != IKEV2_PROTO_IKE) {
				bunyan_error(sa->i2sa_log,
				    "Invalid SPI protocol in notification",
				    BUNYAN_T_STRING, "notification",
				    ikev2_notify_str(params[i].ntype),
				    BUNYAN_T_STRING, "protocol",
				    ikev2_spi_str(n->pn_proto),
				    BUNYAN_T_UINT32, "protonum",
				    (uint32_t)n->pn_proto, BUNYAN_T_END);
				return (B_FALSE);
			}
			if (n->pn_spi != 0) {
				bunyan_error(sa->i2sa_log,
				    "Non-zero SPI size in NAT notification",
				    BUNYAN_T_STRING, "notification",
				    ikev2_notify_str(params[i].ntype),
				    BUNYAN_T_END);
				return (B_FALSE);
			}
			if (n->pn_len != NAT_LEN) {
				bunyan_error(sa->i2sa_log,
				    "NAT notification size mismatch",
				    BUNYAN_T_STRING, "notification",
				    ikev2_notify_str(params[i].ntype),
				    BUNYAN_T_UINT32, "notifylen",
				    (uint32_t)n->pn_len,
				    BUNYAN_T_UINT32, "expected",
				    (uint32_t)NAT_LEN,
				    BUNYAN_T_END);
				return (B_FALSE);
			}

			if (memcmp(data, n->pn_ptr, NAT_LEN) == 0) {
				sa->flags |= params[i].flag;
				bunyan_debug(sa->i2sa_log, params[i].msg,
				    BUNYAN_T_END);
				break;
			}

			n = pkt_get_notify(pkt, params[i].ntype, n);
		}
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
	ikev2_sa_t *sa = pkt->pkt_sa;
	struct {
		ikev2_notify_type_t	ntype;
		struct sockaddr_storage *addr;
	} params[] = {
		/*
		 * Since these are from our perspective, the local address
		 * corresponds to the source address and remote to the
		 * destination address.
		 */
		{
			IKEV2_N_NAT_DETECTION_SOURCE_IP,
			&pkt->pkt_sa->laddr,
		},
		{
			IKEV2_N_NAT_DETECTION_DESTINATION_IP,
			&pkt->pkt_sa->raddr,
		}
	};

	/*
	 * These normally don't get converted to network byte order until
	 * the packet has finished construction, so we need to do local
	 * conversion for the NAT payload creation
	 */
	uint64_t spi[2] = {
		htonll(pkt->pkt_header.initiator_spi),
		htonll(pkt->pkt_header.responder_spi)
	};

	for (int i = 0; i < 2; i++) {
		uint8_t data[NAT_LEN] = { 0 };

		if (!compute_nat(spi, params[i].addr, data, sizeof (data),
		    sa->i2sa_log))
			return (B_FALSE);

		if (!ikev2_add_notify(pkt, IKEV2_PROTO_IKE, 0, params[i].ntype,
		    data, sizeof (data)))
			return (B_FALSE);
	}
	return (B_TRUE);

fail:
	return (B_FALSE);
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
		    sizeof (VENDOR_STR_ILLUMOS_1)) == 0) {
			bunyan_debug(sa->i2sa_log,
			    "Found illumos_1 vendor payload", BUNYAN_T_END);
			sa->vendor = VENDOR_ILLUMOS_1;
		}
	}
}

static boolean_t
add_vendor(pkt_t *pkt)
{
	return (ikev2_add_vendor(pkt, (uint8_t *)VENDOR_STR_ILLUMOS_1,
	    sizeof (VENDOR_STR_ILLUMOS_1)));
}

static boolean_t
add_cookie(pkt_t *restrict pkt, void *restrict cookie, size_t len)
{
	if (cookie == NULL)
		return (B_TRUE);

	/* Should be the first payload */
	VERIFY3U(pkt->pkt_payload_count, ==, 0);

	return (ikev2_add_notify(pkt, IKEV2_PROTO_IKE, 0, IKEV2_N_COOKIE,
	    cookie, len));
}

static size_t
skeyseed_noncelen(ikev2_prf_t prf, size_t len)
{
	switch (prf) {
	/*
	 * RFC7296 2.14 - For these PRFs, only the first 64 bits of Ni and Nr
	 * are used when calculating skeyseed, though all bits are used for
	 * the prf+ function
	 */
	case IKEV2_PRF_AES128_XCBC:
	case IKEV2_PRF_AES128_CMAC:
		if (len > 8)
			return (8);
		/*FALLTHRU*/
	default:
		return (len);
	}
}

/* Create a PKCS#11 object of Ni | Nr */
static boolean_t
create_nonceobj(ikev2_prf_t prf, pkt_payload_t *restrict ni,
    pkt_payload_t *restrict nr, CK_OBJECT_HANDLE_PTR restrict objp,
    bunyan_logger_t *restrict l)
{
	size_t noncelen = MAX(ni->pp_len + nr->pp_len, ikev2_prf_outlen(prf));
	uint8_t nonce[noncelen];
	size_t ni_len = skeyseed_noncelen(prf, ni->pp_len);
	size_t nr_len = skeyseed_noncelen(prf, nr->pp_len);
	CK_RV rc;

	(void) memset(nonce, 0, noncelen);
	(void) memcpy(nonce, ni->pp_ptr, ni_len);
	(void) memcpy(nonce + ni_len, nr->pp_ptr, nr_len);
	rc = SUNW_C_KeyToObject(p11h(), ikev2_prf_to_p11(prf), nonce, noncelen,
	    objp);
	explicit_bzero(nonce, noncelen);

	if (rc != CKR_OK)
		PKCS11ERR(error, l, "SUNW_C_KeyToObject", rc,
		    BUNYAN_T_STRING, "objname", "Ni|Nr");

	return ((rc == CKR_OK) ? B_TRUE : B_FALSE);
}

static boolean_t
create_skeyseed(ikev2_sa_t *restrict sa, CK_OBJECT_HANDLE nonce,
    CK_OBJECT_HANDLE_PTR restrict keyp)
{
	CK_SESSION_HANDLE h = p11h();
	uint8_t *dh_key = NULL, *skeyseed = NULL;
	size_t dh_key_len = 0, skeyseed_len = 0;
	CK_RV rc = CKR_OK;
	boolean_t ok = B_TRUE;

	skeyseed_len = ikev2_prf_outlen(sa->prf);
	skeyseed = umem_zalloc(skeyseed_len, UMEM_DEFAULT);
	if (skeyseed == NULL)
		goto fail;

	/*
	 * Unfortunately, to generate SKEYSEED, we need to copy down the g^ir
	 * value to perform the prf function since there is no C_SignKey
	 * function in PKCS#11. As such we try to keep the value in memory for
	 * as short a time as possible.
	 */
	rc = pkcs11_ObjectToKey(h, sa->dh_key, (void **)&dh_key, &dh_key_len,
	    B_FALSE);
	if (rc != CKR_OK) {
		PKCS11ERR(error, sa->i2sa_log, "pkcs11_ObjectToKey", rc,
		    BUNYAN_T_STRING, "objname", "dh_key");
		goto fail;
	}

	ok = prf(sa->prf, nonce, skeyseed, skeyseed_len, sa->i2sa_log, dh_key,
	    dh_key_len, NULL);
	explicit_bzero(dh_key, dh_key_len);
	free(dh_key);
	dh_key = NULL;
	dh_key_len = 0;

	if (!ok) {
		explicit_bzero(skeyseed, skeyseed_len);
		goto fail;
	}

	rc = SUNW_C_KeyToObject(h, ikev2_prf_to_p11(sa->prf), skeyseed,
	    skeyseed_len, keyp);
	explicit_bzero(skeyseed, skeyseed_len);
	if (rc != CKR_OK) {
		PKCS11ERR(error, sa->i2sa_log, "SUNW_C_KeyToObject", rc,
		    BUNYAN_T_STRING, "objname", "skeyseed");
		goto fail;
	}

	(void) bunyan_trace(sa->i2sa_log, "Created SKEYSEED", BUNYAN_T_END);

	return (B_TRUE);

fail:
	if (dh_key != NULL) {
		explicit_bzero(dh_key, dh_key_len);
		free(dh_key);
	}
	if (skeyseed != NULL) {
		explicit_bzero(skeyseed, skeyseed_len);
		umem_free(skeyseed, skeyseed_len);
	}
	return (B_FALSE);
}

static boolean_t
ikev2_sa_keygen(ikev2_sa_result_t *restrict result, pkt_t *restrict init,
    pkt_t *restrict resp)
{
	ikev2_sa_t *sa = resp->pkt_sa;
	pkt_payload_t *ni = pkt_get_payload(init, IKEV2_PAYLOAD_NONCE, NULL);
	pkt_payload_t *nr = pkt_get_payload(resp, IKEV2_PAYLOAD_NONCE, NULL);
	CK_SESSION_HANDLE h = p11h();
	CK_OBJECT_HANDLE nonce = CK_INVALID_HANDLE;
	CK_OBJECT_HANDLE skeyseed = CK_INVALID_HANDLE;
	size_t encrlen = result->sar_encr_keylen;
	size_t prflen = ikev2_prf_keylen(result->sar_prf);
	size_t authlen = auth_data[result->sar_auth].ad_keylen;
	int p11prf = ikev2_prf_to_p11(result->sar_prf);
	int p11encr = encr_data[result->sar_encr].ed_p11id;
	int p11auth = auth_data[result->sar_auth].ad_p11id;
	prfp_t prfp = { 0 };

	if (encrlen == 0)
		encrlen = encr_data[sa->encr].ed_keydefault;

	sa->encr = result->sar_encr;
	sa->auth = result->sar_auth;
	sa->prf = result->sar_prf;
	sa->dhgrp = result->sar_dh;
	sa->saltlen = encr_data[result->sar_encr].ed_saltlen;

	if (!create_nonceobj(sa->prf, ni, nr, &nonce, sa->i2sa_log))
		goto fail;
	if (!create_skeyseed(sa, nonce, &skeyseed))
		goto fail;
	pkcs11_destroy_obj("Ni|Nr", &nonce, sa->i2sa_log);

	if (!prfplus_init(&prfp, sa->prf, skeyseed, sa->i2sa_log,
	    ni->pp_ptr, (size_t)ni->pp_len,
	    nr->pp_ptr, (size_t)nr->pp_len,
	    pkt_start(init), sizeof (uint64_t) * 2, NULL))
		goto fail;
	if (!prf_to_p11key(&prfp, "SK_d", p11prf, prflen, &sa->sk_d))
		goto fail;
	if (!prf_to_p11key(&prfp, "SK_ai", p11auth, authlen, &sa->sk_ai))
		goto fail;
	if (!prf_to_p11key(&prfp, "SK_ar", p11auth, authlen, &sa->sk_ar))
		goto fail;
	if (!prf_to_p11key(&prfp, "SK_ei", p11encr, sa->encr_key_len,
	    &sa->sk_ei))
		goto fail;
	if (!prfplus(&prfp, sa->salt_i, sa->saltlen))
		goto fail;
	if (!prf_to_p11key(&prfp, "SK_er", p11encr, sa->encr_key_len,
	    &sa->sk_er))
		goto fail;
	if (!prfplus(&prfp, sa->salt_r, sa->saltlen))
		goto fail;
	if (!prf_to_p11key(&prfp, "SK_pi", p11prf, prflen, &sa->sk_pi))
		goto fail;
	if (!prf_to_p11key(&prfp, "SK_pr", p11prf, prflen, &sa->sk_pr))
		goto fail;

	pkcs11_destroy_obj("Ni|Nr", &nonce, sa->i2sa_log);
	pkcs11_destroy_obj("skeyseed", &skeyseed, sa->i2sa_log);
	prfplus_fini(&prfp);
	return (B_TRUE);

fail:
	pkcs11_destroy_obj("Ni|Nr", &nonce, sa->i2sa_log);
	pkcs11_destroy_obj("skeyseed", &skeyseed, sa->i2sa_log);
	prfplus_fini(&prfp);
	return (B_FALSE);
}
