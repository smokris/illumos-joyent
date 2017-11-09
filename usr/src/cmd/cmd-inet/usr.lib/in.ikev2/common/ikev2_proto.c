/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */

/*
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright 2017 Jason King.
 * Copyright (c) 2017, Joyent, Inc
 */

#include <errno.h>
#include <ipsec_util.h>
#include <libperiodic.h>
#include <note.h>
#include <string.h>
#include <sys/debug.h>
#include <sys/types.h>
#include <sys/socket.h>
#include "config.h"
#include "defs.h"
#include "fromto.h"
#include "inbound.h"
#include "ikev2_cookie.h"
#include "ikev2_enum.h"
#include "ikev2_pkt.h"
#include "ikev2_proto.h"
#include "ikev2_sa.h"
#include "pfkey.h"
#include "pkt.h"
#include "worker.h"

static void ikev2_dispatch_pkt(pkt_t *);
static void ikev2_dispatch_pfkey(ikev2_sa_t *restrict, parsedmsg_t *restrict);

static int select_socket(const ikev2_sa_t *);

static ikev2_sa_t *ikev2_try_new_sa(pkt_t *restrict,
    const struct sockaddr_storage *restrict,
    const struct sockaddr_storage *restrict);

/*
 * Find the IKEv2 SA for a given inbound packet (or create a new one if
 * an IKE_SA_INIT exchange) and either process or add to the IKEv2 SA queue.
 */
void
ikev2_inbound(pkt_t *pkt, const struct sockaddr_storage *restrict src_addr,
    const struct sockaddr_storage *restrict dest_addr)
{
	ikev2_sa_t *i2sa = NULL;
	ike_header_t *hdr = pkt_header(pkt);
	uint64_t local_spi = INBOUND_LOCAL_SPI(hdr);
	uint64_t remote_spi = INBOUND_REMOTE_SPI(hdr);

	VERIFY(IS_WORKER);

	ikev2_pkt_log(pkt, BUNYAN_L_TRACE, "Received packet");

	i2sa = ikev2_sa_get(local_spi, remote_spi, dest_addr, src_addr, pkt);
	if (i2sa == NULL) {
		if (local_spi != 0) {
			/*
			 * If the local SPI is set, we should be able to find it
			 * in our hash.  This may be a packet destined for a
			 * condemned or recently deleted IKE SA.
			 *
			 * RFC7296 2.21.4 we may send an INVALID_IKE_SPI
			 * notification if we wish, but it is suggested the
			 * responses be rate limited.
			 *
			 * For now, discard.
			 */
			ikev2_pkt_log(pkt, BUNYAN_L_DEBUG,
			    "Cannot find IKE SA for packet; discarding");
			ikev2_pkt_free(pkt);
			return;
		}

		/*
		 * XXX: This might require special processing.
		 * Discard for now.
		 */
		if (remote_spi == 0) {
			ikev2_pkt_log(pkt, BUNYAN_L_DEBUG,
			    "Received packet with a 0 remote SPI; discarding");
			ikev2_pkt_free(pkt);
			return;
		}

		/*
		 * If we received a response, we should either have an IKE SA
		 * or discard it, but shouldn't try to create a larval IKE SA.
		 */
		if (I2P_RESPONSE(pkt)) {
			ikev2_pkt_log(pkt, BUNYAN_L_DEBUG,
			    "Received response to non-existant IKE SA; "
			    "discarding");
			ikev2_pkt_free(pkt);
			return;
		}

		/* On success, returns with i2sa_queue_lock held */
		i2sa = ikev2_try_new_sa(pkt, dest_addr, src_addr);
		if (i2sa == NULL) {
			ikev2_pkt_free(pkt);
			return;
		}
		key_add_ike_spi(LOG_KEY_LSPI, I2SA_LOCAL_SPI(i2sa));
	} else {
		mutex_enter(&i2sa->i2sa_queue_lock);
	}

	/* These never change once set */
	if (i2sa->local_id != NULL) {
		key_add_id(LOG_KEY_LOCAL_ID, LOG_KEY_LOCAL_ID_TYPE,
		    i2sa->local_id);
	}
	if (i2sa->remote_id != NULL) {
		key_add_id(LOG_KEY_REMOTE_ID, LOG_KEY_REMOTE_ID_TYPE,
		    i2sa->remote_id);
	}

	VERIFY(MUTEX_HELD(&i2sa->i2sa_queue_lock));
	/*
	 * ikev2_sa_get and ikev2_try_new_sa both return refheld ikev2_sa_t's
	 * that we then give to the inbound packet.
	 */
	pkt->pkt_sa = i2sa;

	if (!ikev2_sa_queuemsg(i2sa, I2SA_MSG_PKT, pkt)) {
		(void) bunyan_info(log, "queue full; discarding packet",
		    BUNYAN_T_END);
		ikev2_pkt_free(pkt);	/* Also refrele's pkt->pkt_sa */
	}
}

/*
 * Determine if this pkt is an request for a new IKE SA.  If so, create
 * a larval IKE SA and return it, otherwise return NULL.  It is assumed
 * caller will discard packet when NULL is returned.
 */
static ikev2_sa_t *
ikev2_try_new_sa(pkt_t *restrict pkt,
    const struct sockaddr_storage *restrict l_addr,
    const struct sockaddr_storage *restrict r_addr)
{
	ikev2_sa_t *i2sa = NULL;
	ike_header_t *hdr = pkt_header(pkt);
	const char *errmsg = NULL;

	/* ikev2_dispatch() should guarantee this */
	VERIFY3U(INBOUND_LOCAL_SPI(hdr), ==, 0);

	/*
	 * RFC7296 2.2 - The only exchange where our SPI is zero is when
	 * the remote peer has started an IKE_SA_INIT exchange.  All others
	 * must have both SPIs set (non-zero).
	 */
	if (hdr->exch_type != IKEV2_EXCH_IKE_SA_INIT) {
		errmsg = "Received a non-IKE_SA_INIT message with a local "
		    "SPI of 0; discarding";
		goto fail;
	}

	/*
	 * RFC7296 2.2 -- IKE_SA_INIT exchanges always have msgids == 0
	 */
	if (hdr->msgid != 0) {
		errmsg = "Received an IKE_SA_INIT message with a non-zero "
		    "message id; discarding";
		goto fail;
	}

	/*
	 * It also means it must be the initiator and not a response
	 */
	if ((hdr->flags & IKEV2_FLAG_INITIATOR) != hdr->flags) {
		errmsg = "Invalid flags on packet; discarding";
		goto fail;
	}

	/*
	 * XXX: Since cookies are enabled in high traffic situations,
	 * might we want to silently discard these?
	 */
	if (!ikev2_cookie_check(pkt, r_addr)) {
		errmsg = "Cookies missing or failed check; discarding";
		goto fail;
	}

	/* otherwise create a larval SA */
	i2sa = ikev2_sa_alloc(B_FALSE, pkt, l_addr, r_addr);
	if (i2sa == NULL) {
		errmsg = "Could not create larval IKEv2 SA; discarding";
		goto fail;
	}

	return (i2sa);

fail:
	if (errmsg != NULL)
		ikev2_pkt_log(pkt, BUNYAN_L_DEBUG, errmsg);

	return (NULL);
}

/*
 * Take a parsed pfkey message, and either locate an existing IKE SA and
 * add to it's queue, or create a larval IKE SA and kickoff the
 * IKE_SA_INIT exchange.
 */
void
ikev2_pfkey(parsedmsg_t *pmsg)
{
	ikev2_sa_t *sa = NULL;
	sadb_x_kmc_t *kmc = NULL;
	uint64_t local_spi = 0;
	sockaddr_u_t laddr;
	sockaddr_u_t raddr;

	/*
	 * XXX: Once OPS/OPD extensions are there, this probably needs
	 * to be changed.
	 */
	laddr = pmsg->pmsg_sau;
	raddr = pmsg->pmsg_dau;

	kmc = (sadb_x_kmc_t *)pmsg->pmsg_exts[SADB_X_EXT_KM_COOKIE];
	if (kmc != NULL) {
		VERIFY3U(kmc->sadb_x_kmc_exttype, ==, SADB_X_EXT_KM_COOKIE);
		local_spi = kmc->sadb_x_kmc_cookie64;
	}

	sa = ikev2_sa_get(local_spi, 0, laddr.sau_ss, raddr.sau_ss, NULL);
	if (sa == NULL) {
		config_rule_t *rule = NULL;

		/*
		 * The KM cookie (kmc) is what links an IPsec SA to an IKE
		 * SA.  If we receive a message with a kmc, we should have
		 * a corresponding IKE SA.  If we receive a message without
		 * a kmc, the only message that makes any sense is an
		 * ACQUIRE (kernel requesting keys for an IPsec SA).  Any
		 * others we drop and log (since it shouldn't happen).
		 */
		if (kmc != NULL ||
		    pmsg->pmsg_samsg->sadb_msg_type != SADB_ACQUIRE) {
			sadb_log(BUNYAN_L_ERROR, "Received a pfkey "
			    "message for a non-existant IKE SA",
			    pmsg->pmsg_samsg);

			/*
			 * XXX: Should we try to send an error reply back
			 * to the kernel?  My guess is no, but need to confirm.
			 */
			parsedmsg_free(pmsg);
			return;
		}

		rule = config_get_rule(laddr, raddr);
		if (rule == NULL) {
			/*
			 * The kernel currently only cares that sadb_msg_errno
			 * (set by the 2nd parameter to pfkey_send_error()) is
			 * != 0.  However we still pick an error code that is
			 * hopefully somewhat accurate to the reason for the
			 * failure.
			 */
			pfkey_send_error(pmsg->pmsg_samsg, ENOENT);
			sadb_log(BUNYAN_L_ERROR,
			    "Could not find a matching IKE rule for the "
			    "SADB ACQUIRE request", pmsg->pmsg_samsg);
			parsedmsg_free(pmsg);
			return;
		}

		/* On success, returns sa with i2sa_queue_lock held */
		sa = ikev2_sa_alloc(B_TRUE, NULL, laddr.sau_ss, raddr.sau_ss);
		if (sa == NULL) {
			/*
			 * The kernel currently only cares that sadb_msg_errno
			 * (set by the 2nd parameter to pfkey_send_error()) is
			 * != 0.  To try to be at least somewhat accurate in
			 * the reason for the failure, we use whatever error
			 * was returned by ikev2_sa_alloc().
			 */
			VERIFY3S(errno, !=, 0);
			pfkey_send_error(pmsg->pmsg_samsg, errno);
			sadb_log(BUNYAN_L_ERROR,
			    "Failed to create larval IKE SA: out of memory",
			    pmsg->pmsg_samsg);
			parsedmsg_free(pmsg);
			return;
		}

		mutex_enter(&sa->i2sa_lock);
		key_add_ike_spi(LOG_KEY_LSPI, I2SA_LOCAL_SPI(sa));
		sa->i2sa_rule = rule;
		mutex_exit(&sa->i2sa_lock);
	} else {
		mutex_enter(&sa->i2sa_queue_lock);
	}

	if (!ikev2_sa_queuemsg(sa, I2SA_MSG_PFKEY, pmsg)) {
		sadb_log(BUNYAN_L_WARN,
		    "Could not queue SADB message; discarding",
		    pmsg->pmsg_samsg);
		parsedmsg_free(pmsg);
		I2SA_REFRELE(sa);
	}
}

/*
 * Attempt to create an IKEv2 SA  and start an IKE_SA_INIT exchange
 * from the given rule.
 */
void
ikev2_sa_init_cfg(config_rule_t *rule)
{
	ikev2_sa_t *sa = NULL;
	parsedmsg_t *pmsg = NULL;
	struct sockaddr_storage src = { 0 };
	struct sockaddr_storage dst = { 0 };
	sockaddr_u_t susrc = { .sau_ss = &src };
	sockaddr_u_t sudst = { .sau_ss = &dst };
	sockaddr_u_t isrc = { .sau_ss = NULL };
	sockaddr_u_t idst = { .sau_ss = NULL };
	size_t len = 0;

	if (!config_addr_to_ss(&rule->rule_local_addr[0], susrc))
		goto fail;
	if (!config_addr_to_ss(&rule->rule_remote_addr[0], sudst))
		goto fail;

	if (!pfkey_inverse_acquire(susrc, sudst, isrc, idst, &pmsg)) {
		if (pmsg == NULL) {
			STDERR(error, "Inverse acquire failed");
			goto fail;
		}

		int errval = pmsg->pmsg_samsg->sadb_msg_errno;
		uint32_t diag = pmsg->pmsg_samsg->sadb_x_msg_diagnostic;

		if (errval == ENOENT) {
			char *label = rule->rule_label;

			if (RULE_IS_DEFAULT(rule))
				label = "<default rule>";

			/* XXX: Add addresses to message? */
			(void) bunyan_error(log,
			    "Cannot create IKEV2 SA for host: No IPsec "
			    "configuration found",
			    BUNYAN_T_STRING, "ike_rule", label,
			    BUNYAN_T_END);
			goto fail;
		}

		TSTDERR(errval, error,
		    "Inverse acquire failed",
		    (diag > 0) ? BUNYAN_T_UINT32 : BUNYAN_T_END,
		    "code", diag,
		    BUNYAN_T_STRING, "diagmsg", keysock_diag(diag),
		    BUNYAN_T_END);
		goto fail;
	}

	sa = ikev2_sa_alloc(B_TRUE, NULL, &src, &dst);
	if (sa == NULL) {
		STDERR(error, "Failed to allocate larval IKE SA");
		goto fail;
	}

	mutex_enter(&sa->i2sa_lock);
	sa->i2sa_rule = rule;
	mutex_exit(&sa->i2sa_lock);

	VERIFY(ikev2_sa_queuemsg(sa, I2SA_MSG_PFKEY, pmsg));
	return;

fail:
	if (sa != NULL) {
		VERIFY(MUTEX_HELD(&sa->i2sa_queue_lock));
		mutex_enter(&sa->i2sa_lock);
		ikev2_sa_condemn(sa);
		mutex_exit(&sa->i2sa_lock);
		mutex_exit(&sa->i2sa_queue_lock);
		I2SA_REFRELE(sa);
	}
	parsedmsg_free(pmsg);
	CONFIG_REFRELE(rule->rule_config);
}

static boolean_t
ikev2_send_common(pkt_t *pkt)
{
	ikev2_sa_t *sa = pkt->pkt_sa;
	ike_header_t *hdr = pkt_header(pkt);
	char *desc = NULL;
	ssize_t len = 0;
	int s = -1;

	s = select_socket(sa);

	desc = ikev2_pkt_desc(pkt);
	(void) bunyan_debug(log, "Sending packet",
	    BUNYAN_T_UINT32, "msgid", ntohll(hdr->msgid),
	    BUNYAN_T_BOOLEAN, "response", I2P_RESPONSE(pkt),
	    BUNYAN_T_STRING, "pktdesc", desc,
	    BUNYAN_T_UINT32, "nxmit", (uint32_t)pkt->pkt_xmit,
	    BUNYAN_T_END);
	free(desc);
	desc = NULL;

	len = sendfromto(s, pkt_start(pkt), pkt_len(pkt), &sa->laddr,
	    &sa->raddr);
	return ((len == -1) ? B_FALSE : B_TRUE);
}

/*
 * Send a request (i.e. initiate the exchange).  All requests MUST include
 * a callback function.  When a response is received (see
 * ikev2_handle_response), the callback given here is invoked with the IKEv2 SA,
 * the response packet, and the value of arg given here.  arg is merely an
 * opaque pointer that can be used to pass context/state from the initiating
 * function to the request callback (and may be NULL if not needed).
 * If the request times out, or the IKEv2 SA is condemned, the callback will be
 * invokved with the response packet parameter set to NULL (to allow for any
 * cleanup -- include of 'arg' if necessary).
 */
boolean_t
ikev2_send_req(pkt_t *restrict req, ikev2_send_cb_t cb, void *restrict arg)
{
	ikev2_sa_t *i2sa = req->pkt_sa;
	i2sa_req_t *i2req = &i2sa->last_req;
	config_t *cfg = config_get();
	hrtime_t retry = cfg->cfg_retry_init;
	int s = -1;

	VERIFY(IS_WORKER);
	VERIFY(!MUTEX_HELD(&i2sa->i2sa_queue_lock));
	VERIFY(MUTEX_HELD(&i2sa->i2sa_lock));
	VERIFY(!I2P_RESPONSE(req));
	VERIFY3P(cb, !=, NULL);

	CONFIG_REFRELE(cfg);

	if (!ikev2_pkt_done(req)) {
		ikev2_pkt_free(req);
		return (B_FALSE);
	}

	/*
	 * Shouldn't try to start a new exchange when one is already in
	 * progress.
	 */
	VERIFY3P(i2sa->last_sent, ==, NULL);
	VERIFY3P(i2req->i2r_pkt, ==, NULL);

	if (!ikev2_send_common(req)) {
		/*
		 * XXX: For now at least, we don't bother with attempting to
		 * retransmit a packet if the original transmission failed.
		 */
		if (req != i2sa->init_i)
			ikev2_pkt_free(req);
		return (B_FALSE);
	}

	i2sa->last_sent = req;
	i2req->i2r_pkt = req;
	i2req->i2r_msgid = ntohl(pkt_header(req)->msgid);
	i2req->i2r_cb = cb;
	i2req->i2r_arg = arg;

	if (!ikev2_sa_arm_timer(i2sa, I2SA_EVT_PKT_XMIT, retry)) {
		/*
		 * XXX: If this fails, we could check for timeout on our
		 * next attempt to send a request and fail if we never
		 * received a response.
		 */
		STDERR(error, "Could not arm packet retransmit timer");
		return (B_FALSE);
	}

	return (B_TRUE);
}

/* Send a response */
boolean_t
ikev2_send_resp(pkt_t *restrict resp)
{
	ikev2_sa_t *i2sa = resp->pkt_sa;
	ike_header_t *hdr = pkt_header(resp);

	VERIFY(IS_WORKER);
	VERIFY(i2sa == NULL || !MUTEX_HELD(&i2sa->i2sa_queue_lock));
	VERIFY(i2sa == NULL || MUTEX_HELD(&i2sa->i2sa_lock));
	VERIFY(I2P_RESPONSE(resp));

	if (!ikev2_pkt_done(resp)) {
		ikev2_pkt_free(resp);
		return (B_FALSE);
	}

	if (!ikev2_send_common(resp)) {
		if (resp != i2sa->init_r)
			ikev2_pkt_free(resp);
		return (B_FALSE);
	}

        /*
	 * Normally, we save the last repsonse packet we've sent in order to
	 * re-send the last response in case the remote system retransmits
	 * the last exchange it initiated.  However for IKE_SA_INIT exchanges,
	 * _responses_ of the form HDR(A,0) are not saved for retransmission.
	 * These responses should be either a request for cookies, a new DH
	 * group, or a failed exchange (no proposal chosen), and we will
	 * want to process the resulting reply (which, if it happens, should
	 * be a restart of the IKE_SA_INIT exchange with the updated
	 * parameters).
         */
	if (hdr->exch_type != IKEV2_EXCH_IKE_SA_INIT ||
	    hdr->responder_spi != 0) {
		i2sa->last_resp_sent = resp;
	}

	return (B_TRUE);
}

/*
 * Trigger a resend of our last request due to timeout waiting for a
 * response.
 */
void
ikev2_retransmit_cb(void *data)
{
	VERIFY(IS_WORKER);

	ikev2_sa_t *sa = data;
	ikev2_sa_post_event(sa, I2SA_EVT_PKT_XMIT);
}

/*
 * Resend our last request.
 */
static void
ikev2_retransmit(ikev2_sa_t *sa)
{
	pkt_t *pkt = sa->last_sent;
	ike_header_t *hdr = pkt_header(pkt);
	i2sa_req_t *req = &sa->last_req;
	hrtime_t retry = 0, retry_init = 0, retry_max = 0;
	size_t limit = 0;

	VERIFY(IS_WORKER);
	VERIFY(!MUTEX_HELD(&sa->i2sa_queue_lock));
	VERIFY(MUTEX_HELD(&sa->i2sa_lock));

	if (pkt == NULL) {
		VERIFY3P(req->i2r_pkt, ==, NULL);
		/* already acknowledged */
		return;
	}

	config_t *cfg = config_get();
	retry_init = cfg->cfg_retry_init;
	retry_max = cfg->cfg_retry_max;
	limit = cfg->cfg_retry_limit;
	CONFIG_REFRELE(cfg);
	cfg = NULL;

	retry = retry_init * (1ULL << ++pkt->pkt_xmit);
	if (retry > retry_max)
		retry = retry_max;

	if (pkt->pkt_xmit > limit) {
		ikev2_send_cb_t cb = req->i2r_cb;

		cb(sa, NULL, req->i2r_arg);

		(void) bunyan_info(log,
		    "Transmit timeout on packet; deleting IKE SA",
		    BUNYAN_T_END);
		ikev2_sa_condemn(sa);
		return;
	}

	/*
	 * If sendfromto() errors, it will log the error, however there's not
	 * much that can be done if it fails, other than just wait to try
	 * again, so we ignore the return value.
	 */
	(void) ikev2_send_common(pkt);

	if (!ikev2_sa_arm_timer(sa, I2SA_EVT_PKT_XMIT, retry)) {
		(void) bunyan_error(log,
		    "No memory to reschedule packet retransmit; "
			    "deleting IKE SA", BUNYAN_T_END);
		ikev2_sa_condemn(sa);
	}
}

/*
 * Handle the instance where an inbound request is a retransmit by sending
 * out last response.  Returns B_TRUE if packet was processed.
 */
static boolean_t
ikev2_handle_retransmit(pkt_t *req)
{
	ikev2_sa_t *i2sa = req->pkt_sa;
	pkt_t *resp = NULL;
	uint32_t msgid = ntohl(pkt_header(req)->msgid);

	VERIFY(!MUTEX_HELD(&i2sa->i2sa_queue_lock));
	VERIFY(MUTEX_HELD(&i2sa->i2sa_lock));

	if (I2P_RESPONSE(req))
		return (B_FALSE);

	if ((resp = ikev2_sa_get_response(i2sa, req)) == NULL)
		return (B_FALSE);

	(void) bunyan_debug(log, "Resending last response", BUNYAN_T_END);
	ikev2_send_common(resp);
	ikev2_pkt_free(req);
	return (B_TRUE);
}

/* Returns B_TRUE if resp was processed */
static boolean_t
ikev2_handle_response(pkt_t *resp)
{
	ikev2_sa_t *i2sa = resp->pkt_sa;
	i2sa_req_t *i2req = &i2sa->last_req;
	pkt_t *last = i2sa->last_sent;
	ikev2_send_cb_t cb = i2req->i2r_cb;
	uint32_t msgid = ntohl(pkt_header(resp)->msgid);

	VERIFY(!MUTEX_HELD(&i2sa->i2sa_queue_lock));
	VERIFY(MUTEX_HELD(&i2sa->i2sa_lock));

	if (!I2P_RESPONSE(resp))
		return (B_FALSE);

	if (msgid != i2req->i2r_msgid) {
		/*
		 * Not a response to an outstanding request.
		 *
		 * XXX: Send INVALID_MESSAGE_ID notification in certain
		 * circumstances.  For now, drop.
		 */
		goto discard;
	}

	if (pkt_get_payload(resp, IKEV2_PAYLOAD_SK, NULL) != NULL) {
		if (!ikev2_pkt_signverify(resp, B_FALSE))
			goto discard;
		/*
		 * This also indexes and verifies the sizes of the decrypted
		 * payloads.
		 */
		if (!ikev2_pkt_encryptdecrypt(resp, B_FALSE))
			goto discard;
	}

	(void) ikev2_sa_disarm_timer(i2sa, I2SA_EVT_PKT_XMIT);

	i2sa->last_sent = NULL;
	i2req->i2r_pkt = NULL;

	/*
	 * The IKE_SA_INIT packets need to be retained for the IKE_AUTH
	 * exchange.
	 */
	if (last != i2sa->init_i)
		ikev2_pkt_free(last);

	cb(i2sa, resp, i2req->i2r_arg);
	return (B_TRUE);

discard:
	ikev2_pkt_free(resp);
	return (B_TRUE);
}

/*
 * Dispatches any queued messages and services any events that have fired.
 * Function must be called with sa->i2sa_queue_lock held.  If another thread
 * is already processing the queue for this IKE SA, the function will return
 * without doing any processing.  In all instances, the function returns with
 * sa->i2sa_queue_lock held.
 */
void
ikev2_dispatch(ikev2_sa_t *sa)
{
	VERIFY(IS_WORKER);
	int rc;

	VERIFY(MUTEX_HELD(&sa->i2sa_queue_lock));

	/*
	 * The first thread that acquires i2sa_lock for this SA will pin
	 * the SA to itself by setting i2sa_tid to it's tid (whole holding
	 * i2sa_lock).  Outside of IKE SA creation and destruction, this
	 * should be the only other path to acquiring i2sa_lock for this SA.
	 * If we cannot immediately acquire i2sa_lock, it's either being
	 * condemned (in which case we don't care about dispatching any
	 * pending items), or another thread has already started processing
	 * (in which case we let it do the processing).  In either instance,
	 * we can just exit.
	 */
	switch ((rc = mutex_trylock(&sa->i2sa_lock))) {
	case 0:
		if (sa->i2sa_tid != 0 && sa->i2sa_tid != thr_self()) {
			/*
			 * It is possible we've acquired i2sa_lock between
			 * iterations of the queue processing loop below
			 * that is running on another thread.  If that happens,
			 * just release the lock to allow the other thread to
			 * proceed, and we return.
			 */
			mutex_exit(&sa->i2sa_lock);
			return;
		}

		/*
		 * However, if we have acquired the lock, and i2sa_tid has
		 * already been set to us, we somehow failed to unpin this SA
		 * in a previous call to ikev2_dispatch(), and indicates a
		 * code error somewhere.
		 */
		VERIFY3U(sa->i2sa_tid, ==, 0);
		break;
	case EBUSY:
		return;
	default:
		TSTDERR(rc, fatal, "Unexpected mutex_tryenter() failure");
		abort();
	}

	/* Pin the IKE SA to us */
	sa->i2sa_tid = thr_self();

	while (sa->i2sa_events != 0 || !I2SA_QUEUE_EMPTY(sa)) {
		i2sa_msg_type_t type = I2SA_MSG_NONE;
		void *data = NULL;

		/* Grab any pending events and a queue item if available */

		i2sa_evt_t events = sa->i2sa_events;
		sa->i2sa_events = I2SA_EVT_NONE;

		/*
		 * All of these are oneshot periodics.  If they've fired,
		 * clear the id while we hold both the queue lock and
		 * the SA lock to indicate they're not armed while no other
		 * thread can rearm them (since we hold i2sa_lock).
		 */
		if (events & I2SA_EVT_P1_EXPIRE)
			sa->i2sa_p1_timer = 0;
		if (events & I2SA_EVT_HARD_EXPIRE)
			sa->i2sa_hardlife_timer = 0;
		if (events & I2SA_EVT_SOFT_EXPIRE)
			sa->i2sa_softlife_timer = 0;
		if (events & I2SA_EVT_PKT_XMIT)
			sa->i2sa_xmit_timer = 0;

		if (!I2SA_QUEUE_EMPTY(sa)) {

			/* Pick off a message and release the queue for now */
			type = sa->i2sa_queue[sa->i2sa_queue_end].i2m_type;
			data = sa->i2sa_queue[sa->i2sa_queue_end].i2m_data;

			/*
			 * If we see an empty message, the queue is corrupt.
			 * Abort to get a snapshot of the process.
			 */
			VERIFY3S(type, !=, I2SA_MSG_NONE);

			sa->i2sa_queue[sa->i2sa_queue_end].i2m_type =
			    I2SA_MSG_NONE;
			sa->i2sa_queue[sa->i2sa_queue_end].i2m_data = NULL;
			sa->i2sa_queue_end++;
			sa->i2sa_queue_end %= I2SA_QUEUE_DEPTH;
		}

		/*
		 * Release the queue so other threads can queue messages for
		 * this IKE SA.  Since we retain i2sa_lock while processing
		 * the messages, we release i2sa_lock and reacquire the
		 * queue lock and then i2sa_lock before starting another
		 * iteration.  The i2sa_tid check prevents another thread
		 * from doing anything beyond adding messages to the queue
		 * while we're still running.
		 */
		mutex_exit(&sa->i2sa_queue_lock);

		if (events & I2SA_EVT_P1_EXPIRE) {
			events &= ~(I2SA_EVT_P1_EXPIRE);

			/*
			 * If the P1 timer happened to fire around the same
			 * time we successfully authenticated, we'll ignore
			 * it.
			 */
			if (!(sa->flags & I2SA_AUTHENTICATED))
				ikev2_sa_condemn(sa);
		}
		if (events & I2SA_EVT_HARD_EXPIRE) {
			events &= ~(I2SA_EVT_HARD_EXPIRE);
			/* TODO: ikev2_sa_hard_expire(sa); */
		}
		if (events & I2SA_EVT_SOFT_EXPIRE) {
			events &= ~(I2SA_EVT_SOFT_EXPIRE);
			/* TODO: ikev2_sa_soft_expire(sa); */
		}
		if (events & I2SA_EVT_PKT_XMIT) {
			events &= ~(I2SA_EVT_PKT_XMIT);
			ikev2_retransmit(sa);
		}

		if (type != I2SA_MSG_NONE) {
			(void) bunyan_debug(log,
			    "Processing IKE SA message",
			    BUNYAN_T_STRING, "msgtype", i2sa_msgtype_str(type),
			    BUNYAN_T_POINTER, "msgdata", data,
			    BUNYAN_T_END);
		}

		switch (type) {
		case I2SA_MSG_NONE:
			break;
		case I2SA_MSG_PKT:
			VERIFY3P(((pkt_t *)data)->pkt_sa, !=, NULL);
			ikev2_dispatch_pkt(data);
			break;
		case I2SA_MSG_PFKEY:
			ikev2_dispatch_pfkey(sa, data);
			break;
		}

		mutex_exit(&sa->i2sa_lock);
		mutex_enter(&sa->i2sa_queue_lock);
		mutex_enter(&sa->i2sa_lock);
	}

	VERIFY(MUTEX_HELD(&sa->i2sa_lock));
	VERIFY(MUTEX_HELD(&sa->i2sa_queue_lock));

	/* We're done for now, release IKEv2 SA for use with other threads */
	sa->i2sa_tid = 0;
	mutex_exit(&sa->i2sa_lock);

	/*
	 * We enter with i2sa->i2sa_queue_lock held, exit with it held
	 */
}

static void
ikev2_dispatch_pkt(pkt_t *pkt)
{
	ikev2_sa_t *i2sa = pkt->pkt_sa;
	uint32_t msgid = ntohl(pkt_header(pkt)->msgid);

	VERIFY(!MUTEX_HELD(&i2sa->i2sa_queue_lock));
	VERIFY(MUTEX_HELD(&i2sa->i2sa_lock));

	if (ikev2_handle_retransmit(pkt))
		return;

	if (ikev2_handle_response(pkt))
		return;

	if (i2sa->flags & I2SA_CONDEMNED) {
		ikev2_pkt_free(pkt);
		return;
	}

	if (i2sa->inmsgid != msgid) {
		(void) bunyan_info(log,
		    "IKEv2 packet message ID out of sequence", BUNYAN_T_END);

		/*
		 * TODO: Send INVALID_MESSAGE_ID in a new informational
		 * exchange if authentiated (RFC7296 2.3) w/ rate limiting.
		 *
		 * For now, discard.
		 */
		goto discard;
	}

	switch (pkt_header(pkt)->exch_type) {
	case IKEV2_EXCH_IKE_SA_INIT:
		/* Nothing to decrypt */
		break;
	case IKEV2_EXCH_IKE_AUTH:
	case IKEV2_EXCH_CREATE_CHILD_SA:
	case IKEV2_EXCH_INFORMATIONAL:
	case IKEV2_EXCH_IKE_SESSION_RESUME:
		if (!ikev2_pkt_signverify(pkt, B_FALSE))
			goto discard;
		/*
		 * This also indexes and verifies the sizes of the
		 * decrypted payloads.
		 */
		if (!ikev2_pkt_encryptdecrypt(pkt, B_FALSE))
			goto discard;
		break;
	default:
		ikev2_pkt_log(pkt, BUNYAN_L_ERROR, "Unknown IKEv2 exchange");
		goto discard;
	}

	/* New request, no longer need previous response for retransmitting */
	if (i2sa->last_resp_sent != i2sa->init_r)
		ikev2_pkt_free(i2sa->last_resp_sent);
	i2sa->last_resp_sent = NULL;
	i2sa->inmsgid++;

	switch (pkt_header(pkt)->exch_type) {
	case IKEV2_EXCH_IKE_SA_INIT:
		ikev2_sa_init_resp(pkt);
		break;
	case IKEV2_EXCH_IKE_AUTH:
		ikev2_ike_auth_resp(pkt);
		break;
	case IKEV2_EXCH_CREATE_CHILD_SA:
		ikev2_create_child_sa_resp(pkt);
		break;
	case IKEV2_EXCH_INFORMATIONAL:
	case IKEV2_EXCH_IKE_SESSION_RESUME:
		/* TODO */
		ikev2_pkt_log(pkt, BUNYAN_L_INFO,
		    "Exchange not implemented yet");
		goto discard;
	}
	return;

discard:
	ikev2_pkt_free(pkt);
}

static void
ikev2_dispatch_pfkey(ikev2_sa_t *restrict sa, parsedmsg_t *restrict pmsg)
{
	sadb_msg_t *samsg = pmsg->pmsg_samsg;

	switch (samsg->sadb_msg_type) {
	case SADB_ACQUIRE:
		if (!(sa->flags & I2SA_AUTHENTICATED)) {
			ikev2_sa_init_init(sa, pmsg, NULL);
		} else {
			sadb_log(BUNYAN_L_INFO,
			    "CREATE_CHILD_SA not implemented yet",
			    pmsg->pmsg_samsg);

			/* TODO: Start CREATE_CHILD_SA exchange */
			parsedmsg_free(pmsg);
			I2SA_REFRELE(sa);
		}
		return;
	case SADB_EXPIRE:
		/* TODO */
		sadb_log(BUNYAN_L_INFO,
		    "SADB_EXPIRE support not implemented yet; discarding msg",
		    samsg);
		parsedmsg_free(pmsg);
		I2SA_REFRELE(sa);
		return;
	default:
		sadb_log(BUNYAN_L_ERROR,
		    "Unexpected SADB request from kernel", samsg);
		parsedmsg_free(pmsg);
		I2SA_REFRELE(sa);
	}
}

static int
select_socket(const ikev2_sa_t *i2sa)
{
	if (i2sa->laddr.ss_family == AF_INET6)
		return (ikesock6);
	if (I2SA_IS_NAT(i2sa))
		return (nattsock);
	return (ikesock4);
}
