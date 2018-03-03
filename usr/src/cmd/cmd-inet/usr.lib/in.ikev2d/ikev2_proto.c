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
 * Copyright 2018, Joyent, Inc
 */

#include <errno.h>
#include <ipsec_util.h>
#include <libcmdutils.h>
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
#include "ikev2_pkt_check.h"
#include "ikev2_proto.h"
#include "ikev2_sa.h"
#include "pfkey.h"
#include "pkt.h"
#include "util.h"
#include "worker.h"

static void ikev2_dispatch_pkt(pkt_t *);
static void ikev2_dispatch_pfkey(ikev2_sa_t *restrict, parsedmsg_t *restrict);
static void ikev2_informational(pkt_t *);

static int select_socket(const struct sockaddr *, boolean_t);

static ikev2_sa_t *ikev2_try_new_sa(pkt_t *restrict,
    const struct sockaddr *restrict,
    const struct sockaddr *restrict);

static ikev2_sa_t *
get_i2sa_inbound(uint64_t local_spi, uint64_t remote_spi,
    const struct sockaddr *src, const struct sockaddr *dst,
    pkt_t *restrict pkt)
{
	ikev2_sa_t *i2sa = NULL;

	/*
	 * We always use the local SPI when present (!= 0) to lookup an IKEv2
	 * SA.  The only time the local SPI is missing is during an IKE_SA_INIT
	 * exchange where we are the responder (as we have not yet allocated
	 * our ikev2_sa_t yet and thus haven't generated our SPI).   If such
	 * a packet is a retransmit (which could be due to packet loss of our
	 * reply, or due to us requesting a COOKIE or now KE group), we must
	 * still be able to find the ikev2_sa_t instance for this connection
	 * in progress.  Since the remote SPI is (as the term suggests) is
	 * picked by the remote peer, we have no control over it, and it is
	 * possible two peers could choose the same value.  To disambiguate, we
	 * have to not only look at the local and remote addresses, we must
	 * also look at the original remote packet that triggered the creation
	 * of our IKEv2 SA.
	 */
	if (local_spi != 0 &&
	    (i2sa = ikev2_sa_getbylspi(local_spi, !I2P_INITIATOR(pkt))) != NULL)
		return (i2sa);
	if (pkt_header(pkt)->exch_type != IKEV2_EXCH_IKE_SA_INIT)
		return (NULL);
	return (ikev2_sa_getbyrspi(remote_spi, dst, src, pkt));
}

/*
 * Find the IKEv2 SA for a given inbound packet (or create a new one if
 * an IKE_SA_INIT exchange) and either process or add to the IKEv2 SA queue.
 */
void
ikev2_inbound(pkt_t *restrict pkt, const struct sockaddr *restrict src,
    const struct sockaddr *restrict dest)
{
	ikev2_sa_t *i2sa = NULL;
	ike_header_t *hdr = pkt_header(pkt);
	uint64_t local_spi = INBOUND_LOCAL_SPI(hdr);
	uint64_t remote_spi = INBOUND_REMOTE_SPI(hdr);

	VERIFY(IS_WORKER);

	ikev2_pkt_log(pkt, BUNYAN_L_TRACE, "Received packet");

	i2sa = get_i2sa_inbound(local_spi, remote_spi, dest, src, pkt);
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
		i2sa = ikev2_try_new_sa(pkt, dest, src);
		if (i2sa == NULL) {
			ikev2_pkt_free(pkt);
			return;
		}
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

	pkt->pkt_sa = i2sa;
	ikev2_sa_queuemsg(i2sa, I2SA_MSG_PKT, pkt);

	I2SA_REFRELE(i2sa);
}

/*
 * Determine if this pkt is an request for a new IKE SA.  If so, create
 * a larval IKE SA and return it, otherwise return NULL.  It is assumed
 * caller will discard packet when NULL is returned.
 */
static ikev2_sa_t *
ikev2_try_new_sa(pkt_t *restrict pkt,
    const struct sockaddr *restrict l_addr,
    const struct sockaddr *restrict r_addr)
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
	if (!ikev2_cookie_check(pkt, l_addr, r_addr))
		goto fail;

	/* otherwise create a larval SA */
	i2sa = ikev2_sa_alloc(pkt, l_addr, r_addr);
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
 * Take a parsed pfkey message (either an SADB_ACQUIRE or SADB_EXPIRE message),
 * and either locate an existing IKE SA and add to it's queue, or create a
 * larval IKE SA and kickoff the IKE_SA_INIT exchange.
 */
void
ikev2_pfkey(parsedmsg_t *pmsg)
{
	ikev2_sa_t *i2sa = NULL;
	sadb_x_kmc_t *kmc = NULL;
	sadb_sa_t *sadb_sa = NULL;
	sockaddr_u_t laddr;
	sockaddr_u_t raddr;

	laddr = pmsg->pmsg_sau;
	raddr = pmsg->pmsg_dau;

	kmc = (sadb_x_kmc_t *)pmsg->pmsg_exts[SADB_X_EXT_KM_COOKIE];
	sadb_sa = (sadb_sa_t *)pmsg->pmsg_exts[SADB_EXT_SA];

	if (kmc != NULL && sadb_sa != NULL) {
		uint64_t local_spi = 0;
		boolean_t initiator = B_FALSE;

		VERIFY3U(kmc->sadb_x_kmc_exttype, ==, SADB_X_EXT_KM_COOKIE);
		local_spi = kmc->sadb_x_kmc_cookie64;

		if (sadb_sa->sadb_sa_flags & IKEV2_SADB_INITIATOR)
			initiator = B_TRUE;

		i2sa = ikev2_sa_getbylspi(local_spi, initiator);
	} else {
		if (pmsg->pmsg_samsg->sadb_msg_type != SADB_ACQUIRE) {
			(void) bunyan_error(log,
			    "Received an non-ACQUIRE SADB message with a "
			    "missing KMC", BUNYAN_T_END);
			parsedmsg_free(pmsg);
			return;
		}

		/*
		 * XXX: Since we set the KMC on every IPsec SA we create,
		 * can this situation ever be anything other than an
		 * SADB_ACQUIRE from the kernel?
		 */
		i2sa = ikev2_sa_getbyaddr(laddr.sau_sa, raddr.sau_sa);
	}

	if (i2sa == NULL) {
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
		i2sa = ikev2_sa_alloc(NULL, laddr.sau_sa, raddr.sau_sa);
		if (i2sa == NULL) {
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
			RULE_REFRELE(rule);
			return;
		}

		mutex_enter(&i2sa->i2sa_lock);
		key_add_ike_spi(LOG_KEY_LSPI, I2SA_LOCAL_SPI(i2sa));
		/* Pass ref from config_get_rule() to i2sa */
		i2sa->i2sa_rule = rule;
		mutex_exit(&i2sa->i2sa_lock);
	} else {
		key_add_ike_spi(LOG_KEY_LSPI, I2SA_LOCAL_SPI(i2sa));
		(void) bunyan_trace(log, "Found IKEv2 SA", BUNYAN_T_END);
		mutex_enter(&i2sa->i2sa_queue_lock);
	}

	ikev2_sa_queuemsg(i2sa, I2SA_MSG_PFKEY, pmsg);
	I2SA_REFRELE(i2sa);
}

/*
 * Attempt to create an IKEv2 SA  and start an IKE_SA_INIT exchange
 * from the given rule.
 *
 * XXX: This currently only works for transport mode IKE SAs.  The main problem
 * with being able to support tunnel mode is figuring what addresses to
 * use to query the inner src/dst addresses.
 */
void
ikev2_sa_init_cfg(config_rule_t *rule)
{
	ikev2_sa_t *i2sa = NULL;
	parsedmsg_t *pmsg = NULL;
	ts_t src = { .ts_proto = IPPROTO_IP };
	ts_t dst = { .ts_proto = IPPROTO_IP };

	if (!config_addr_to_ss(&rule->rule_local_addr[0], &src.ts_ss))
		goto fail;
	if (!config_addr_to_ss(&rule->rule_remote_addr[0], &dst.ts_ss))
		goto fail;

	if (!pfkey_inverse_acquire(&src, &dst, NULL, NULL, &pmsg)) {
		if (pmsg == NULL) {
			STDERR(error, "Inverse acquire failed");
			goto fail;
		}

		int errval = pmsg->pmsg_samsg->sadb_msg_errno;
		uint32_t diag = pmsg->pmsg_samsg->sadb_x_msg_diagnostic;

		if (errval == ENOENT) {
			char *label = rule->rule_label;

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

	i2sa = ikev2_sa_alloc(NULL, &src.ts_sa, &dst.ts_sa);
	if (i2sa == NULL) {
		STDERR(error, "Failed to allocate larval IKE SA");
		goto fail;
	}

	mutex_enter(&i2sa->i2sa_lock);
	i2sa->i2sa_rule = rule;
	mutex_exit(&i2sa->i2sa_lock);

	ikev2_sa_queuemsg(i2sa, I2SA_MSG_PFKEY, pmsg);
	I2SA_REFRELE(i2sa);
	return;

fail:
	if (i2sa != NULL) {
		VERIFY(MUTEX_HELD(&i2sa->i2sa_queue_lock));
		mutex_enter(&i2sa->i2sa_lock);
		i2sa->flags |= I2SA_CONDEMNED;
		ikev2_sa_condemn(i2sa);
		mutex_exit(&i2sa->i2sa_lock);
		mutex_exit(&i2sa->i2sa_queue_lock);

		I2SA_REFRELE(i2sa);
	}

	parsedmsg_free(pmsg);
	RULE_REFRELE(rule);
}

static boolean_t
ikev2_send_common(pkt_t *restrict pkt,
    const struct sockaddr *restrict laddr,
    const struct sockaddr *restrict raddr,
    boolean_t nat_is_known)
{
	ike_header_t *hdr = pkt_header(pkt);
	custr_t *desc = NULL;
	ssize_t len = 0;
	int s = -1;

	if (!ikev2_pkt_done(pkt)) {
		ikev2_pkt_free(pkt);
		return (B_FALSE);
	}

	s = select_socket(laddr, nat_is_known);

	desc = ikev2_pkt_desc(pkt);
	(void) bunyan_debug(log, "Sending packet",
	    BUNYAN_T_UINT32, "msgid", ntohll(hdr->msgid),
	    BUNYAN_T_BOOLEAN, "response", I2P_RESPONSE(pkt),
	    BUNYAN_T_STRING, "pktdesc", (desc != NULL) ? custr_cstr(desc) : "",
	    BUNYAN_T_UINT32, "nxmit", (uint32_t)pkt->pkt_xmit,
	    BUNYAN_T_END);
	custr_free(desc);

	len = sendfromto(s, pkt_start(pkt), pkt_len(pkt), laddr, raddr);
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
	hrtime_t retry = config->cfg_retry_init;

	VERIFY(IS_WORKER);
	VERIFY(!MUTEX_HELD(&i2sa->i2sa_queue_lock));
	VERIFY(MUTEX_HELD(&i2sa->i2sa_lock));
	VERIFY(!I2P_RESPONSE(req));
	VERIFY3P(cb, !=, NULL);

	/*
	 * Shouldn't try to start a new exchange when one is already in
	 * progress.
	 */
	VERIFY3P(i2req->i2r_pkt, ==, NULL);

	if (!ikev2_send_common(req, SSTOSA(&i2sa->laddr), SSTOSA(&i2sa->raddr),
	    I2SA_IS_NAT(i2sa))) {
		/*
		 * XXX: For now at least, we don't bother with attempting to
		 * retransmit a packet if the original transmission failed.
		 *
		 * We might want to instead still return 'success' and
		 * let the retransmit timer attempt to send + only 'fail'
		 * if it times out, or not return any status (i.e. change
		 * return to 'void') and condemn the IKEv2 SA if we
		 * can't arm the PKT_XMIT timer.
		 */
		ikev2_pkt_free(req);
		return (B_FALSE);
	}

	/*
	 * If we receive a valid response to this request,
	 * ikev2_handle_response() will consume req and invoke the given
	 * callback (w/ both arg and the response packet as arguments).
	 * Success will also cancel the retransmit counter.  If this request
	 * times out, ikev2_timeout() will consume req and invoke the given
	 * callback w/ arg and a NULL response packet (to indicate the request
	 * was a failure and allow the callback to do any necessary cleanup).
	 */
	i2req->i2r_pkt = req;
	i2req->i2r_msgid = ntohl(pkt_header(req)->msgid);
	i2req->i2r_cb = (void *)cb;
	i2req->i2r_arg = arg;

	if (!ikev2_sa_arm_timer(i2sa, retry, I2SA_EVT_PKT_XMIT, i2req)) {
		STDERR(error, "Could not arm packet retransmit timer");
		ikev2_pkt_free(req);
		return (B_FALSE);
	}

	return (B_TRUE);
}

/* Send a response */
void
ikev2_send_resp(pkt_t *restrict resp)
{
	ikev2_sa_t *i2sa = resp->pkt_sa;
	ike_header_t *hdr = pkt_header(resp);

	VERIFY(IS_WORKER);
	VERIFY(!MUTEX_HELD(&i2sa->i2sa_queue_lock));
	VERIFY(MUTEX_HELD(&i2sa->i2sa_lock));
	VERIFY(I2P_RESPONSE(resp));

	/*
	 * Normally, we save the last response packet we've sent in order to
	 * re-send the last response in case the remote system retransmits
	 * the last exchange it initiated.  However for IKE_SA_INIT exchanges,
	 * _responses_ of the form HDR(A,0) are not saved for retransmission.
	 * These responses should be either a request for cookies, a new DH
	 * group, or a failed exchange (no proposal chosen), and we will
	 * want to process the resulting reply (which, if it happens, should
	 * be a restart of the IKE_SA_INIT exchange with the updated
	 * parameters).  The msgid in these instances will also still be 0,
	 * so we don't want to bump the expected next inbound msgid.
	 *
	 * We also want to wait to update i2sa->last_resp_sent and
	 * i2sa->inmsgid until after we've successfully sent a reply to a
	 * request.  If we bump it immediately upon receiving a new request,
	 * if we fail to generate a reply for some reason, the peer
	 * retransmitting the response will trigger an out of sequence message
	 * and we'll never attempt to respond again, all of which would lead
	 * to confusion.
	 */
	if (hdr->exch_type != IKEV2_EXCH_IKE_SA_INIT ||
	    hdr->responder_spi != 0) {
		ikev2_pkt_free(i2sa->last_resp_sent);
		i2sa->inmsgid++;
		i2sa->last_resp_sent = resp;
	}

	/*
	 * Ignore if we fail.  In the hope that it might be a transitory
	 * problem, let the retransmit or P1 timer (if appropriate)
	 * determine if the repsonse fails or not.
	 */
	(void) ikev2_send_common(resp, SSTOSA(&i2sa->laddr),
	    SSTOSA(&i2sa->raddr), I2SA_IS_NAT(i2sa));
}

/* Used for sending responses outside of an IKEv2 SA */
boolean_t
ikev2_send_resp_addr(pkt_t *restrict resp,
    const struct sockaddr *restrict laddr,
    const struct sockaddr *restrict raddr)
{
	VERIFY(IS_WORKER);
	VERIFY(I2P_RESPONSE(resp));
	VERIFY3P(resp->pkt_sa, ==, NULL);

	return (ikev2_send_common(resp, laddr, raddr, B_FALSE));
}

/*
 * Trigger a resend of our last request due to timeout waiting for a
 * response.
 */
void
ikev2_retransmit_cb(void *data)
{
	VERIFY(IS_WORKER);

	i2sa_req_t *i2req = data;
	ikev2_sa_t *i2sa = i2req->i2r_pkt->pkt_sa;

	I2SA_REFHOLD(i2sa);

	mutex_enter(&i2sa->i2sa_queue_lock);
	i2req->i2r_fired = B_TRUE;
	i2req->i2r_timer = 0;
	mutex_exit(&i2sa->i2sa_queue_lock);

	ikev2_sa_post_event(i2sa, I2SA_EVT_PKT_XMIT);

	I2SA_REFRELE(i2sa);
}

/*
 * Resend our last request.
 */
static void
ikev2_retransmit(ikev2_sa_t *restrict sa, i2sa_req_t *restrict req)
{
	pkt_t *pkt = req->i2r_pkt;
	hrtime_t retry = 0, retry_init = 0, retry_max = 0;
	size_t limit = 0;

	VERIFY(IS_WORKER);
	VERIFY(!MUTEX_HELD(&sa->i2sa_queue_lock));
	VERIFY(MUTEX_HELD(&sa->i2sa_lock));

	req->i2r_fired = B_FALSE;

	if (pkt == NULL) {
		/* already acknowledged */
		return;
	}

	retry_init = config->cfg_retry_init;
	retry_max = config->cfg_retry_max;
	limit = config->cfg_retry_limit;

	retry = retry_init * (1ULL << ++pkt->pkt_xmit);
	if (retry > retry_max)
		retry = retry_max;

	if (pkt->pkt_xmit > limit) {
		ikev2_send_cb_t cb = (ikev2_send_cb_t)req->i2r_cb;

		cb(sa, NULL, req->i2r_arg);

		(void) bunyan_debug(log,
		    "Transmit timeout on packet",
		    BUNYAN_T_END);

		sa->flags |= I2SA_CONDEMNED;
		ikev2_sa_clear_req(sa, req);
		return;
	}

	/*
	 * If sendfromto() errors, it will log the error, however there's not
	 * much that can be done if it fails, other than just wait to try
	 * again, so we ignore the return value.
	 */
	(void) ikev2_send_common(pkt, SSTOSA(&sa->laddr), SSTOSA(&sa->raddr),
	    I2SA_IS_NAT(sa));

	if (!ikev2_sa_arm_timer(sa, retry, I2SA_EVT_PKT_XMIT, req)) {
		(void) bunyan_error(log,
		    "No memory to reschedule packet retransmit; "
		    "deleting IKE SA", BUNYAN_T_END);
		sa->flags |= I2SA_CONDEMNED;
	}
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

	/*
	 * TODO: Cap how long we spend in the loop by either time or iterations
	 * and defer processing for some amount of time if we spend too much
	 * time dealing with one IKEv2 SA
	 */
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

			sa->flags |= I2SA_CONDEMNED;
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

			/*
			 * XXX: When WINDOW_SIZE is added, scan through all
			 * i2sa_req_t's and call ikev2_retransmit for each
			 * where i2r_fired == B_TRUE, and remove VERIFY
			 */
			VERIFY(sa->last_req.i2r_fired);
			ikev2_retransmit(sa, &sa->last_req);
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

	/* Once all the outstanding requests are done, we can do it */
	if ((sa->flags & I2SA_CONDEMNED) && !ikev2_sa_has_requests(sa)) {
		ikev2_sa_condemn(sa);
		return;
	}

	/* We're done for now, release IKEv2 SA for use with other threads */
	sa->i2sa_tid = 0;
	mutex_exit(&sa->i2sa_lock);

	/*
	 * We enter with i2sa->i2sa_queue_lock held, exit with it held
	 */
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

	VERIFY(!MUTEX_HELD(&i2sa->i2sa_queue_lock));
	VERIFY(MUTEX_HELD(&i2sa->i2sa_lock));

	if (I2P_RESPONSE(req))
		return (B_FALSE);

	if ((resp = ikev2_sa_get_response(i2sa, req)) == NULL)
		return (B_FALSE);

	(void) bunyan_debug(log, "Resending last response", BUNYAN_T_END);
	(void) ikev2_send_common(resp, SSTOSA(&i2sa->laddr),
	    SSTOSA(&i2sa->raddr), I2SA_IS_NAT(i2sa));
	ikev2_pkt_free(req);
	return (B_TRUE);
}

/* Returns B_TRUE if resp was processed */
static boolean_t
ikev2_handle_response(pkt_t *resp)
{
	ikev2_sa_t *i2sa = resp->pkt_sa;
	i2sa_req_t *i2req = &i2sa->last_req;
	ikev2_send_cb_t cb = (ikev2_send_cb_t)i2req->i2r_cb;
	void *arg = i2req->i2r_arg;
	uint32_t msgid = ntohl(pkt_header(resp)->msgid);
	ikev2_exch_t exch_type;

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

	exch_type = pkt_header(resp)->exch_type;

	if (exch_type != IKEV2_EXCH_IKE_SA_INIT &&
	    !ikev2_pkt_encryptdecrypt(resp, B_FALSE))
		goto discard;

	/*
	 * RFC7296 is fairly clear that problems with response traffic should
	 * not themselves generate additional traffic except in specific
	 * circumstances.  Additionally section 2.5 specifically states that
	 * the critical bit MUST NOT be set in responses.  Therefore we
	 * just discard these packets without generating another exchange.
	 */
	if (!ikev2_pkt_check_payloads(resp) ||
	    ikev2_pkt_check_critical(resp) != IKEV2_PAYLOAD_NONE)
		goto discard;

	/*
	 * Since IKE_SA_INIT exchanges are unprotected, it's possible that
	 * certain replies may be ignored, so we cannot dispose of our
	 * request packet or cancel the retransmit timer here.  Instead
	 * the callback function (it's always ikev2_sa_init_init_resp for
	 * an IKE_SA_INIT exchange), must determine if it can do this.
	 *
	 * For everything else, we can get rid of the request.
	 */
	if (exch_type != IKEV2_EXCH_IKE_SA_INIT)
		ikev2_sa_clear_req(i2sa, i2req);

	cb(i2sa, resp, arg);
	ikev2_pkt_free(resp);
	return (B_TRUE);

discard:
	ikev2_pkt_free(resp);
	return (B_TRUE);
}

static void
ikev2_dispatch_pkt(pkt_t *pkt)
{
	ikev2_sa_t *i2sa = pkt->pkt_sa;
	uint32_t msgid = ntohl(pkt_header(pkt)->msgid);
	ikev2_exch_t exch_type = pkt_header(pkt)->exch_type;
	uint8_t crit_pay = IKEV2_PAYLOAD_NONE;

	VERIFY(!MUTEX_HELD(&i2sa->i2sa_queue_lock));
	VERIFY(MUTEX_HELD(&i2sa->i2sa_lock));

	if (exch_type != IKEV2_EXCH_IKE_SA_INIT &&
	    !ikev2_pkt_signverify(pkt, B_FALSE))
		goto discard;

	if (!I2P_RESPONSE(pkt) && i2sa->inmsgid != msgid) {
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

	if (ikev2_handle_response(pkt))
		return;

	/*
	 * Once we are condemned, we only want to process replies to our
	 * outstanding requests.
	 */
	if (i2sa->flags & I2SA_CONDEMNED) {
		ikev2_pkt_free(pkt);
		return;
	}

	if (ikev2_handle_retransmit(pkt))
		return;

	/* Decyption will also index the encrypted payloads */
	if (exch_type != IKEV2_EXCH_IKE_SA_INIT &&
	    !ikev2_pkt_encryptdecrypt(pkt, B_FALSE))
		goto discard;

	if (!ikev2_pkt_check_payloads(pkt)) {
		if (exch_type == IKEV2_EXCH_IKE_SA_INIT)
			goto discard;

		/* TODO: send INVALID_SYNTAX notification */
		goto discard;
	}

	crit_pay = ikev2_pkt_check_critical(pkt);
	if (crit_pay != IKEV2_PAYLOAD_NONE) {
		pkt_t *resp = NULL;

		/*
		 * Since IKE_SA_INIT exchanges are unprotected, we ignore any
		 * errors, and let the P1 timer expire if we never receive
		 * a valid request.
		 */
		if (exch_type == IKEV2_EXCH_IKE_SA_INIT)
			goto discard;

		/* Any other exchange is protected, so respond with an error */
		if ((resp = ikev2_pkt_new_response(pkt)) == NULL)
			goto discard;

		/* This is the 2nd payload, it should fit */
		VERIFY(ikev2_add_notify_full(resp, IKEV2_PROTO_NONE, 0,
		    IKEV2_N_UNSUPPORTED_CRITICAL_PAYLOAD,
		    &crit_pay, sizeof (crit_pay)));

		(void) ikev2_send_resp(resp);
		goto discard;
	}

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
		ikev2_informational(pkt);
		break;
	}

discard:
	ikev2_pkt_free(pkt);
}

static void
ikev2_dispatch_pfkey(ikev2_sa_t *restrict sa, parsedmsg_t *restrict pmsg)
{
	sadb_msg_t *samsg = pmsg->pmsg_samsg;

	VERIFY(!MUTEX_HELD(&sa->i2sa_queue_lock));
	VERIFY(MUTEX_HELD(&sa->i2sa_lock));

	/* Is there a request already in progress? */
	if (sa->last_req.i2r_pkt != NULL) {
		(void) bunyan_debug(log, "Discarding sadb message",
		    BUNYAN_T_END);

		parsedmsg_free(pmsg);
		return;
	}

	switch (samsg->sadb_msg_type) {
	case SADB_ACQUIRE:
		/*
		 * If we've already authenticated, we need to do a
		 * CREATE_CHILD_SA exchange, otherwise we need to start
		 * an IKE_SA_INIT exchange.  If we've already started an
		 * IKE_SA_INIT exchange, that request will be in progress,
		 * and the sadb message will be discarded before getting here
		 * with the above checks.
		 */
		if (sa->flags & I2SA_AUTHENTICATED)
			ikev2_create_child_sa_init(sa, pmsg);
		else
			ikev2_sa_init_init(sa, pmsg);
		return;
	case SADB_EXPIRE: {
		const char *exptype = NULL;
		char msg[128] = { 0 };

		if (pmsg->pmsg_exts[SADB_EXT_LIFETIME_HARD] != NULL) {
			exptype = "HARD";
		} else if (pmsg->pmsg_exts[SADB_EXT_LIFETIME_SOFT] != NULL) {
			exptype = "SOFT";
		} else if (pmsg->pmsg_exts[SADB_X_EXT_LIFETIME_IDLE] != NULL) {
			exptype = "IDLE";
		} else {
			(void) bunyan_error(log, "Unknown SADB_EXPIRE message",
			    BUNYAN_T_END);
			parsedmsg_free(pmsg);
			return;
		}

		if (pmsg->pmsg_exts[SADB_EXT_LIFETIME_HARD] != NULL) {
			ikev2_hard_expire(sa, pmsg);
			return;
		}

		/* TODO: Soft expire (rekey), idle (?) */
		(void) snprintf(msg, sizeof (msg),
		    "%s SADB_EXPIRE support not implemented yet; discarding",
		    exptype);

		sadb_log(BUNYAN_L_INFO, msg, samsg);
		parsedmsg_free(pmsg);
		return;
	}
	default:
		sadb_log(BUNYAN_L_ERROR,
		    "Unexpected SADB request from kernel", samsg);
		parsedmsg_free(pmsg);
	}
}

/*
 * XXX:The handling of INFORMATIONAL exchanges is still in it's infancy, so this
 * is just an initial stab at it, and it's form may change as support for
 * more features are added.
 */

/* Since n is reachable from req, we can't mark them as restricted */
static boolean_t
ikev2_handle_notification(pkt_notify_t *n, pkt_t *req, pkt_t *restrict resp)
{
	switch (n->pn_type) {
	case IKEV2_N_AUTHENTICATION_FAILED:
		/*
		 * XXX: We may want to track the last inbound IKE_AUTH msgid
		 * (normally would be 1, but could be higher if EAP is used)
		 * and only act on this if the inbound msgid is
		 * last_auth_msgid + 1 (i.e. the next exchange after the
		 * IKE_AUTH exchange).
		 */
		return (ikev2_auth_failed_resp(req, resp));
	break;
	/* XXX: Any other notifications? */
	}

	return (B_TRUE);
}

static void
ikev2_informational(pkt_t *req)
{
	pkt_t *resp = ikev2_pkt_new_response(req);
	pkt_payload_t *pay = NULL;
	pkt_notify_t *n = NULL;
	size_t payidx = 0, nidx = 0;

	if (resp == NULL) {
		(void) bunyan_error(log,
		    "No memory to respond to an INFORMATIONL request",
		    BUNYAN_T_END);
		return;
	}

	for (payidx = 0; payidx < req->pkt_payload_count; payidx++) {
		n = NULL;
		pay = pkt_payload(req, payidx);

		if (pay->pp_type == IKEV2_PAYLOAD_NOTIFY) {
			VERIFY3U(nidx, <=, req->pkt_notify_count);
			n = pkt_notify(req, nidx++);
			if (!ikev2_handle_notification(n, req, resp))
				goto fail;
			continue;
		}

		if (pay->pp_type == IKEV2_PAYLOAD_DELETE)
			ikev2_handle_delete(req->pkt_sa, pay, resp);

		/* TODO: Handle other payloads */
	}

	ikev2_send_resp(resp);
	return;

fail:
	ikev2_pkt_free(resp);
}

/* Picks the socket to use for sending based on our local address. */
static int
select_socket(const struct sockaddr *laddr, boolean_t nat_is_known)
{
	if (laddr->sa_family == AF_INET6)
		return (ikesock6);

	/*
	 * If our local port is IPPORT_IKE_NATT (4500), we always use the
	 * NATT (NAT-traversal) socket.  If our IKEv2 SA determines either end
	 * is behind a NAT, we also use the NATT socket for any subsequent
	 * transmissions.
	 */
	if (nat_is_known || ss_port(laddr) == IPPORT_IKE_NATT)
		return (nattsock);

	return (ikesock4);
}
