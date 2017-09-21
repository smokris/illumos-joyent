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

#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include "defs.h"
#include "config.h"
#include "ikev2_cookie.h"
#include "ikev2_enum.h"
#include "ikev2_sa.h"
#include "ikev2_pkt.h"
#include "worker.h"
#include "inbound.h"
#include "timer.h"
#include "fromto.h"
#include "ikev2_proto.h"
#include "config.h"
#include "pkt.h"

#define	SPILOG(_level, _log, _msg, _src, _dest, _lspi, _rspi, ...)	\
	NETLOG(_level, _log, _msg, _src, _dest,				\
	BUNYAN_T_UINT64, "local_spi", (_lspi),				\
	BUNYAN_T_UINT64, "remote_spi", (_rspi),				\
	## __VA_ARGS__)

static void ikev2_retransmit_cb(te_event_t, void *);
static int select_socket(const ikev2_sa_t *);

static ikev2_sa_t *ikev2_try_new_sa(pkt_t *restrict,
    const struct sockaddr_storage *restrict,
    const struct sockaddr_storage *restrict);

/*
 * Find the IKEv2 SA for a given inbound packet (or create a new one if
 * an IKE_SA_INIT exchange) and send packet to worker.
 */
void
ikev2_dispatch(pkt_t *pkt, const struct sockaddr_storage *restrict src_addr,
    const struct sockaddr_storage *restrict dest_addr)
{
	ikev2_sa_t *i2sa = NULL;
	ike_header_t *hdr = pkt_header(pkt);
	uint64_t local_spi = INBOUND_LOCAL_SPI(hdr);
	uint64_t remote_spi = INBOUND_REMOTE_SPI(hdr);

	ikev2_pkt_log(pkt, log, BUNYAN_L_TRACE,
	    "Looking for IKE SA for packet");

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
			ikev2_pkt_log(pkt, log, BUNYAN_L_DEBUG,
			    "Cannot find IKE SA for packet; discarding");
			ikev2_pkt_free(pkt);
			return;
		}

		/*
		 * XXX: This might require special processing.
		 * Discard for now.
		 */
		if (remote_spi == 0) {
			ikev2_pkt_log(pkt, log, BUNYAN_L_DEBUG,
			    "Received packet with a 0 remote SPI; discarding");
			ikev2_pkt_free(pkt);
			return;
		}

		i2sa = ikev2_try_new_sa(pkt, dest_addr, src_addr);
		if (i2sa == NULL)
			return;
	}

	local_spi = I2SA_LOCAL_SPI(i2sa);

	/*
	 * ikev2_sa_get and ikev2_try_new_sa both return refheld ikev2_sa_t's
	 * that we then give to the inbound packet.
	 */
	pkt->pkt_sa = i2sa;

	if (worker_dispatch(WMSG_PACKET, pkt, local_spi % wk_nworkers))
		return;

	SPILOG(info, log, "worker queue full; discarding packet",
	    src_addr, dest_addr, local_spi, remote_spi);
	ikev2_pkt_free(pkt);
}

/*
 * Determine if this pkt is an request for a new IKE SA.  If so, create
 * a larval IKE SA and return it, otherwise discard the packet.
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
		goto discard;
	}

	/*
	 * RFC7296 2.2 -- IKE_SA_INIT exchanges always have msgids == 0
	 */
	if (hdr->msgid != 0) {
		errmsg = "Received an IKE_SA_INIT message with a non-zero "
		    "message id; discarding";
		goto discard;
	}

	/*
	 * It also means it must be the initiator and not a response
	 */
	if ((hdr->flags & IKEV2_FLAG_INITIATOR) != hdr->flags) {
		errmsg = "Invalid flags on packet; discarding";
		goto discard;
	}

	/*
	 * XXX: Since cookies are enabled in high traffic situations,
	 * might we want to silently discard these?
	 */
	if (!ikev2_cookie_check(pkt, l_addr, r_addr)) {
		errmsg = "Cookies missing or failed check; discarding";
		goto discard;
	}

	/* otherwise create a larval SA */
	i2sa = ikev2_sa_alloc(B_FALSE, pkt, l_addr, r_addr);
	if (i2sa == NULL) {
		errmsg = "Could not create larval IKEv2 SA; discarding";
		goto discard;
	}

	return (i2sa);

discard:
	if (errmsg != NULL)
		ikev2_pkt_log(pkt, log, BUNYAN_L_DEBUG, errmsg);

	ikev2_pkt_free(pkt);
	return (NULL);
}

/*
 * Sends a packet out.  If pkt is an error reply, is_error should be
 * set so that it is not saved for possible retransmission.
 */
boolean_t
ikev2_send(pkt_t *pkt, boolean_t is_error)
{
	VERIFY(IS_WORKER);

	ikev2_sa_t *i2sa = pkt->pkt_sa;
	ike_header_t *hdr = pkt_header(pkt);
	ssize_t len = 0;
	int s = -1;
	boolean_t resp = !!(hdr->flags & IKEV2_FLAG_RESPONSE);

	if (!ikev2_pkt_done(pkt)) {
		ikev2_pkt_free(pkt);
		return (B_FALSE);
	}

	/*
	 * We should not send out a new exchange while still waiting
	 * on a response from a previous request
	 */
	if (!resp)
		VERIFY3P(i2sa->last_sent, ==, NULL);

	char *str = ikev2_pkt_desc(pkt);
	bunyan_debug(i2sa->i2sa_log, "Sending packet",
	    BUNYAN_T_STRING, "pktdesc", str,
	    BUNYAN_T_BOOLEAN, "response", resp,
	    BUNYAN_T_UINT32, "nxmit", (uint32_t)pkt->pkt_xmit,
	    BUNYAN_T_END);
	free(str);
	str = NULL;

	s = select_socket(i2sa);
	len = sendfromto(s, pkt_start(pkt), pkt_len(pkt), &i2sa->laddr,
	    &i2sa->raddr);
	if (len == -1) {
		if (pkt != i2sa->init_i && pkt != i2sa->init_r) {
			/*
			 * If the send failed, should we still save it and let
			 * ikev2_retransmit attempt?  For now, no.
			 *
			 * Note: sendfromto() should have logged any relevant
			 * errors
			 */
			ikev2_pkt_free(pkt);
		}
		return (B_FALSE);
	}

	/*
	 * For error messages, don't expect a response, so also don't try
	 * to retransmit
	 */
	if (is_error) {
		ikev2_pkt_free(pkt);
		return (B_TRUE);
	}

	if (!resp) {
		config_t *cfg = config_get();
		hrtime_t retry = cfg->cfg_retry_init;

		CONFIG_REFRELE(cfg);

		VERIFY0(pthread_mutex_lock(&i2sa->lock));
		i2sa->last_sent = pkt;
		VERIFY0(pthread_mutex_unlock(&i2sa->lock));

		(void) schedule_timeout(TE_TRANSMIT, ikev2_retransmit_cb, i2sa,
		    retry, i2sa->i2sa_log);
		return (B_TRUE);
	}

	/*
	 * Normally, we save the last repsonse packet we've sent in order to
	 * re-send the last response in case the remote system retransmits
	 * the last exchange it initiated.  However for IKE_SA_INIT exchanges,
	 * responses of the form HDR(A,0) are not saved, as these should be
	 * either a request for cookies, a new DH group, or a failed exchange
	 * (no proposal chosen).
	 */
	if (hdr->exch_type != IKEV2_EXCH_IKE_SA_INIT ||
	    hdr->responder_spi != 0) {
		VERIFY0(pthread_mutex_lock(&i2sa->lock));
		i2sa->last_resp_sent = pkt;
		VERIFY0(pthread_mutex_unlock(&i2sa->lock));
	}

	return (B_TRUE);
}

/*
 * Retransmit callback
 */
static void
ikev2_retransmit_cb(te_event_t event, void *data)
{
	VERIFY(IS_WORKER);

	ikev2_sa_t *sa = data;
	pkt_t *pkt = sa->last_sent;
	ike_header_t *hdr = pkt_header(pkt);
	hrtime_t retry = 0, retry_init = 0, retry_max = 0;
	size_t limit = 0;
	ssize_t len;

	VERIFY0(pthread_mutex_lock(&sa->lock));

	/* XXX: what about condemned SAs */
	if (sa->outmsgid > ntohl(hdr->msgid) || sa->last_sent == NULL) {
		/* already acknowledged */
		VERIFY0(pthread_mutex_unlock(&sa->lock));
		ikev2_pkt_free(pkt);
		return;
	}
	VERIFY0(pthread_mutex_unlock(&sa->lock));

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
		bunyan_info(sa->i2sa_log,
		    "Transmit timeout on packet; deleting IKE SA",
		    BUNYAN_T_END);
		ikev2_sa_condemn(sa);
		return;
	}

	ikev2_pkt_log(pkt, sa->i2sa_log, BUNYAN_L_DEBUG, "Sending packet");

	/*
	 * If sendfromto() errors, it will log the error, but being a
	 * retransmit callback, there's not much more we can do here, so
	 * just ignore the return value.
	 */
	(void) sendfromto(select_socket(sa), pkt_start(pkt), pkt_len(pkt),
	    &sa->laddr, &sa->raddr);

	VERIFY(schedule_timeout(TE_TRANSMIT, ikev2_retransmit_cb, sa, retry,
	    sa->i2sa_log));
}

/*
 * Determine if packet is a retransmit, if so, retransmit our last
 * response and discard.  Otherwise return B_FALSE and continue processing.
 *
 * XXX better function name?
 */
static boolean_t
ikev2_retransmit_check(pkt_t *pkt)
{
	ikev2_sa_t *sa = pkt->pkt_sa;
	ike_header_t *hdr = pkt_header(pkt);
	uint32_t msgid = ntohl(hdr->msgid);
	boolean_t discard = B_TRUE;

	VERIFY0(pthread_mutex_lock(&sa->lock));
	if (sa->flags & I2SA_CONDEMNED)
		goto done;

	if (hdr->flags & IKEV2_FLAG_RESPONSE) {
		pkt_t *last = sa->last_sent;

		if (msgid != sa->outmsgid) {
			/*
			 * Not a response to our last message.
			 *
			 * XXX: Send INVALID_MESSAGE_ID notification in
			 * certain circumstances.  Drop for now.
			 */
			goto done;
		}

		/* A response to our last message */
		VERIFY3S(cancel_timeout(TE_TRANSMIT, sa,
		    sa->i2sa_log), ==, 1);

		/*
		 * Corner case: this isn't the actual response in the
		 * IKE_SA_INIT exchange, but a request to either use
		 * cookies or a different DH group.  In that case we don't
		 * want to treat it like a response (ending the exchange
		 * and resetting sa->last_sent).
		 */
		if (hdr->exch_type != IKEV2_EXCH_IKE_SA_INIT ||
		    hdr->responder_spi != 0)
			sa->last_sent = NULL;

		/* Keep IKE_SA_INIT packets until we've authed or time out */
		if (last != sa->init_i && last != sa->init_r)
			ikev2_pkt_free(last);

		discard = B_FALSE;
		goto done;
	}

	VERIFY(hdr->flags & IKEV2_FLAG_INITIATOR);

	if (msgid == sa->inmsgid) {
		pkt_t *resp = sa->last_resp_sent;
		ssize_t len = 0;

		if (resp == NULL) {
			discard = B_FALSE;
			goto done;
		}

		ikev2_pkt_log(pkt, sa->i2sa_log, BUNYAN_L_DEBUG,
		    "Resending last response");

		len = sendfromto(select_socket(sa), pkt_start(resp),
		    pkt_len(pkt), &sa->laddr, &sa->raddr);
		goto done;
	}

	if (msgid != sa->inmsgid + 1) {
		ikev2_pkt_log(pkt, sa->i2sa_log, BUNYAN_L_INFO,
		    "Message id is out of sequence");

		/*
		 * TODO: Create in informational exchange & send
		 * INVALID_MESSAGE_ID if this is a fully-formed IKE SA
		 *
		 * For now, just discard.
		 */
		goto done;
	}

	/* New exchange, free last response and get going */
	ikev2_pkt_free(sa->last_resp_sent);
	sa->last_resp_sent = NULL;
	sa->inmsgid++;
	discard = B_FALSE;

done:
	VERIFY0(pthread_mutex_unlock(&sa->lock));
	return (discard);
}

/*
 * Worker inbound function -- handle retransmits or do processing for
 * the given message exchange type;
 */
void
ikev2_inbound(pkt_t *pkt)
{
	VERIFY(IS_WORKER);

	(void) bunyan_trace(worker->w_log, "Starting IKEV2 inbound processing",
	    BUNYAN_T_END);

	if (ikev2_retransmit_check(pkt)) {
		ikev2_pkt_free(pkt);
		return;
	}

	/* XXX: Might this log msg be better in ikev2_dispatch() instead? */
	ikev2_pkt_log(pkt, pkt->pkt_sa->i2sa_log, BUNYAN_L_DEBUG,
	    "Received packet");

	switch (pkt_header(pkt)->exch_type) {
	case IKEV2_EXCH_IKE_SA_INIT:
		ikev2_sa_init_inbound(pkt);
		break;
	case IKEV2_EXCH_IKE_AUTH:
	case IKEV2_EXCH_CREATE_CHILD_SA:
	case IKEV2_EXCH_INFORMATIONAL:
	case IKEV2_EXCH_IKE_SESSION_RESUME:
		/* TODO */
		ikev2_pkt_log(pkt, pkt->pkt_sa->i2sa_log, BUNYAN_L_INFO,
		    "Exchange not implemented yet");
		ikev2_pkt_free(pkt);
		break;
	default:
		ikev2_pkt_log(pkt, pkt->pkt_sa->i2sa_log, BUNYAN_L_ERROR,
		    "Unknown IKEv2 exchange");
		ikev2_pkt_free(pkt);
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
