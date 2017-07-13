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
 * Copyright 2012 Jason King.
 * Copyright 2017 Joyent, Inc
 */

#include <sys/types.h>
#include <sys/socket.h>
#include "defs.h"
#include "config.h"
#include "ikev2_sa.h"
#include "ikev2_pkt.h"
#include "worker.h"
#include "inbound.h"

#define	SPILOG(_level, _log, _msg, _src, _dest, _lspi, _rspi, ...)	\
	NETLOG(_level, _log, _msg, _src, _dest,				\
	BUNYAN_T_UINT64, "local_spi", (_lspi),				\
	BUNYAN_T_UINT64, "remote_spi", (_rspi),				\
	## __VA_ARGS__)

static int select_socket(const ikev2_sa_t *, const struct sockaddr_storage *);

void
ikev2_dispatch(pkt_t *pkt, const struct sockaddr_storage *restrict l_addr,
    const struct sockaddr_storage *restrict r_addr)
{
	ikev2_sa_t *i2sa = NULL;
	uint64_t local_spi = INBOUND_LOCAL_SPI(&pkt->pkt_header);
	uint64_t remote_spi = INBOUND_REMOTE_SPI(&pkt->pkt_header);

	i2sa = ikev2_sa_get(local_spi, remote_spi, l_addr, r_addr, pkt);
	if (i2sa != NULL)
		goto dispatch;

	if (local_spi != 0) {
		/*
		 * If the local SPI is set, we should be able to find it
		 * in our hash.
		 *
		 * XXX: Should we respond with a notificaiton?
		 *
		 * RFC5996 2.21.4 we may send an INVALID_IKE_SPI
		 * notification if we wish.
		 *
		 * For now, discard.
		 */
		SPILOG(debug, log, "cannot find existing IKE SA with "
		    "matching local SPI value; discarding",
		    r_addr, l_addr, local_spi, remote_spi);

		ikev2_pkt_free(pkt);
		return;
	}

	if (remote_spi == 0) {
		/*
		 * XXX: this might require special processing.
		 * Discard for now.
		 */
		goto discard;
	}

	/*
	 * If the local SPI == 0, this can only be an IKE SA INIT
	 * exchange.  For all such exchanges, the msgid is always 0,
	 * regardless of the the number of actual messages sent during
	 * the exchange (RFC5996 2.2).
	 */
	if (pkt->pkt_header.exch_type != IKEV2_EXCH_IKE_SA_INIT ||
	    pkt->pkt_header.msgid != 0) {
		SPILOG(debug, log, "received non IKE_SA_INIT message with "
		    "0 local spi; discarding", r_addr, l_addr, local_spi,
		    remote_spi,
		    BUNYAN_T_UINT32, "exch_type",
		    (uint32_t)pkt->pkt_header.exch_type,
		    BUNYAN_T_UINT32, "msgid", pkt->pkt_header.msgid);
		goto discard;
	}

	/*
	 * If there isn't an existing IKEv2 SA, the only
	 * valid inbound packet is a request to start an
	 * IKE_EXCH_IKE_SA_INIT exchange.
	 */
	if (!(pkt->pkt_header.flags & IKEV2_FLAG_INITIATOR)) {
		SPILOG(debug, log, "cannot find existing SA", r_addr, l_addr,
		    local_spi, remote_spi);
		goto discard;
	}

	/* otherwise create a larval SA */
	i2sa = ikev2_sa_alloc(B_FALSE, pkt, l_addr, r_addr);
	if (i2sa == NULL) {
		SPILOG(warn, log, "could not create IKEv2 SA", r_addr,
		    l_addr, local_spi, remote_spi);
		goto discard;
	}
	local_spi = I2SA_LOCAL_SPI(i2sa);

dispatch:
	pkt->pkt_sa = i2sa;
	if (worker_dispatch(pkt, local_spi % nworkers))
		return;

	SPILOG(info, log, "worker queue full; discarding packet",
	    r_addr, l_addr, local_spi, remote_spi);

discard:
	if (i2sa != NULL)
		I2SA_REFRELE(i2sa);
	ikev2_pkt_free(pkt);
}

void
ikev2_retransmit(void *data)
{
	pkt_t *pkt = data;
	ikev2_sa_t *sa = pkt->pkt_sa;
	hrtime_t retry = 0;
	ssize_t len;

	PTH(pthread_mutex_lock(&sa->lock));

	/* XXX: what about condemned SAs */
	if (sa->outmsgid > pkt->pkt_header.msgid || sa->last_sent == NULL) {
		/* already acknowledged */
		PTH(pthread_mutex_unlock(&sa->lock));
		ikev2_pkt_free(pkt);
		return;
	}

	retry = cfg_retry_init * (1ULL << ++pkt->pkt_xmit);
	if (retry > cfg_retry_max || pkt->pkt_xmit > cfg_retry_max) {
		PTH(pthread_mutex_unlock(&sa->lock));
		ikev2_sa_condemn(sa);
		ikev2_pkt_free(pkt);
		return;
	}

}

static int
select_socket(const ikev2_sa_t *i2sa, const struct sockaddr_storage *local)
{
	if (local->ss_family == AF_INET6)
		return (ikesock6);
	if (i2sa != NULL && I2SA_IS_NAT(i2sa))
		return (nattsock);
	return (ikesock4);
}

