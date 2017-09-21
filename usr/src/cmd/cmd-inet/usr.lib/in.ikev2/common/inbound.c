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
 * Copyright (c) 2017, Joyent, Inc.
 */

#include <arpa/inet.h>
#include <bunyan.h>
#include <inttypes.h>
#include <err.h>
#include <errno.h>
#include <ipsec_util.h>
#include <locale.h>
#include <netinet/in.h>
#include <netinet/udp.h>
#include <note.h>
#include <port.h>
#include <string.h>
#include <sys/debug.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <thread.h>
#include "inbound.h"
#include "defs.h"
#include "fromto.h"
#include "ikev1.h"
#include "ikev2.h"
#include "ikev2_pkt.h"
#include "ikev2_proto.h"

typedef struct inbound_s {
	thread_t	ib_tid;
	bunyan_logger_t	*ib_log;
	uint8_t		*ib_buf;
	size_t		ib_buflen;
} inbound_t;

int ikesock4 = -1;
int ikesock6 = -1;
int nattsock = -1;
size_t ninbound = 0;
int inbound_port = -1;

static rwlock_t ib_lock = DEFAULTRWLOCK;
static inbound_t *ibdata;
static size_t ibdata_alloc;
static __thread inbound_t *ib = NULL;

static void *
inbound_main(void *ibarg)
{
	port_event_t pe;
	int rc;

	ib = ibarg;

	(void) bunyan_trace(ib->ib_log, "Inbound main loop starting",
	    BUNYAN_T_END);

	while (1) {
		if (port_get(inbound_port, &pe, NULL) < 0) {
			STDERR(fatal, ib->ib_log, "port_get() failed");
			exit(EXIT_FAILURE);
		}

		(void) bunyan_debug(ib->ib_log, "Received port event",
		    BUNYAN_T_INT32, "event", pe.portev_events,
		    BUNYAN_T_STRING, "source",
		    port_source_str(pe.portev_source),
		    BUNYAN_T_POINTER, "object", pe.portev_object,
		    BUNYAN_T_POINTER, "cookie", pe.portev_user,
		    BUNYAN_T_END);

		VERIFY3S(pe.portev_source, ==, PORT_SOURCE_FD);

		void (*fn)(int) = (void (*)(int))pe.portev_user;
		int fd = (int)pe.portev_object;
		fn(fd);
	}

	return (NULL);
}

static void
inbound(int s)
{
	pkt_t *pkt = NULL;
	struct sockaddr_storage to = { 0 };
	struct sockaddr_storage from = { 0 };
	socklen_t tolen = sizeof (to);
	socklen_t fromlen = sizeof (from);
	ssize_t pktlen;

	(void) memset(ib->ib_buf, 0, ib->ib_buflen);
	pktlen = recvfromto(s, ib->ib_buf, ib->ib_buflen, 0, &from, &fromlen,
	    &to, &tolen);

	/*
	 * Once we've received the datagram, re-arm socket to other threads
	 * can receive datagrams from this socket.
	 */
	schedule_socket(s, inbound);

	/* recvfromto() should have dumped enough debug info */
	if (pktlen == -1)
		return;

	/* recvfromto() should discard truncated packets, if not, it's a bug */
	VERIFY3U(pktlen, >=, sizeof (ike_header_t));

	/* sanity checks */
	ike_header_t *hdr = (ike_header_t *)ib->ib_buf;
	size_t hdrlen = ntohl(hdr->length);

	VERIFY(bunyan_key_add(ib->ib_log,
	    ss_bunyan(&from), "src", ss_addr(&from),
	    BUNYAN_T_UINT32, "srcport", ss_port(&from),
	    ss_bunyan(&to), "dest", ss_addr(&to),
	    BUNYAN_T_UINT32, "destport", ss_port(&to),
	    BUNYAN_T_END) == 0);

	if (hdrlen != pktlen) {
		(void) bunyan_info(ib->ib_log,
		    "ISAKMP/IKE header length doesn't match received length",
		    BUNYAN_T_UINT32, "hdrlen", (uint32_t)hdrlen,
		    BUNYAN_T_UINT32, "pktlen", (uint32_t)pktlen,
		    BUNYAN_T_END);
		return;
	}

	switch (hdr->version) {
	case IKEV1_VERSION:
		/* XXX: Until we support V1 */
		bunyan_info(ib->ib_log, "Discarding ISAKMP/IKEV1 packet",
		    BUNYAN_T_END);
		return;
	case IKEV2_VERSION:
		pkt = ikev2_pkt_new_inbound(ib->ib_buf, pktlen, ib->ib_log);
		if (pkt == NULL)
			return;
		ikev2_dispatch(pkt, &from, &to);
		return;
	default:
		bunyan_info(ib->ib_log, "Unsupported ISAKMP/IKE version",
		    BUNYAN_T_UINT32, "version", hdr->version,
		    BUNYAN_T_END);
		return;
	}
}

void
schedule_socket(int fd, void (*cb)(int))
{
	if (port_associate(inbound_port, PORT_SOURCE_FD, fd, POLLIN, cb) < 0) {
		STDERR(error, log, "port_associate() failed",
		    BUNYAN_T_INT32, "fd", (int32_t)fd,
		    BUNYAN_T_END);

		/*
		 * If port_associate() fails, we'll stop receiving messages
		 * in the corresponding socket, so no use in trying to stay
		 * alive.
		 *
		 * XXX: abort() instead of exit()?
		 */
		exit(EXIT_FAILURE);
	}
}

static int
udp_listener_socket(sa_family_t af, uint16_t port)
{
	struct sockaddr_storage storage = { 0 };
	sockaddr_u_t sau = { .sau_ss = &storage };
	size_t socksize = 0;
	int sock = -1;
	int yes = 1;
	ipsec_req_t ipsr = { 0 };

	ipsr.ipsr_ah_req = ipsr.ipsr_esp_req = IPSEC_PREF_NEVER;

	switch (af) {
	case AF_INET:
		socksize = sizeof (struct sockaddr_in);
		break;
	case AF_INET6:
		socksize = sizeof (struct sockaddr_in6);
		break;
	default:
		INVALID("af");
	}

	if ((sock = socket(af, SOCK_DGRAM, 0)) == -1) {
		STDERR(fatal, log, "socket(af, SOCK_DGRAM) call failed",
		    BUNYAN_T_STRING, "af", afstr(af),
		    BUNYAN_T_END);
		exit(EXIT_FAILURE);
	}

	(void) bunyan_trace(log, "UDP socket created",
	    BUNYAN_T_INT32, "fd", (int32_t)sock,
	    BUNYAN_T_STRING, "af", afstr(af),
	    BUNYAN_T_UINT32, "port", (uint32_t)port,
	    BUNYAN_T_END);

	sau.sau_ss->ss_family = af;
	/* Exploit that sin_port and sin6_port live at the same offset. */
	sau.sau_sin->sin_port = htons(port);
	if (bind(sock, (const struct sockaddr *)sau.sau_ss, socksize) == -1) {
		STDERR(fatal, log, "bind(fd, addr) failed",
		    BUNYAN_T_INT32, "fd", (int32_t)sock,
		    ss_bunyan(sau.sau_ss), "addr", ss_addr(sau.sau_ss),
		    BUNYAN_T_UINT32, "port", ss_port(sau.sau_ss),
		    BUNYAN_T_END);
		exit(EXIT_FAILURE);
	}

	switch (af) {
	case AF_INET:
		/* Make sure we can receive the destination address */
		if (setsockopt(sock, IPPROTO_IP, IP_RECVDSTADDR,
		    (const void *)&yes, sizeof (yes)) == -1)
			err(EXIT_FAILURE, "%s: setsockopt(IP_RECVDSTADDR)",
			    __func__);

		if (setsockopt(sock, IPPROTO_IP, IP_SEC_OPT,
		    (const void *)&ipsr, sizeof (ipsr)) == -1)
			err(EXIT_FAILURE, "%s: setsockopt(IP_SEC_OPT)",
			    __func__);
		break;
	case AF_INET6:
		if (setsockopt(sock, IPPROTO_IPV6, IPV6_RECVPKTINFO,
		    (const void *)&yes, sizeof (yes)) == -1)
			err(EXIT_FAILURE, "%s: setsockopt(IPV6_RECVPKTINFO)",
			    __func__);

		if (setsockopt(sock, IPPROTO_IPV6, IPV6_SEC_OPT,
		    (const void *)&ipsr, sizeof (ipsr)) == -1)
			err(EXIT_FAILURE, "%s: setsockopt(IPV6_SEC_OPT)",
			    __func__);
		break;
	default:
		INVALID(af);
	}

	/* Setup IPv4 NAT Traversal */
	if (af == AF_INET && port == IPPORT_IKE_NATT) {
		int nat_t = 1;

		if (setsockopt(sock, IPPROTO_UDP, UDP_NAT_T_ENDPOINT,
		    &nat_t, sizeof (nat_t)) == -1)
			err(EXIT_FAILURE, "%s: setsockopt(IPPROTO_UDP, "
			    "UDP_NAT_T_ENDPOINT", __func__);
	}

	return (sock);
}

void
inbound_init(size_t n)
{
	/* main() should initialize inbound_port */
	VERIFY3S(inbound_port, >=, 0);

	ikesock4 = udp_listener_socket(AF_INET, IPPORT_IKE);
	nattsock = udp_listener_socket(AF_INET, IPPORT_IKE_NATT);
	ikesock6 = udp_listener_socket(AF_INET6, IPPORT_IKE);

	size_t amt = n * sizeof (inbound_t);
	VERIFY3U(amt, >, sizeof (inbound_t));
	VERIFY3U(amt, >=, n);

	ibdata = umem_zalloc(amt, UMEM_DEFAULT);
	if (ibdata == NULL)
		NOMEM;

	for (size_t i = 0; i < n; i++) {
		ibdata[i].ib_buf = umem_alloc(MAX_PACKET_SIZE, UMEM_DEFAULT);
		if (ibdata[i].ib_buf == NULL)
			NOMEM;
		ibdata[i].ib_buflen = MAX_PACKET_SIZE;

		if (bunyan_child(log, &ibdata[i].ib_log, BUNYAN_T_END) != 0)
			NOMEM;

		int rc = thr_create(NULL, 0, inbound_main, &ibdata[i], 0,
		    &ibdata[i].ib_tid);

		if (rc != 0) {
			bunyan_fatal(log, "Cannot create inbound thread",
			    BUNYAN_T_STRING, "errmsg", strerror(rc),
			    BUNYAN_T_INT32, "errno", rc,
			    BUNYAN_T_STRING, "file", __FILE__,
			    BUNYAN_T_INT32, "line", __LINE__,
			    BUNYAN_T_STRING, "func", __func__,
			    BUNYAN_T_END);
			exit(EXIT_FAILURE);
		}
	}

	ninbound = n;

	schedule_socket(ikesock4, inbound);
	schedule_socket(nattsock, inbound);
	schedule_socket(ikesock6, inbound);
}
