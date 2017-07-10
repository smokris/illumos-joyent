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
 * Copyright 2017 Joyent, Inc.
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <inttypes.h>
#include <stdio.h>
#include <err.h>
#include <errno.h>
#include <pthread.h>
#include <string.h>
#include <port.h>
#include <assert.h>
#include <locale.h>
#include <ipsec_util.h>
#include <note.h>
#include <err.h>
#include <sys/debug.h>
#include <bunyan.h>
#include "inbound.h"
#include "defs.h"
#include "ikev2_pkt.h"
#include "fromto.h"

static uchar_t *inbound_buf(void);
static pthread_key_t inbound_key = PTHREAD_ONCE_KEY_NP;

int ikesock4 = -1;
int ikesock6 = -1;
int nattsock = -1;

static void
inbound(int s, void *arg)
{
	_NOTE(ARGUNUSED(arg))

	uchar_t *buf = NULL;
	pkt_t *pkt = NULL;
	struct sockaddr_storage to = { 0 };
	struct sockaddr_storage from = { 0 };
	socklen_t tolen = sizeof (to);
	socklen_t fromlen = sizeof (from);
	buf_t data = { 0 };
	ssize_t pktlen;

	buf = inbound_buf();
	(void) memset(buf, 0, MAX_PACKET_SIZE);

	pktlen = recvfromto(s, buf, MAX_PACKET_SIZE, 0, &from, &fromlen, &to,
	    &tolen);
	schedule_socket(s, inbound);

	if (pktlen == -1) {
		/* recvfromto() should have dumped enough debug info */
		return;
	}

	/*
	 * recvfromto() guarantees we've received at least ike_header_t
	 * bytes (or it returns -1)
	 */

	/* sanity checks */
	ike_header_t *hdr = (ike_header_t *)buf;
	size_t hdrlen = ntohl(hdr->length);

	if (hdrlen != pktlen) {
		NETLOG(info, log, "ISAKMP header length doesn't match "
		    "received length; discarding", &from, &to,
		    BUNYAN_T_UINT32, "hdrlen", (uint32_t)hdrlen,
		    BUNYAN_T_UINT32, "pktlen", (uint32_t)pktlen);
		return;
	}

#if 0
	data.b_ptr = buf;
	data.b_len = (size_t)pktlen;
	pkt = ikev2_pkt_new_inbound(buf, pktlen);
	if (pkt == NULL)
		return;

	ikev2_dispatch(pkt, &to, &from);
#endif
}

static int
udp_listener_socket(sa_family_t af, uint16_t port)
{
	struct sockaddr_storage storage = { 0 };
	sockaddr_u_t sau = { .sau_ss = &storage };
	size_t socksize = 0;
	const char *afstring = NULL;
	int sock = -1;
	int yes = 1;
	ipsec_req_t ipsr = { 0 };

	ipsr.ipsr_ah_req = ipsr.ipsr_esp_req = IPSEC_PREF_NEVER;

	switch (af) {
	case AF_INET:
		afstring = "AF_INET";
		socksize = sizeof (struct sockaddr_in);
		break;
	case AF_INET6:
		afstring = "AF_INET6";
		socksize = sizeof (struct sockaddr_in6);
		break;
	default:
		INVALID("af");
	}

	if ((sock = socket(af, SOCK_DGRAM, 0)) == -1)
		err(EXIT_FAILURE, "%s: socket(%s)", __func__, afstring);

	sau.sau_ss->ss_family = af;
	/* Exploit that sin_port and sin6_port live at the same offset. */
	sau.sau_sin->sin_port = htons(port);
	if (bind(sock, (const struct sockaddr *)sau.sau_ss, socksize) == -1)
		err(EXIT_FAILURE, "%s: bind(%s, %d)", __func__, afstring, port);

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

static uchar_t *
inbound_buf(void)
{
	uchar_t *ptr = pthread_getspecific(inbound_key);

	if (ptr != NULL)
		return (ptr);

	if ((ptr = umem_alloc(MAX_PACKET_SIZE, UMEM_DEFAULT)) == NULL)
		err(EXIT_FAILURE, "%s", __func__);

	PTH(pthread_setspecific(inbound_key, ptr));
	return (ptr);
}

static void
inbound_free_buf(void *buf)
{
	umem_free(buf, MAX_PACKET_SIZE);
}

void
inbound_init(void)
{
	PTH(pthread_key_create_once_np(&inbound_key, inbound_free_buf));

	ikesock4 = udp_listener_socket(AF_INET, IPPORT_IKE);
	nattsock = udp_listener_socket(AF_INET, IPPORT_IKE_NATT);
	ikesock6 = udp_listener_socket(AF_INET6, IPPORT_IKE);

	schedule_socket(ikesock4, inbound);
	schedule_socket(nattsock, inbound);
	schedule_socket(ikesock6, inbound);
}
