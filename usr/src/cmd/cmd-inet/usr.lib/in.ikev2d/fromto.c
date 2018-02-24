/*
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2017, Joyent, Inc.
 */

/* Portions of the following are... */
/*
 * Copyright (C) 1995, 1996, 1997, and 1998 WIDE Project.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the project nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE PROJECT AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE PROJECT OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*
 * These functions provide an easy way to receive a packet with FULL address
 * information, and send one using precise addresses.
 */
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/int_fmtio.h>
#include <sys/debug.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include "defs.h"
#include "fromto.h"
#include "ike.h"

/*
 * Receive packet, with src/dst information.  It is assumed that necessary
 * setsockopt()s (e.g. IP_SEC_OPT(NEVER)) have already performed on socket.
 */
ssize_t
recvfromto(int s, void *restrict buf, size_t buflen, int flags,
    struct sockaddr_storage *restrict from, socklen_t *restrict fromlen,
    struct sockaddr_storage *restrict to, socklen_t *restrict tolen)
{
	socklen_t otolen;
	ssize_t len;
	socklen_t sslen;
	struct sockaddr_storage ss;
	struct msghdr m;
	struct iovec iov[1] = { 0 };
	uint32_t cmsgbuf[64] = { 0 };
	struct cmsghdr *cm = (struct cmsghdr *)cmsgbuf;
	struct in6_pktinfo *pi;
	struct sockaddr_in6 *sin6;
	struct sockaddr_in *sin;
	boolean_t toset = _B_FALSE;

	sslen = sizeof (ss);
	if (getsockname(s, (struct sockaddr *)&ss, &sslen) < 0) {
		STDERR(error, "getsockname() failed",
		    BUNYAN_T_INT32, "socket", (int32_t)s);
		return (-1);
	}

	/* Quick hack -- snapshot the current socket's port, at least. */
	(void) memcpy(to, &ss, sslen < *tolen ? sslen : *tolen);

	m.msg_name = (caddr_t)from;
	m.msg_namelen = *fromlen;
	iov[0].iov_base = (caddr_t)buf;
	iov[0].iov_len = buflen;
	m.msg_iov = iov;
	m.msg_iovlen = 1;
	m.msg_control = (caddr_t)cm;
	m.msg_controllen = sizeof (cmsgbuf);
	if ((len = recvmsg(s, &m, flags)) < 0) {
		STDERR(error, "recvmsg() failed",
		    BUNYAN_T_INT32, "socket", (int32_t)s,
		    BUNYAN_T_END);
		return (-1);
	}
	key_add_addr(LOG_KEY_RADDR, SSTOSA(from));

	if (m.msg_flags & MSG_TRUNC) {
		/*
		 * size_t and ssize_t should always be "long", but not in 32-
		 * bit apps for some bizarre reason.
		 */
		(void) bunyan_warn(log, "Received oversized message",
		    BUNYAN_T_INT32, "socket", (int32_t)s,
		    BUNYAN_T_UINT32, "msglen", (uint32_t)len,
		    BUNYAN_T_UINT32, "maxlen", (uint32_t)buflen,
		    BUNYAN_T_END);

		errno = E2BIG;	/* Not returned from normal recvmsg()... */
		return (-1);
	}

	if (len < sizeof (ike_header_t)) {
		(void) bunyan_warn(log, "Received undersized message",
		    BUNYAN_T_INT32, "socket", (int32_t)s,
		    BUNYAN_T_UINT32, "msglen", (uint32_t)len,
		    BUNYAN_T_END);
		return (-1);
	}

	*fromlen = m.msg_namelen;

	otolen = *tolen;
	*tolen = 0;
	for (cm = (struct cmsghdr *)CMSG_FIRSTHDR(&m);
	    m.msg_controllen != 0 && cm;
	    cm = (struct cmsghdr *)CMSG_NXTHDR(&m, cm)) {
		if (!toset && ss.ss_family == AF_INET6 &&
		    cm->cmsg_level == IPPROTO_IPV6 &&
		    cm->cmsg_type == IPV6_PKTINFO &&
		    otolen >= sizeof (*sin6)) {
			/* LINTED */
			pi = (struct in6_pktinfo *)(CMSG_DATA(cm));
			*tolen = sizeof (*sin6);
			sin6 = (struct sockaddr_in6 *)to;
			(void) memset(sin6, 0, sizeof (*sin6));
			sin6->sin6_family = AF_INET6;
			sin6->sin6_addr = pi->ipi6_addr;
			/* XXX other cases, such as site-local? */
			if (IN6_IS_ADDR_LINKLOCAL(&sin6->sin6_addr))
				sin6->sin6_scope_id = pi->ipi6_ifindex;
			else
				sin6->sin6_scope_id = 0;
			sin6->sin6_port =
			    ((struct sockaddr_in6 *)&ss)->sin6_port;
			toset = _B_TRUE;
			continue;
		}

		if (!toset &&
		    ss.ss_family == AF_INET && cm->cmsg_level == IPPROTO_IP &&
		    cm->cmsg_type == IP_RECVDSTADDR &&
		    otolen >= sizeof (struct sockaddr_in)) {
			*tolen = sizeof (*sin);
			sin = (struct sockaddr_in *)to;
			(void) memset(sin, 0, sizeof (*sin));
			sin->sin_family = AF_INET;
			(void) memcpy(&sin->sin_addr, CMSG_DATA(cm),
			    sizeof (sin->sin_addr));
			sin->sin_port = ((struct sockaddr_in *)&ss)->sin_port;
			toset = _B_TRUE;
			continue;
		}
	}
	key_add_addr(LOG_KEY_LADDR, SSTOSA(to));

	(void) bunyan_debug(log, "Received datagram",
	    BUNYAN_T_INT32, "socket", (int32_t)s,
	    BUNYAN_T_UINT32, "msglen", (uint32_t)len,
	    BUNYAN_T_END);

	return (len);
}

/*
 * Send packet, with fixing src/dst address pair. It should be noted
 * that the source port value used is the one that was set on the
 * socket being used (i.e. the port value in 'src' is ignored), while
 * the port value in 'dest' IS used to determine the destination port of
 * the datagram.
 */
ssize_t
sendfromto(int s, const uint8_t *restrict buf, size_t buflen,
    const struct sockaddr *restrict src,
    const struct sockaddr *restrict dst)
{
	uint32_t cmsgbuf[64] = { 0 };
	struct msghdr m = { 0 };
	struct iovec iov[1];
	struct cmsghdr *cm = (struct cmsghdr *)&cmsgbuf;
	struct in6_pktinfo *pi6;
	struct in_pktinfo *pi;
	ssize_t n;

	if (src->sa_family != AF_INET && src->sa_family != AF_INET6) {
		(void) bunyan_error(log, "Unsupported address family",
		    BUNYAN_T_STRING, LOG_KEY_FUNC, __func__,
		    BUNYAN_T_STRING, LOG_KEY_FILE, __FILE__,
		    BUNYAN_T_INT32, LOG_KEY_LINE, __LINE__,
		    BUNYAN_T_UINT32, "af", (uint32_t)src->sa_family,
		    BUNYAN_T_END);
		errno = EAFNOSUPPORT;
		return (-1);
	}

	if (src->sa_family != dst->sa_family) {
		(void) bunyan_error(log, "Address family mismatch",
		    BUNYAN_T_INT32, "socket", (int32_t)s,
		    BUNYAN_T_UINT32, "srcaf", (uint32_t)src->sa_family,
		    BUNYAN_T_UINT32, "destaf", (uint32_t)src->sa_family,
		    BUNYAN_T_END);

		errno = EADDRNOTAVAIL;	/* XXX KEBE ASKS - Better ideas? */
		return (-1);
	}

	key_add_addr(LOG_KEY_RADDR, dst);
	key_add_addr(LOG_KEY_LADDR, src);

	(void) bunyan_debug(log, "Sending datagram",
	    BUNYAN_T_INT32, "socket", (int32_t)s,
	    BUNYAN_T_UINT32, "msglen", (uint32_t)buflen,
	    BUNYAN_T_END);

	m.msg_name = (caddr_t)dst;
	iov[0].iov_base = (caddr_t)buf;
	iov[0].iov_len = buflen;
	m.msg_iov = iov;
	m.msg_iovlen = 1;
	m.msg_control = (caddr_t)cm;
	if (src->sa_family == AF_INET6) {
		/* v6 setup */
		struct sockaddr_in6 *src6;

		/* LINTED E_BAD_PTR_CAST_ALIGN */
		src6 = (struct sockaddr_in6 *)src;
		m.msg_namelen = sizeof (*src6);
		m.msg_controllen = CMSG_SPACE(sizeof (*pi6));
		cm->cmsg_len = CMSG_LEN(sizeof (*pi6));
		cm->cmsg_level = IPPROTO_IPV6;
		cm->cmsg_type = IPV6_PKTINFO;
		/* LINTED E_BAD_PTR_CAST_ALIGN */
		pi6 = (struct in6_pktinfo *)CMSG_DATA(cm);
		pi6->ipi6_addr = src6->sin6_addr;
		if (IN6_IS_ADDR_LINKLOCAL(&src6->sin6_addr)) {
			pi6->ipi6_ifindex = src6->sin6_scope_id;
		} else {
			pi6->ipi6_ifindex = 0;
		}
	} else if (src->sa_family == AF_INET) {
		/* v4 setup */
		struct sockaddr_in *src4;

		/* LINTED E_BAD_PTR_CAST_ALIGN */
		src4 = (struct sockaddr_in *)src;
		m.msg_namelen = sizeof (*src4);
		m.msg_controllen = CMSG_SPACE(sizeof (*pi));
		cm->cmsg_len = CMSG_LEN(sizeof (*pi));
		cm->cmsg_level = IPPROTO_IP;
		cm->cmsg_type = IP_PKTINFO;
		/* LINTED E_BAD_PTR_CAST_ALIGN */
		pi = (struct in_pktinfo *)CMSG_DATA(cm);
		pi->ipi_addr = src4->sin_addr;
		/* Zero out the other fields for IPv4. */
		pi->ipi_spec_dst.s_addr = 0;
		pi->ipi_ifindex = 0;
	} else {
		/*NOTREACHED*/
		INVALID(src->ss_family);
	}

	n = sendmsg(s, &m, 0);
	if (n < 0) {
		STDERR(error, "sendmsg() failed",
		    BUNYAN_T_INT32, "socket", (int32_t)s,
		    BUNYAN_T_END);
	} else {
		(void) bunyan_trace(log, "Sent datagram",
		    BUNYAN_T_INT32, "socket", (int32_t)s,
		    BUNYAN_T_INT32, "len", (int32_t)n,
		    BUNYAN_T_END);
	}

	return (n);
}
