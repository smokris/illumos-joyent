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
 * Copyright 2018 Joyent, Inc.
 */

/*
 * NAT engine.  Mappings, 1-1 The rules in vxlnat_rules.c are only consulted
 * if the 1-1 map (kept here) misses or if the outbound lookup (vnetid,
 * protocol, src-IP, dst-IP, src-port, dst-port) misses.
 *
 * The plan is for inbound to hit conn_ts, whose conn_private points to
 * entries here.  The conn_recv* functions live here too (for now).
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ksynch.h>
#include <sys/ksocket.h>
#include <sys/kmem.h>
#include <sys/stream.h>
#include <sys/strsubr.h>
#include <sys/strsun.h>
#include <sys/sysmacros.h>
#include <sys/debug.h>
#include <sys/dtrace.h>
#include <sys/errno.h>
#include <sys/tihdr.h>
#include <netinet/in.h>
#include <netinet/udp.h>

#include <inet/vxlnat_impl.h>

static boolean_t vxlnat_vxlan_input(ksocket_t, mblk_t *, size_t, int, void *);

/*
 * Initialized to NULL, read/write protected by vxlnat_mutex.
 * Receive functions shouldn't have to access this directly.
 */
ksocket_t vxlnat_underlay;

void
vxlnat_closesock(void)
{
	ASSERT(MUTEX_HELD(&vxlnat_mutex));
	if (vxlnat_underlay != NULL) {
		(void) ksocket_close(vxlnat_underlay, zone_kcred());
		vxlnat_underlay = NULL;
	}
}

static int
vxlnat_opensock(in6_addr_t *underlay_ip)
{
	int rc, val;
	/* Assume rest is initialized to 0s. */
	struct sockaddr_in6 sin6 = {AF_INET6, BE_16(IPPORT_VXLAN)};

	ASSERT(MUTEX_HELD(&vxlnat_mutex));
	/* Open... */
	rc = ksocket_socket(&vxlnat_underlay, AF_INET6, SOCK_DGRAM, 0,
	    KSOCKET_SLEEP, zone_kcred());
	if (rc != 0)
		return (rc);

	/* Bind... */
	sin6.sin6_addr = *underlay_ip;
	rc = ksocket_bind(vxlnat_underlay, (struct sockaddr *)(&sin6),
	    sizeof (sin6), zone_kcred());
	if (rc != 0) {
		vxlnat_closesock();
		return (rc);
	}

	/* Use source-port hashing when sending packets out VXLAN... */
	val = UDP_HASH_VXLAN;
	rc = ksocket_setsockopt(vxlnat_underlay, IPPROTO_UDP,
	    UDP_SRCPORT_HASH, &val, sizeof (val), kcred);
	if (rc != 0) {
		vxlnat_closesock();
		return (rc);
	}

	/* Once we return from this, start eating data. */
	rc = ksocket_krecv_set(vxlnat_underlay, vxlnat_vxlan_input, NULL);
	if (rc != 0) {
		vxlnat_closesock();
	}

	return (rc);
}

/*
 * Establish a VXLAN-listening kernel socket.
 * XXX KEBE ASKS ==> Support more than one VXLAN address?
 */
/* ARGSUSED */
int
vxlnat_vxlan_addr(in6_addr_t *underlay_ip)
{
	int rc;

	ASSERT(MUTEX_HELD(&vxlnat_mutex));
	/* For now, we make this a one-underlay-address-only solution. */
	vxlnat_closesock();
	rc = vxlnat_opensock(underlay_ip);
	return (rc);
}

static void
vxlnat_one_vxlan(mblk_t *mp, struct sockaddr_in *underlay_src)
{
	vxlan_hdr_t *vxh;
	vxlnat_vnet_t *vnet;

	if (MBLKL(mp) < sizeof (*vxh)) {
		DTRACE_PROBE1(vxlnat__in__drop__vxlsize, mblk_t *, mp);
		freemsg(mp);
		return;
	}
	vxh = (vxlan_hdr_t *)mp->b_rptr;

	/* If we start using more than just the one flag, fix it. */
	if (vxh->vxlan_flags != VXLAN_F_VDI_WIRE) {
		DTRACE_PROBE1(vxlnat__in__drop__VDI, mblk_t *, mp);
		freemsg(mp);
		return;
	}

	/* Remember, we key off of what's on the wire. */
	vnet = vxlnat_get_vnet(VXLAN_ID_WIRE32(vxh->vxlan_id), B_FALSE);
	if (vnet == NULL) {
		DTRACE_PROBE1(vxlnat__in__drop__vnetid, uint32_t,
		    VXLAN_ID_HTON(VXLAN_ID_WIRE32(vxh->vxlan_id)));
		freemsg(mp);
		return;
	}

	DTRACE_PROBE2(vxlnat__in__vnet, uint32_t,
	    VXLAN_ID_HTON(VXLAN_ID_WIRE32(vxh->vxlan_id)),
	    vxlnat_vnet_t, vnet);

	/*
	 * Off-vxlan processing steps:
	 * 1.) Locate the ethernet header and check/update/add-into remotes.
	 * 2.) Search 1-1s, process if hit.
	 * 3.) Search flows, process if hit.
	 * 4.) Search rules, create new flow (or not) if hit.
	 * 5.) Drop the packets.
	 */

	/* XXX KEBE SAYS BUILD STEPS 1-4. */

	/* 5.) Nothing, drop the packet. */
	/* XXX KEBE ASKS DIAGNOSTIC? */
	VXNV_REFRELE(vnet);
	freemsg(mp);
}
/*
 * ONLY return B_FALSE if we get a packet-clogging event.
 */
/* ARGSUSED */
static boolean_t
vxlnat_vxlan_input(ksocket_t insock, mblk_t *chain, size_t msgsize, int oob,
    void *ignored)
{
	mblk_t *mp, *nextmp;

	/*
	 * XXX KEBE ASKS --> move hold & release outside of loop?
	 * If so, hold rwlock here.
	 */

	for (mp = chain; mp != NULL; mp = nextmp) {
		struct T_unitdata_ind *tudi;
		struct sockaddr_in *sin;

		nextmp = mp->b_next;
		if (DB_TYPE(mp) != M_PROTO || mp->b_cont == NULL) {
			DTRACE_PROBE1(vxlnat__in__drop__mblk, mblk_t *, mp);
			freemsg(mp);
			continue;
		}

		/* LINTED -- aligned */
		tudi = (struct T_unitdata_ind *)mp->b_rptr;
		if (tudi->PRIM_type != T_UNITDATA_IND) {
			DTRACE_PROBE1(vxlnat__in__drop__TPI, mblk_t *, mp);
			freemsg(mp);
			continue;
		}
		/* LINTED -- aligned */
		sin = (struct sockaddr_in *)(mp->b_rptr + tudi->SRC_offset);
		VERIFY(sin->sin_family == AF_INET);
		VERIFY(tudi->SRC_length >= sizeof (*sin));

		vxlnat_one_vxlan(mp->b_cont, sin);
		freeb(mp);
	}

	return (B_TRUE);
}
