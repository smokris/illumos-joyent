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
#include <inet/ip.h>
#include <inet/ip6.h>

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

/*
 * Free a remote VXLAN destination.
 */
static void
vxlnat_remote_free(vxlnat_remote_t *remote)
{
	ASSERT0(remote->vxnrem_refcount);

	kmem_free(remote, sizeof (*remote));
}

/*
 * Like other unlink functions, assume the appropriate lock is held.
 */
void
vxlnat_remote_unlink(vxlnat_remote_t *remote)
{
	vxlnat_vnet_t *vnet = remote->vxnrem_vnet;

	ASSERT3P(vnet, !=, NULL);
	ASSERT(MUTEX_HELD(&vnet->vxnv_remote_lock));

	/* First unlink so nobody else can find me */
	avl_remove(&vnet->vxnv_remotes, remote);

	/*
	 * We still hold a vnet reference, so races shouldn't be a problem.
	 * Still, for added safety, NULL it out first.
	 */
	remote->vxnrem_vnet = NULL;  /* Condemn this entry. */
	VXNV_REFRELE(vnet);
	VXNREM_REFRELE(remote);	/* Internment release. */
}

/*
 * Find or create a remote VXLAN destination.
 */
static vxlnat_remote_t *
vxlnat_get_remote(vxlnat_vnet_t *vnet, in6_addr_t *remote_addr,
    boolean_t create_on_miss)
{
	vxlnat_remote_t *remote, searcher;
	avl_index_t where;

	searcher.vxnrem_addr = *remote_addr;
	mutex_enter(&vnet->vxnv_remote_lock);
	remote = avl_find(&vnet->vxnv_remotes, &searcher, &where);
	if (remote == NULL && create_on_miss) {
		/* Not as critical if we can't allocate here. */
		remote = kmem_zalloc(sizeof (*remote),
		    KM_NOSLEEP | KM_NORMALPRI);
		if (remote != NULL) {
			remote->vxnrem_addr = *remote_addr;
			remote->vxnrem_refcount = 1; /* Internment reference. */
			VXNV_REFHOLD(vnet);
			remote->vxnrem_vnet = vnet;
			/* Rest is filled in by caller. */
			avl_insert(&vnet->vxnv_remotes, remote, where);
		}
	}
	if (remote != NULL)
		VXNREM_REFHOLD(remote);
	mutex_exit(&vnet->vxnv_remote_lock);
	return (remote);
}

/*
 * Cache inbound packet information in the vnet's remotes section.
 *
 * NOTE: This function assumes a trustworthy underlay network.  If the
 * underlay isn't trustworthy, this function should be renamed, and reduced to
 * a "strip and reality-check the ethernet header" function.
 *
 * Caller has stripped any pre-ethernet data from mp.  We return mp
 * stripped down to its IP header.
 */
static mblk_t *
vxlnat_cache_remote(mblk_t *mp, struct sockaddr_in *underlay_src,
    vxlnat_vnet_t *vnet)
{
	struct ether_vlan_header *evh;
	struct ether_header *eh;
	vxlnat_remote_t *remote;
	uint16_t vlan, ethertype;
	ether_addr_t remote_ether;
	ipha_t *ipha;
	ip6_t *ip6h;
	in6_addr_t remote_addr;

	/* Assume (for now) we have at least a VLAN header's worth of data. */
	if (MBLKL(mp) < sizeof (*evh)) {
		/* XXX KEBE ASKS - should we be more forgiving? */
		DTRACE_PROBE1(vxlnat__in__drop__etherhdr, mblk_t *, mp);
		freemsg(mp);
		return (NULL);
	}

	eh = (struct ether_header *)mp->b_rptr;
	ethertype = ntohs(eh->ether_type);
	ether_copy(&eh->ether_shost, &remote_ether);
	if (ethertype == ETHERTYPE_VLAN) {
		evh = (struct ether_vlan_header *)eh;
		/* Keep it in network order... */
		vlan = evh->ether_tci;
		ethertype = ntohs(evh->ether_type);
		ASSERT(vlan != 0);
		mp->b_rptr += sizeof (*evh);
	} else {
		evh = NULL;
		vlan = 0;
		mp->b_rptr += sizeof (*eh);
	}
	/* Handle case of split ether + IP headers. */
	if (MBLKL(mp) < sizeof (ipha_t)) {
		mblk_t *freemp;
		
		if (MBLKL(mp) > 0 || mp->b_cont == NULL) {
			/* The IP header is split ACROSS MBLKS! Bail for now. */
			DTRACE_PROBE1(vxlnat__in__drop__splitip, mblk_t *, mp);
			freemsg(mp);
			return (NULL);
		}
		freemp = mp;
		mp = mp->b_cont;
		freeb(freemp);
	}
	/* LINTED -- alignment... */
	ipha = (ipha_t *)mp->b_rptr;

	if (IPH_HDR_VERSION(ipha) == IPV4_VERSION) {
		if (ethertype != ETHERTYPE_IP) {
			/* XXX KEBE ASKS - should we be more forgiving? */
			DTRACE_PROBE1(vxlnat__in__drop__etherhdr4,
			    mblk_t *, mp);
			freemsg(mp);
			return (NULL);
		}
		IN6_INADDR_TO_V4MAPPED((struct in_addr *)(&ipha->ipha_src),
		    &remote_addr);
	} else {
		if (ethertype != ETHERTYPE_IPV6 ||
		    IPH_HDR_VERSION(ipha) != IPV6_VERSION ||
		    MBLKL(mp) < sizeof (ip6_t)) {	
			/* XXX KEBE ASKS - should we be more forgiving? */
			DTRACE_PROBE1(vxlnat__in__drop__etherhdr6,
			    mblk_t *, mp);
			freemsg(mp);
			return (NULL);
		}
		ip6h = (ip6_t *)ipha;
		remote_addr = ip6h->ip6_src;
	}

	/* XXX KEBE SAYS FIND remote and replace OR create new remote. */
	remote = vxlnat_get_remote(vnet, &remote_addr, B_TRUE);
	if (remote != NULL) {
		/*
		 * See if this entry needs fixing or filling-in.  This might
		 * get a bit racy with read-only threads that actually
		 * transmit, but it only means dropped-packets in the worst
		 * case.
		 *
		 * It's THIS PART that inspires the warning about trusting the
		 * underlay network.
		 *
		 * XXX KEBE ASKS -- should we just replace things w/o checking?
		 */
		/* Replace the ethernet address? */
		if (ether_cmp(&remote->vxnrem_ether, &remote_ether) != 0)
			ether_copy(&remote_ether, &remote->vxnrem_ether);
		/*
		 * Replace the underlay? NOTE: Fix if/when underlay becomes
		 * IPv6.
		 */
		IN6_INADDR_TO_V4MAPPED(&underlay_src->sin_addr, &remote_addr);
		if (!IN6_ARE_ADDR_EQUAL(&remote->vxnrem_uaddr, &remote_addr))
			remote->vxnrem_uaddr = remote_addr;
		/* Replace the vlan ID. Maintain network order... */
		if (remote->vxnrem_vlan != vlan)
			remote->vxnrem_vlan = vlan;
	}
	/*
	 * Else just continue and pray for better luck on another packet or
	 * on the return flight.  It is IP, we can Just Drop It (TM)...
	 */

	/* We're done with the remote entry now. */
	VXNREM_REFRELE(remote);

	/* Advance rptr to the inner IP header and proceed. */
	mp->b_rptr = (uint8_t *)ipha;
	return (mp);
}

/*
 * Process exactly one VXLAN packet.
 */
static void
vxlnat_one_vxlan(mblk_t *mp, struct sockaddr_in *underlay_src)
{
	vxlan_hdr_t *vxh;
	vxlnat_vnet_t *vnet;
	ipha_t *ipha;
	ip6_t *ip6h;
	vxlnat_fixed_t *fixed, fsearch;

	if (MBLKL(mp) < sizeof (*vxh)) {
		/* XXX KEBE ASKS -- should we be more forgiving? */
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

	/* 1.) Locate the ethernet header and check/update/add-into remotes. */
	mp->b_rptr += sizeof (*vxh);
	while (MBLKL(mp) == 0) {
		mblk_t *oldmp = mp;

		mp = mp->b_cont;
		freeb(oldmp);
	}
	mp = vxlnat_cache_remote(mp, underlay_src, vnet);
	if (mp == NULL) {
		VXNV_REFRELE(vnet);
		return;
	}

	/* 2.) Search 1-1s, process if hit. */
	ipha = (ipha_t *)mp->b_rptr;
	if (IPH_HDR_VERSION(ipha) == IPV4_VERSION) {
		ip6h = NULL;
		IN6_INADDR_TO_V4MAPPED((struct in_addr *)(&ipha->ipha_src),
		    &fsearch.vxnf_addr);
	} else {
		/* vxlnat_cache_remote() did reality checks... */
		ASSERT(IPH_HDR_VERSION(ipha) == IPV6_VERSION);
		ip6h = (ip6_t *)ipha;
		ipha = NULL;
		fsearch.vxnf_addr = ip6h->ip6_src;
	}
	rw_enter(&vnet->vxnv_fixed_lock, RW_READER);
	fixed = avl_find(&vnet->vxnv_fixed_ips, &fsearch, NULL);
	rw_exit(&vnet->vxnv_fixed_lock);
	if (fixed != NULL) {
		/* XXX KEBE SAYS -- FILL ME IN... but for now: */
		freemsg(mp);

		/* All done... */
		VXNF_REFRELE(fixed);
		VXNV_REFRELE(vnet);
		return;
	}

	/* XXX KEBE SAYS BUILD STEPS 3-4. */

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
