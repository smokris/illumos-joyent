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
#include <sys/ddi.h>
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
#include <inet/arp.h>
#include <inet/ip.h>
#include <inet/ip6.h>
#include <inet/tcp_impl.h>
#include <inet/udp_impl.h>
#include <inet/tcp.h>

#include <inet/vxlnat_impl.h>

/*
 * Initialized to NULL, read/write protected by vxlnat_mutex.
 * Receive functions shouldn't have to access this directly.
 */
ksocket_t vxlnat_underlay;
ire_t *vxlnat_underlay_ire;

void
vxlnat_closesock(void)
{
	ASSERT(MUTEX_HELD(&vxlnat_mutex));
	if (vxlnat_underlay_ire != NULL) {
		ire_refrele(vxlnat_underlay_ire);
		vxlnat_underlay_ire = NULL;
	}
	if (vxlnat_underlay != NULL) {
		/*
		 * NOTE: The caller should've also called
		 * vxlnat_quiesce_traffic() before calling here.
		 */
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
	ip_stack_t *ipst = vxlnat_netstack->netstack_ip;

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

	/*
	 * Grab the IRE for underlay address.
	 */
	ASSERT3P(vxlnat_underlay_ire, ==, NULL);
	vxlnat_underlay_ire = (IN6_IS_ADDR_V4MAPPED(underlay_ip)) ?
	    ire_ftable_lookup_simple_v4(underlay_ip->_S6_un._S6_u32[3],
	    0, ipst, NULL) :
	    ire_ftable_lookup_simple_v6(underlay_ip, 0, ipst, NULL);
	if (vxlnat_underlay_ire == NULL) {
		DTRACE_PROBE1(vxlnat__opensock__ire__fail, in6_addr_t *,
		    underlay_ip);
		vxlnat_closesock();
		return (EADDRNOTAVAIL);
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
	vxlnat_quiesce_traffic();
	vxlnat_closesock();
	rc = vxlnat_opensock(underlay_ip);
	vxlnat_enable_traffic();
	return (rc);
}

/*
 * Free a remote VXLAN destination.
 */
void
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
 * Actually transmit an mblk to a VXLAN underlay destination.
 */
static void
vxlnat_sendmblk(mblk_t **send_mp, struct sockaddr_in6 *underlay_dst)
{
	struct msghdr msghdr = {NULL};
	cred_t *cred;
	int rc;

	msghdr.msg_name = (struct sockaddr_storage *)underlay_dst;
	msghdr.msg_namelen = sizeof (*underlay_dst);

	/*
	 * cred_t dance is because we may be getting this straight from
	 * interrupt context.
	 */
	cred = zone_get_kcred(netstack_get_zoneid(vxlnat_netstack));
	if (cred == NULL) {
		DTRACE_PROBE1(vxlnat__sendmblk__credfail, 
		    struct sockaddr_in6 *, underlay_dst);
		freemsg(*send_mp);
		return;
	}

	if (vxlnat_underlay != NULL) {
		/*
		 * Use MSG_DONTWAIT to avoid blocks, esp. if we're getting
		 * this straight from interrupt context.
		 */
		rc = ksocket_sendmblk(vxlnat_underlay, &msghdr, MSG_DONTWAIT,
		    send_mp, cred);
		crfree(cred);
		if (rc != 0) {
			DTRACE_PROBE2(vxlnat__sendmblk__sendfail, int, rc,
			    struct sockaddr_in6 *, underlay_dst);
			freemsg(*send_mp);
		}
		/* else ksocket_sendmblk() consumed the message. */
	} else {
		DTRACE_PROBE1(vxlnat__sendmblk__nosocket,
		    struct sockaddr_in6 *, underlay_dst);
		freemsg(*send_mp);
	}
}

/*
 * Parse an ARP request.  We want to handle unicast ARP requests so peers that
 * use them for liveness detection think we're alive.  In Triton/SDC, this
 * response is unicast.  Consult the available NAT-rule prefixes to see what
 * we can answer.
 *
 * NOTE:  We receive the packet prior to advancing the ethernet header.
 *
 * There will be an IPv6-equivalent dealing with ND_{ROUTER,NEIGHBOR}_SOLICIT.
 */
static void
vxlnat_handle_arp(mblk_t *mp, struct ether_header *eh,
    struct ether_vlan_header *evh, struct sockaddr_in6 *underlay_src,
    vxlnat_vnet_t *vnet)
{
	arh_t *arh; /* = (arh_t *)mp->b_rptr; */
	ether_addr_t *macdst = (ether_addr_t *)&eh->ether_dhost;
	ether_addr_t *macsrc = (ether_addr_t *)&eh->ether_shost;
	ether_addr_t *arpsendmac, *arptargmac;
	vxlnat_rule_t *rule;
	ipaddr_t ruleip, arpsendip, arptargip;
	uint8_t *arpap; /* = (uint8_t *)(arh + 1); */
	mblk_t *nextmp;
	size_t ether_headerlen;

	ASSERT((void *)eh == (void *)evh || evh == NULL);
	ASSERT3P((uint8_t *)eh, ==, mp->b_rptr);

	ether_headerlen = (evh != NULL) ? sizeof (*evh) : sizeof (*eh);

	/*
	 * Reality checks. Drop if any fail.
	 *
	 * 0.) Must be big enough to hold a proper ARP request.
	 */
	if (mp->b_cont != NULL) {
		nextmp = mp->b_cont;
		DTRACE_PROBE1(vxlnat__arp__bcont, mblk_t *, mp);
		if (nextmp->b_cont != NULL) {
			/* WOW! What a corner-case. pullup here. */
			DTRACE_PROBE1(vxlnat__arp__bcont2, mblk_t *, nextmp);
			nextmp = msgpullup(nextmp, -1);
			if (nextmp == NULL)
				goto done;	/* Bail! */
			freemsg(mp->b_cont);
			mp->b_cont = nextmp;
		}
		if ((mp->b_wptr - mp->b_rptr) != ether_headerlen) {
			/*
			 * WOW! Someone's being a jerk not splitting right
			 * after the ethernet header.
			 */
			DTRACE_PROBE1(vxlnat__arp__mblksplit, mblk_t *, mp);
			goto done;
		}
		if (nextmp->b_wptr - nextmp->b_rptr < 
		    sizeof (*arh) + 2 * sizeof (ether_addr_t) +
		    2 * sizeof (ipaddr_t)) {
			DTRACE_PROBE1(vxlnat__arp__toosmallsplit, mblk_t *,
			    nextmp);
			goto done;
		}
		arh = (arh_t *)nextmp->b_rptr;
	} else {
		if (mp->b_wptr - mp->b_rptr < ether_headerlen +
		    sizeof (*arh) + 2 * sizeof (ether_addr_t) +
		    2 * sizeof (ipaddr_t)) {
			DTRACE_PROBE1(vxlnat__arp__toosmall, mblk_t *, mp);
			goto done;
		}
		arh = (arh_t *)(mp->b_rptr + ether_headerlen);
	}
	arpap = (uint8_t *)(arh + 1);

	arpsendmac = (ether_addr_t *)arpap;
	arpap += sizeof (ether_addr_t);
	memcpy(&arpsendip, arpap, sizeof (ipaddr_t));
	arpap += sizeof (ipaddr_t);
	arptargmac = (ether_addr_t *)arpap;
	arpap += sizeof (ether_addr_t);
	memcpy(&arptargip, arpap, sizeof (ipaddr_t));
	arpap += sizeof (ipaddr_t);

	/*
	 * 1.) Must be ARPHDR_ETHER (0x1 in arh_hardware).
	 * 2.) Must be ETHERTYPE_IP (0x800 in arh_proto).
	 * 3.) Must be ARP_REQUEST (0x1 in arh_operation).
	 * 4.) ARP sender HW address must match ARP sender HW address.
	 */
	if (arh->arh_hardware[0] != 0 || arh->arh_hardware[1] != 0x1 ||
	    arh->arh_proto[0] != 0x8 || arh->arh_proto[1] != 0 ||
	    arh->arh_operation[0] != 0 ||
	    arh->arh_operation[1] != ARP_REQUEST ||
	    memcmp(arpsendmac, macsrc, ETHERADDRL) != 0) {
		goto done;
	}

	/*
	 * Okay, we passed the reality checks.  Time to confirm it's me.
	 * Use the IP address from the ARP packet to search, then compare.
	 */
	rule = vxlnat_rule_lookup(vnet, &arptargip, B_TRUE);
	if (rule == NULL) {
		DTRACE_PROBE1(vxlnat__arp__unknownaddr, ipaddr_t, arptargip);
		goto done;
	}
	IN6_V4MAPPED_TO_IPADDR(&rule->vxnr_myaddr, ruleip);
	if (ruleip == arptargip) {
		mblk_t *vxlan_mp;
		vxlan_hdr_t *vxh;

		/* Swap sending/target addresses. */
		memcpy(macdst, macsrc, ETHERADDRL);
		memcpy(macsrc, rule->vxnr_myether, ETHERADDRL);
		memcpy(arptargmac, arpsendmac, ETHERADDRL);
		memcpy(arpsendmac, rule->vxnr_myether, ETHERADDRL);
		VXNR_REFRELE(rule);
		memcpy((arptargmac + 1), &arpsendip, sizeof (ipaddr_t));
		memcpy((arpsendmac + 1), &arptargip, sizeof (ipaddr_t));
		arh->arh_operation[1] = ARP_RESPONSE;

		if (mp->b_rptr - mp->b_datap->db_base < vxlan_noalloc_min) {
			vxlan_mp = allocb(vxlan_alloc_size, BPRI_HI);
			if (vxlan_mp == NULL) {
				DTRACE_PROBE(vxlnat__arp__allocfail);
				goto done;
			}
			vxlan_mp->b_cont = mp;
			vxlan_mp->b_wptr = DB_LIM(vxlan_mp);
			vxlan_mp->b_rptr = vxlan_mp->b_wptr - sizeof (*vxh);
			vxh = (vxlan_hdr_t *)vxlan_mp->b_rptr;
		} else {
			mp->b_rptr -= sizeof (*vxh);
			vxh = (vxlan_hdr_t *)mp->b_rptr;
			vxlan_mp = mp;
		}
		vxh->vxlan_flags = VXLAN_F_VDI_WIRE;
		vxh->vxlan_id = vnet->vxnv_vnetid; /* Already in wire-order. */

		underlay_src->sin6_port = htons(IPPORT_VXLAN);
		vxlnat_sendmblk(&vxlan_mp, underlay_src);
		return;
	} else {
		DTRACE_PROBE2(vxlnat__arp__badaddr, ipaddr_t, arptargip,
		    ipaddr_t, ruleip);
		VXNR_REFRELE(rule);
	}

done:
	freemsg(mp);
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
vxlnat_cache_remote(mblk_t *mp, struct sockaddr_in6 *underlay_src,
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
	int advanceby;

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
		advanceby = sizeof (*evh);
	} else {
		evh = NULL;
		vlan = 0;
		advanceby = sizeof (*eh);
	}
	if (ethertype == ETHERTYPE_ARP) {
		vxlnat_handle_arp(mp, eh, evh, underlay_src, vnet);
		return (NULL);
	}
	mp->b_rptr += advanceby;
	if (ethertype != ETHERTYPE_IP && ethertype != ETHERTYPE_IPV6) {
		/* XXX KEBE SAYS for now, don't handle other non-IP packets. */
		DTRACE_PROBE1(vxlnat__in__drop__nonip, mblk_t *, mp);
		freemsg(mp);
		return (NULL);
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

	/* Find remote and replace OR create new remote. */
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
		if (!IN6_ARE_ADDR_EQUAL(&remote->vxnrem_uaddr,
		    &underlay_src->sin6_addr)) {
			remote->vxnrem_uaddr = underlay_src->sin6_addr;
		}
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
 * Extract transport-level information to find a NAT flow.
 * Consume mp and return B_FALSE if there's a problem.  Fill in "ports"
 * and "protocol" and return B_TRUE if there's not.
 */
static boolean_t
vxlnat_grab_transport(mblk_t *mp, ipha_t *ipha, ip6_t *ip6h, uint32_t *ports,
    uint8_t *protocol, uint8_t **nexthdr_ptr)
{
	uint8_t *nexthdr;

	/* Punt on IPv6 for now... */
	if (ip6h != NULL) {
		freemsg(mp);
		return (B_FALSE);
	}

	ASSERT(ipha != NULL);
	*protocol = ipha->ipha_protocol;
	nexthdr = ((uint8_t *)ipha + IPH_HDR_LENGTH(ipha));
	*nexthdr_ptr = nexthdr;	/* Get this out of the way now. */
	if (nexthdr > mp->b_wptr) {
		DTRACE_PROBE1(vxlnat__in__drop__trnexthdr, mblk_t *, mp);
		freemsg(mp);
		return (B_FALSE);
	}
	switch (*protocol) {
	case IPPROTO_TCP: {
		tcpha_t *tcph = (tcpha_t *)nexthdr;

		if (nexthdr + sizeof (*tcph) > mp->b_wptr) {
			DTRACE_PROBE1(vxlnat__in__drop__tcpnexthdr, mblk_t *,
			    mp);
			freemsg(mp);
			return (B_FALSE);
		}
		*ports = *((uint32_t *)tcph);
		/* XXX KEBE SAYS - grab other metadata here NOW? */
		break;
	}
	case IPPROTO_UDP: {
		udpha_t *udph = (udpha_t *)nexthdr;

		if (nexthdr + sizeof (*udph) > mp->b_wptr) {
			DTRACE_PROBE1(vxlnat__in__drop__udpnexthdr, mblk_t *,
			    mp);
			freemsg(mp);
			return (B_FALSE);
		}
		*ports = *((uint32_t *)udph);
		/*
		 * XXX KEBE SAYS - not as much as TCP, but grab other metadata
		 * here NOW?
		 */
		break;
	}
	case IPPROTO_ICMP: {
		icmph_t *icmph = (icmph_t *)nexthdr;

		if (nexthdr + sizeof (*icmph) > mp->b_wptr) {
			DTRACE_PROBE1(vxlnat__in__drop__icmpnexthdr, mblk_t *,
			    mp);
			freemsg(mp);
			return (B_FALSE);
		}
		/* XXX KEBE SAYS sort out ICMP header... */
		switch (icmph->icmph_type) {
		case ICMP_ECHO_REQUEST:
		case ICMP_TIME_STAMP_REQUEST:
		case ICMP_TIME_EXCEEDED:
		case ICMP_INFO_REQUEST:
		case ICMP_ADDRESS_MASK_REPLY:
			/* All ones we can sorta cope with... */
			break;
		default:
			DTRACE_PROBE2(vxlnat__in__drop__icmptype, int,
			    icmph->icmph_type, mblk_t *, mp);
			freemsg(mp);
			return (B_FALSE);
		}
		/* NOTE: as of now, will switch position depending on endian. */
		*ports = icmph->icmph_echo_ident;
		break;
	}
	default:
		*ports = 0;
		break;
	}

	return (B_TRUE);
}

/*
 * This is the evaluate-packet vs. NAT flow state function.
 * This function does NOT alter "mp".
 */
static boolean_t
vxlnat_verify_natstate(mblk_t *mp, ipha_t *ipha, ip6_t *ip6h,
    vxlnat_flow_t *flow, uint8_t *nexthdr)
{
	/* XXX KEBE SAYS FILL ME IN! */
	/* return (B_TRUE); */

	/* XXX MIKE for testing return TRUE */
	return (B_TRUE);
}

/*
 * Inspect the packet and find ports & protos (or ICMP types & codes)
 * and see if we have an established NAT flow.
 *
 * XXX KEBE WONDERS if the transmission path will more closely resemble
 * vxlnat_one_vxlan_fixed() because of ipha_ident issues or not...
 *
 * B_TRUE means the packet was handled, and we shouldn't continue processing
 * (even if "was handled" means droppage).
 */
static boolean_t
vxlnat_one_vxlan_flow(vxlnat_vnet_t *vnet, mblk_t *mp, ipha_t *ipha,
    ip6_t *ip6h)
{
	vxlnat_flow_t *flow, searcher;
	uint8_t *nexthdr;

	/*
	 * XXX KEBE WONDERS, should we return vxlnat_flow_t instead if we
	 * miss?  That way, we only need to find the ports/protocol ONCE.
	 */

	if (ip6h != NULL) {
		/* Eventually, grab addresses for "searcher". */
		return (B_FALSE);	/* Bail on IPv6 for now... */
	} else {
		ASSERT(ipha != NULL);
		searcher.vxnfl_isv4 = B_TRUE;	/* Required? */
		IN6_INADDR_TO_V4MAPPED((struct in_addr *)(&ipha->ipha_src),
		    &searcher.vxnfl_src);
		IN6_INADDR_TO_V4MAPPED((struct in_addr *)(&ipha->ipha_dst),
		    &searcher.vxnfl_dst);
	}

	if (!vxlnat_grab_transport(mp, ipha, ip6h, &searcher.vxnfl_ports,
	    &searcher.vxnfl_protocol, &nexthdr)) {
		DTRACE_PROBE1(vxlnat__in__flowgrab, mblk_t *, mp);
		freemsg(mp);
		return (B_TRUE);
	}


	/*
	 * XXX KEBE SAYS Eventually put the rw&find in an IPv4-only block,
	 * because IPv6 (if we NAT it like IPv4) will have its own table/tree.
	 */
	rw_enter(&vnet->vxnv_flowv4_lock, RW_READER);
	flow = avl_find(&vnet->vxnv_flows_v4, &searcher, NULL);
	if (flow != NULL)
		VXNFL_REFHOLD(flow);
	rw_exit(&vnet->vxnv_flowv4_lock);

	if (flow == NULL)
		return (B_FALSE);	/* Let caller handle things. */

	if (!vxlnat_verify_natstate(mp, ipha, ip6h, flow, nexthdr)) {
		freemsg(mp);	/* XXX KEBE SAYS FOR NOW... */
	} else {
		/* MIKE Process outgoing packets in an established flow */
		mblk_t *newmp;
		ire_t *outbound_ire;
		ip_recv_attr_t iras = { IRAF_IS_IPV4 | IRAF_VERIFIED_SRC };

		if ((newmp = vxlnat_fixv4(mp, NULL, flow, B_FALSE)) == NULL)
			return (B_TRUE);

		/* XXX MIKE Send the pkt! */
		/* copy and paste start*/
		/* the ixa_ire is setup when calling conn_connect */
		outbound_ire = flow->vxnfl_connp->conn_ixa->ixa_ire;
		VERIFY3P(outbound_ire, !=, NULL);
		ire_refhold(outbound_ire);
		if (outbound_ire->ire_type == IRE_NOROUTE) {
			/* Bail! */
			DTRACE_PROBE2(vxlnat__in__drop__mappedire, ipaddr_t,
			    ipha->ipha_dst, mblk_t *, mp);
			VXNFL_REFRELE(flow);
			freemsg(mp);
			return (B_TRUE);
		}

		iras.ira_ip_hdr_length = IPH_HDR_LENGTH(ipha);
		if (iras.ira_ip_hdr_length > sizeof (ipha_t))
			iras.ira_flags |= IRAF_IPV4_OPTIONS;
		iras.ira_xmit_hint = 0; /* XXX KEBE SAYS FIX ME! */
		iras.ira_zoneid = outbound_ire->ire_zoneid;
		iras.ira_pktlen = ntohs(ipha->ipha_length);
		iras.ira_protocol = ipha->ipha_protocol;
		/* XXX KEBE ASKS rifindex & ruifindex ?!? */
		/*
		 * NOTE: AT LEAST ira_ill needs ILLF_ROUTER set, as
		 * well as the ill for the external NIC (where
		 * off-link destinations live).  For fixed, ira_ill
		 * should be the ill of the external source.
		 */
		if (vxlnat_underlay_ire == NULL) {
			/* We're mid-quiesce. */
			DTRACE_PROBE2(vxlnat__in__drop__quiesce, ipaddr_t,
			    ipha->ipha_dst, mblk_t *, mp);
			VXNFL_REFRELE(flow);
			freemsg(mp);
			return (B_TRUE);
		}
		iras.ira_rill = vxlnat_underlay_ire->ire_ill;
		iras.ira_ill = outbound_ire->ire_ill;
		/* XXX KEBE ASKS cred & cpid ? */
		iras.ira_verified_src = ipha->ipha_src;
		/* XXX KEBE SAYS don't sweat IPsec stuff. */
		/* XXX KEBE SAYS ALSO don't sweat l2src & mhip */

		/* Okay, we're good! Let's pretend we're forwarding. */
		ire_recv_forward_v4(outbound_ire, mp, ipha, &iras);
		ire_refrele(outbound_ire);
		/* copy and paste end*/
	}

	VXNFL_REFRELE(flow);
	return (B_TRUE);
}

/*
 * We have a new packet that seems to require a new NAT flow.  Construct that
 * flow now, and intern it as both a conn_t in IP *and* in the vnet's
 * appropriate vxnv_flows* tree.  Return NULL if we have a problem.
 */
static vxlnat_flow_t *
vxlnat_new_flow(vxlnat_rule_t *rule, in6_addr_t *inner_src, in6_addr_t *dst,
    uint32_t ports, uint8_t protocol)
{
	vxlnat_vnet_t *vnet = rule->vxnr_vnet;
	vxlnat_flow_t *flow, *oldflow;
	avl_tree_t *flowtree;
	krwlock_t *flowlock;
	avl_index_t where;

	flow = kmem_alloc(sizeof (*flow), KM_NOSLEEP | KM_NORMALPRI);
	if (flow == NULL)
		return (NULL);

	flow->vxnfl_dst = *dst;
	flow->vxnfl_src = *inner_src;
	flow->vxnfl_ports = ports;
	flow->vxnfl_protocol = protocol;
	flow->vxnfl_refcount = 2; /* One for internment, one for caller. */
	/* Assume no mixed-IP-version mappings for now. */
	if (IN6_IS_ADDR_V4MAPPED(inner_src)) {
		ASSERT(IN6_IS_ADDR_V4MAPPED(dst));
		flow->vxnfl_isv4 = B_TRUE;
		flowtree = &vnet->vxnv_flows_v4;
		flowlock = &vnet->vxnv_flowv4_lock;
	} else {
		ASSERT(!IN6_IS_ADDR_V4MAPPED(dst));
		flow->vxnfl_isv4 = B_FALSE;
		/* XXX KEBE SAYS we don't do IPv6 for now. */
		DTRACE_PROBE2(vxlnat__flow__newv6, in6_addr_t *, inner_src,
		    in6_addr_t *, dst);
		kmem_free(flow, sizeof (*flow));
		return (NULL);
	}
	VXNR_REFHOLD(rule);	/* For the flow itself... */
	flow->vxnfl_rule = rule;

	rw_enter(flowlock, RW_WRITER);
	oldflow = (vxlnat_flow_t *)avl_find(flowtree, flow, &where);
	if (oldflow != NULL) {
		/*
		 * Hmmm, someone put one in while we were dinking around.
		 * XXX KEBE SAYS return the old one, refheld, for now.
		 */
		VXNR_REFRELE(rule);
		kmem_free(flow, sizeof (*flow));
		VXNFL_REFHOLD(oldflow);
		flow = oldflow;
	} else {
		avl_insert(flowtree, flow, where);
		/*
		 * Do conn_t magic here, except for the conn_t activation.  I
		 * am aware of holding the rwlock-as-write here.  We may need
		 * to move this outside the rwlock hold, and
		 * reacquire-on-failure.
		 */
		if (!vxlnat_new_conn(flow)) {
			ASSERT(flow->vxnfl_connp == NULL);
			avl_remove(flowtree, flow);
			VXNR_REFRELE(flow->vxnfl_rule);
			kmem_free(flow, sizeof (*flow));
			flow = NULL;
		}
	}
	rw_exit(flowlock);
	
	/* We just created this one, activate it. */
	if (oldflow == NULL && flow != NULL)
		vxlnat_activate_conn(flow);

	return (flow);
}

void
vxlnat_flow_free(vxlnat_flow_t *flow)
{
	ASSERT(flow->vxnfl_refcount == 0);

	/* XXX KEBE SAYS FILL ME IN?! */
	/* XXX KEBE ASKS ipcl_hash_remove()? */

	flow->vxnfl_connp->conn_priv = NULL; /* Sufficient? */
	CONN_DEC_REF(flow->vxnfl_connp);
	VXNR_REFRELE(flow->vxnfl_rule);
	kmem_free(flow, sizeof (*flow));
}

static boolean_t
vxlnat_verify_initial(mblk_t *mp, ipha_t *ipha, ip6_t *ip6h,
    uint32_t ports, uint8_t protocol, uint8_t *nexthdr)
{
	/*
	 * vxlnat_grab_transport has verified nexthdr for
	 * us, so it always needs to be called first
	 */
	switch (protocol) {
	case IPPROTO_TCP: {
		tcpha_t *tcph = (tcpha_t *)nexthdr;

		/* XXX be more strict about TCP flags? */
		if (tcph->tha_flags == TH_SYN)
			return (B_TRUE);

		break;
	}
	case IPPROTO_UDP:
	case IPPROTO_ICMP:
		/*
		 * UDP doesn't have anything we can check really.
		 * ICMP type has already been checked by vxlnat_grab_transport.
		 */
		return (B_TRUE);
	default:
		break;
	}

	DTRACE_PROBE1(vxlnat__in__drop__initial, mblk_t *, mp);
	freemsg(mp);
	return (B_FALSE);
}

/*
 * If we reach here, we need to find a NAT rule, and see if we can/should
 * CREATE a new NAT flow, or whether or not we should drop, maybe even
 * returning an ICMP message of some sort.
 *
 * B_TRUE means the packet was handled, and we shouldn't continue processing
 * (even if "was handled" means droppage).
 */
static boolean_t
vxlnat_one_vxlan_rule(vxlnat_vnet_t *vnet, mblk_t *mp, ipha_t *ipha,
    ip6_t *ip6h)
{
	vxlnat_rule_t *rule;
	vxlnat_flow_t *flow;
	in6_addr_t v4m_src, v4m_dst, *inner_src, *dst;
	uint32_t ports;
	uint8_t protocol;
	uint8_t *nexthdr;

	/* XXX handle IPv6 later, assigning inner_src and dst to ip6_t addrs. */
	if (ip6h != NULL)
		return (B_FALSE);

	ASSERT3P(ipha, !=, NULL);
	inner_src = &v4m_src;
	dst = &v4m_dst;
	IN6_INADDR_TO_V4MAPPED((struct in_addr *)(&ipha->ipha_src), inner_src);
	IN6_INADDR_TO_V4MAPPED((struct in_addr *)(&ipha->ipha_dst), dst);

	rule = vxlnat_rule_lookup(vnet, &ipha->ipha_src, B_TRUE);
	if (rule == NULL)
		return (B_FALSE);

	/* process packet */

	/*
	 * Grab transport header, and figure out if we can proceed.
	 *
	 * NOTE: vxlnat_grab_transport() will free/consume mp if it fails,
	 * because we want to isolate non-flow-starters without having them
	 * create new flows.  This means we return B_TRUE (consumed mp) on
	 * failure. 
	 */
	if (!vxlnat_grab_transport(mp, ipha, ip6h, &ports, &protocol, &nexthdr))
		return (B_TRUE); /* see above... */
	if (!vxlnat_verify_initial(mp, ipha, ip6h, ports, protocol, nexthdr))
		return (B_TRUE);


	flow = vxlnat_new_flow(rule, inner_src, dst, ports, protocol);
	if (flow != NULL) {
		/*
		 * Call same function that vxlnat_one_vxlan_flow() uses
		 * to remap & transmit the packet out the external side.
		 *
		 * NOTE:  We've already checked the initial-packet-
		 * qualification, so unlike the main datapath, we don't
		 * need to call vxlnat_verify_natstate()
		 */

		mblk_t *newmp;
		ire_t *outbound_ire;
		ip_recv_attr_t iras = { IRAF_IS_IPV4 | IRAF_VERIFIED_SRC };

		if ((newmp = vxlnat_fixv4(mp, NULL, flow, B_FALSE)) == NULL)
			return (B_TRUE);

		/* XXX MIKE Send the pkt! */
		/* copy and paste start*/
		outbound_ire = ire_route_recursive_dstonly_v4(ipha->ipha_dst,
		    IRR_ALLOCATE, 0, vxlnat_netstack->netstack_ip);
		VERIFY3P(outbound_ire, !=, NULL);
		if (outbound_ire->ire_type == IRE_NOROUTE) {
			/* Bail! */
			DTRACE_PROBE2(vxlnat__in__drop__mappedire, ipaddr_t,
			    ipha->ipha_dst, mblk_t *, mp);
			VXNFL_REFRELE(flow);
			freemsg(mp);
			return (B_TRUE);
		}

		iras.ira_ip_hdr_length = IPH_HDR_LENGTH(ipha);
		if (iras.ira_ip_hdr_length > sizeof (ipha_t))
			iras.ira_flags |= IRAF_IPV4_OPTIONS;
		iras.ira_xmit_hint = 0; /* XXX KEBE SAYS FIX ME! */
		iras.ira_zoneid = outbound_ire->ire_zoneid;
		iras.ira_pktlen = ntohs(ipha->ipha_length);
		iras.ira_protocol = ipha->ipha_protocol;
		/* XXX KEBE ASKS rifindex & ruifindex ?!? */
		/*
		 * NOTE: AT LEAST ira_ill needs ILLF_ROUTER set, as
		 * well as the ill for the external NIC (where
		 * off-link destinations live).  For fixed, ira_ill
		 * should be the ill of the external source.
		 */
		if (vxlnat_underlay_ire == NULL) {
			/* We're mid-quiesce. */
			DTRACE_PROBE2(vxlnat__in__drop__quiesce, ipaddr_t,
			    ipha->ipha_dst, mblk_t *, mp);
			VXNFL_REFRELE(flow);
			freemsg(mp);
			return (B_TRUE);
		}
		iras.ira_rill = vxlnat_underlay_ire->ire_ill;
		iras.ira_ill =
		    flow->vxnfl_connp->conn_ixa->ixa_ire->ire_ill;
		/* XXX KEBE ASKS cred & cpid ? */
		iras.ira_verified_src = ipha->ipha_src;
		/* XXX KEBE SAYS don't sweat IPsec stuff. */
		/* XXX KEBE SAYS ALSO don't sweat l2src & mhip */

		/* Okay, we're good! Let's pretend we're forwarding. */
		ire_recv_forward_v4(outbound_ire, mp, ipha, &iras);
		ire_refrele(outbound_ire);
		/* copy and paste end*/


		VXNFL_REFRELE(flow);
		return (B_TRUE);
	}

	return (B_FALSE);
}

/*
 * See if the inbound VXLAN packet hits a 1-1/fixed mapping, and process if it
 * does.  B_TRUE means the packet was handled, and we shouldn't continue
 * processing (even if "was handled" means droppage).
 */
static boolean_t
vxlnat_one_vxlan_fixed(vxlnat_vnet_t *vnet, mblk_t *mp, ipha_t *ipha,
    ip6_t *ip6h)
{
	vxlnat_fixed_t *fixed, fsearch;
	mblk_t *newmp;
	ire_t *outbound_ire = NULL;
	/* Use C99's initializers for fun & profit. */
	ip_recv_attr_t iras = { IRAF_IS_IPV4 | IRAF_VERIFIED_SRC };

	if (ipha != NULL) {
		IN6_INADDR_TO_V4MAPPED((struct in_addr *)(&ipha->ipha_src),
		    &fsearch.vxnf_addr);
	} else {
		/* vxlnat_cache_remote() did reality checks... */
		ASSERT(ipha == NULL && ip6h != NULL);
		fsearch.vxnf_addr = ip6h->ip6_src;
	}

	rw_enter(&vnet->vxnv_fixed_lock, RW_READER);
	fixed = avl_find(&vnet->vxnv_fixed_ips, &fsearch, NULL);
	if (fixed != NULL)
		VXNF_REFHOLD(fixed);
	rw_exit(&vnet->vxnv_fixed_lock);
	if (fixed == NULL)
		return (B_FALSE);	/* Try another method of processing. */

	newmp = NULL;
	/*
	 * XXX KEBE ASKS --> Do an MTU check NOW?!  That way, we have
	 * pre-natted data.  One gotcha, external dests may have
	 * different PathMTUs so see below about EMSGSIZE...
	 *
	 * For now, let the post-NAT crunch through
	 * ire_recv_forward_v4() take care of all of that.
	 */

	if (ipha != NULL)
		newmp = vxlnat_fixv4(mp, fixed, NULL, B_FALSE);
	else {
		freemsg(mp); /* XXX handle ip6h */
		goto release_and_return;
	}

	if (newmp == NULL)
		goto release_and_return;	/* mp eaten by vxlnat_fixv4() */


	ASSERT3P(ipha, ==, newmp->b_rptr);
	/* XXX KEBE ASKS, IRR_ALLOCATE okay?!? */
	/* XXX KEBE SAYS XMIT HINT! */
	outbound_ire = ire_route_recursive_dstonly_v4(ipha->ipha_dst,
	    IRR_ALLOCATE, 0, vxlnat_netstack->netstack_ip);
	VERIFY3P(outbound_ire, !=, NULL);
	if (outbound_ire->ire_type == IRE_NOROUTE) {
		/* Bail! */
		DTRACE_PROBE2(vxlnat__in__drop__fixedire, ipaddr_t,
		    ipha->ipha_dst, mblk_t *, mp);
		freemsg(mp);
		goto release_and_return;
	}

	iras.ira_ip_hdr_length = IPH_HDR_LENGTH(ipha);
	if (iras.ira_ip_hdr_length > sizeof (ipha_t))
		iras.ira_flags |= IRAF_IPV4_OPTIONS;
	iras.ira_xmit_hint = 0; /* XXX KEBE SAYS FIX ME! */
	iras.ira_zoneid = outbound_ire->ire_zoneid;
	iras.ira_pktlen = ntohs(ipha->ipha_length);
	iras.ira_protocol = ipha->ipha_protocol;
	/* XXX KEBE ASKS rifindex & ruifindex ?!? */
	/*
	 * NOTE: AT LEAST ira_ill needs ILLF_ROUTER set, as
	 * well as the ill for the external NIC (where
	 * off-link destinations live).  For fixed, ira_ill
	 * should be the ill of the external source.
	 */
	if (vxlnat_underlay_ire == NULL) {
		/* We're mid-quiesce. */
		DTRACE_PROBE2(vxlnat__in__drop__quiesce, ipaddr_t,
		    ipha->ipha_dst, mblk_t *, mp);
		freemsg(mp);
		goto release_and_return;
	}
	iras.ira_rill = vxlnat_underlay_ire->ire_ill;
	iras.ira_ill = fixed->vxnf_ire->ire_ill;
	/* XXX KEBE ASKS cred & cpid ? */
	iras.ira_verified_src = ipha->ipha_src;
	/* XXX KEBE SAYS don't sweat IPsec stuff. */
	/* XXX KEBE SAYS ALSO don't sweat l2src & mhip */

	/* Okay, we're good! Let's pretend we're forwarding. */
	ire_recv_forward_v4(outbound_ire, mp, ipha, &iras);

release_and_return:
	if (outbound_ire != NULL)
		ire_refrele(outbound_ire);
	VXNF_REFRELE(fixed);
	return (B_TRUE);
}

/*
 * Process exactly one VXLAN packet.
 */
static void
vxlnat_one_vxlan(mblk_t *mp, struct sockaddr_in6 *underlay_src)
{
	vxlan_hdr_t *vxh;
	vxlnat_vnet_t *vnet;
	ipha_t *ipha;
	ip6_t *ip6h;

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
	 * Arrived-from-vxlan processing steps:
	 * 1.) Locate the ethernet header and check/update/add-into remotes.
	 * 2.) Search 1-1s, process if hit.
	 * 3.) Search flows, process if hit.
	 * 4.) Search rules, create new flow (or not) if hit.
	 * 5.) Drop the packet.
	 */

	/* 1.) Locate the ethernet header and check/update/add-into remotes. */
	mp->b_rptr += sizeof (*vxh);
	while (MBLKL(mp) == 0) {
		mblk_t *oldmp = mp;

		mp = mp->b_cont;
		freeb(oldmp);
	}
	/* XXX KEBE ASKS CACHE dst MAC here too for IP? */
	mp = vxlnat_cache_remote(mp, underlay_src, vnet);
	if (mp == NULL)
		goto bail_no_free;

	/* Let's cache the IP header here... */
	ipha = (ipha_t *)mp->b_rptr;
	switch (IPH_HDR_VERSION(ipha)) {
	case IPV4_VERSION:
		ip6h = NULL;
		break;
	case IPV6_VERSION:
		ip6h = (ip6_t *)ipha;
		ipha = NULL;
		break;
	default:
		DTRACE_PROBE2(vxlnat__in__drop__ipvers, int,
		    IPH_HDR_VERSION(ipha), mblk_t *, mp);
		goto bail_and_free;
	}

	/*
	 * XXX KEBE SAYS - if caching dst MAC (see above) make sure we're
	 * getting the right one up to the processing functions below. This
	 * lives on either fixed (in struct), flow (via ptr to rule), or rule
	 * (in struct).
	 */

	/* 2.) Search 1-1s, process if hit. */
	if (vxlnat_one_vxlan_fixed(vnet, mp, ipha, ip6h))
		goto bail_no_free;	/* Success means mp was consumed. */

	/* 3.) Search flows, process if hit. */
	if (vxlnat_one_vxlan_flow(vnet, mp, ipha, ip6h))
		goto bail_no_free;	/* Success means mp was consumed. */

	/* 4.) Search rules, create new flow (or not) if hit. */
	if (vxlnat_one_vxlan_rule(vnet, mp, ipha, ip6h))
		goto bail_no_free;	/* Success means mp was consumed. */

	/* 5.) Nothing, drop the packet. */

	DTRACE_PROBE2(vxlnat__in__drop__nohits, vxlnat_vnet_t *, vnet,
	    mblk_t *, mp);

bail_and_free:
	freemsg(mp);
bail_no_free:
	VXNV_REFRELE(vnet);
}
/*
 * ONLY return B_FALSE if we get a packet-clogging event.
 */
/* ARGSUSED */
boolean_t
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
		struct sockaddr_in6 *sin6;

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
		sin6 = (struct sockaddr_in6 *)(mp->b_rptr + tudi->SRC_offset);
		VERIFY(sin6->sin6_family == AF_INET6);
		VERIFY(tudi->SRC_length >= sizeof (*sin6));

		vxlnat_one_vxlan(mp->b_cont, sin6);
		freeb(mp);
	}

	return (B_TRUE);
}

/*
 * Use RFC 1141's technique (with a check for -0).
 *
 * newsum = oldsum - (new16a + old16a - new16b + old16b ...);
 *
 * NOTE: "oldsum" is right off the wire in wire-native order.
 * NOTE2: "old" and "new" ALSO point to things in wire-native order.
 * NOTE3:  THIS MUST TAKE A MULTIPLE OF 2 BYTES (i.e. uint16_t array).
 * NOTE4: The 32-bit running sum means we can't take len > 64k.
 */
uint16_t
vxlnat_cksum_adjust(uint16_t oldsum, uint16_t *old, uint16_t *new, uint_t len)
{
	uint32_t newsum = ntohs(oldsum);

	ASSERT((len & 0x1) == 0);
	while (len != 0) {
		newsum -= ntohs(*new);
		newsum += ntohs(*old);
		len -= 2;
		old++;
		new++;
	}
	newsum += (newsum >> 16) & 0xffff;

	return (newsum == 0xffff ? 0 : htons(newsum));
}

/*
 * Fix inner headers on an ICMP packet.
 *
 * XXX KEBE SAYS FOR NOW, just do addresses for 1-1/fixed.  When we do
 * flows, include old_port/new_port as well.
 */
static mblk_t *
vxlnat_fix_icmp_inner_v4(mblk_t *mp, icmph_t *icmph, ipaddr_t old_one,
    ipaddr_t new_one, boolean_t to_private)
{
	mblk_t *newmp;
	ipha_t *inner_ipha;
	ipaddr_t *new_ones_place;

	if ((uint8_t *)(icmph + 1) + sizeof (ipha_t) > mp->b_wptr) {
		/* Pay the pullup tax. */
		newmp = msgpullup(mp, -1);
		freemsg(mp);
		if (newmp == NULL) {
			DTRACE_PROBE1(vxlnat__fixicmp__pullupfail, void *,
			    NULL);
			return (NULL);
		}
		if (MBLKL(newmp) < 2 * sizeof (ipha_t) + sizeof (icmph_t)) {
			/* Wow! Too-tiny ICMP packet. */
			DTRACE_PROBE1(vxlnat__fixicmp__tootiny, mblk_t *,
			    newmp);
			freeb(newmp);
			return (NULL);
		}
		mp = newmp;
		/* Temporarily use inner_ipha for the outer one. */
		inner_ipha = (ipha_t *)mp->b_rptr;
		icmph = (icmph_t *)(mp->b_rptr + IPH_HDR_LENGTH(inner_ipha));
	}
	inner_ipha = (ipha_t *)(icmph + 1);
	new_ones_place = to_private ?
	    &inner_ipha->ipha_src : &inner_ipha->ipha_dst;
	if (*new_ones_place != old_one) {
		/* Either I'm buggy or the packet is. */
		DTRACE_PROBE2(vxlnat__fixicmp__badinneraddr, ipaddr_t,
		    old_one, ipaddr_t, *new_ones_place);
		freeb(mp);
		return (NULL);
	}
	*new_ones_place = new_one;

	/* Adjust ICMP checksum... */
	icmph->icmph_checksum = vxlnat_cksum_adjust(icmph->icmph_checksum,
	    (uint16_t *)&old_one, (uint16_t *)&new_one, sizeof (ipaddr_t));

	/*
	 * XXX KEBE ASKS, recompute *inner-packet* checksums?  Let's not for
	 * now, but consider this Fair Warning (or some other VH album...).
	 */
	return (mp);
}

/*
 * Take a 1-1/fixed or mapped IPv4 packet and convert it for transmission out
 * the appropriate end. "to_private" is what it says on the tin.  ALWAYS
 * consumes "mp", regardless of return value.
 */
mblk_t *
vxlnat_fixv4(mblk_t *mp, vxlnat_fixed_t *fixed, vxlnat_flow_t *flow,
    boolean_t to_private)
{
	ipaddr_t new_one, old_one;
	ipaddr_t *new_ones_place;
	ipha_t *ipha = (ipha_t *)mp->b_rptr;
	uint8_t *nexthdr, *end_wptr;

	if (fixed != NULL) {
		if (to_private) {
			IN6_V4MAPPED_TO_IPADDR(&fixed->vxnf_addr, new_one);
			new_ones_place = &ipha->ipha_dst;
		} else {
			IN6_V4MAPPED_TO_IPADDR(&fixed->vxnf_pubaddr, new_one);
			new_ones_place = &ipha->ipha_src;
		}
	} else {
		ASSERT3P(flow, !=, NULL);

		if (to_private) {
			IN6_V4MAPPED_TO_IPADDR(&flow->vxnfl_src,
			    new_one);
			new_ones_place = &ipha->ipha_dst;
		} else {
			IN6_V4MAPPED_TO_IPADDR(&flow->vxnfl_rule->vxnr_pubaddr,
			    new_one);
			new_ones_place = &ipha->ipha_src;
		}
	}


	old_one = *new_ones_place;
	*new_ones_place = new_one;

	/*
	 * Recompute the IP header checksum, and check for the TCP or UDP
	 * checksum as well, as they'll need recomputing as well.
	 */

	/* First, the IPv4 header itself. */
	ipha->ipha_hdr_checksum = vxlnat_cksum_adjust(ipha->ipha_hdr_checksum,
	    (uint16_t *)&old_one, (uint16_t *)&new_one, sizeof (ipaddr_t));

	nexthdr = (uint8_t *)ipha + IPH_HDR_LENGTH(ipha);
	if (nexthdr >= mp->b_wptr) {
		nexthdr = mp->b_cont->b_rptr +
		    (MBLKL(mp) - IPH_HDR_LENGTH(ipha));
		end_wptr = mp->b_cont->b_wptr;
	} else {
		end_wptr = mp->b_wptr;
	}

	switch (ipha->ipha_protocol) {
	case IPPROTO_TCP: {
		tcpha_t *tcph = (tcpha_t *)nexthdr;

		if (nexthdr + sizeof (*tcph) >= end_wptr) {
			/* Bail for now. */
			DTRACE_PROBE1(vxlnat__fix__tcp__mblkspan, mblk_t *,
			    mp);
			freemsg(mp);
			return (NULL);
		}
		tcph->tha_sum = vxlnat_cksum_adjust(tcph->tha_sum,
		    (uint16_t *)&old_one, (uint16_t *)&new_one,
		    sizeof (ipaddr_t));

		if (flow != NULL) {
			in_port_t old_port, new_port;

			if (to_private) {
				old_port = tcph->tha_fport;
				new_port = VXNFL_SPORT(flow->vxnfl_ports);
				tcph->tha_fport = new_port;
				/* XXX MIKE remove debug probe */
				DTRACE_PROBE1(vxlnat__mike_rx,
				    in_port_t, new_port);
			} else {
				old_port = tcph->tha_lport;
				new_port = flow->vxnfl_connp->conn_lport;
				tcph->tha_lport = new_port;
				/* XXX MIKE remove debug probe */
				DTRACE_PROBE1(vxlnat__mike_tx,
				    in_port_t, new_port);
			}
			tcph->tha_sum =
			    vxlnat_cksum_adjust(tcph->tha_sum,
			    (uint16_t *)&old_port, (uint16_t *)&new_port,
			    sizeof (in_port_t));
		}
		break;	/* Out of switch. */
	}
	case IPPROTO_UDP: {
		udpha_t *udph = (udpha_t *)nexthdr;

		if (nexthdr + sizeof (*udph) >= end_wptr) {
			/* Bail for now. */
			DTRACE_PROBE1(vxlnat__fix__udp__mblkspan, mblk_t *,
			    mp);
			freemsg(mp);
			return (NULL);
		}
		udph->uha_checksum = vxlnat_cksum_adjust(udph->uha_checksum,
		    (uint16_t *)&old_one, (uint16_t *)&new_one,
		    sizeof (ipaddr_t));

		if (flow != NULL) {
			in_port_t old_port, new_port;

			if (to_private) {
				old_port = udph->uha_dst_port;
				new_port = VXNFL_SPORT(flow->vxnfl_ports);
				udph->uha_dst_port = new_port;
			} else {
				old_port = udph->uha_src_port;
				new_port = flow->vxnfl_connp->conn_lport;
				udph->uha_src_port = new_port;
			}
			udph->uha_checksum =
			    vxlnat_cksum_adjust(udph->uha_checksum,
			    (uint16_t *)&old_port, (uint16_t *)&new_port,
			    sizeof (in_port_t));
		}
		break;	/* Out of switch. */
	}
	case IPPROTO_ICMP: {
		icmph_t *icmph = (icmph_t *)nexthdr;

		/*
		 * We need to check the case of ICMP messages that contain
		 * IP packets.  We will need to at least change the addresses,
		 * and *maybe* the checksums too if necessary.
		 *
		 * This may replicate some of icmp_inbound_v4(), alas.
		 */
		if (nexthdr + sizeof (*icmph) >= end_wptr) {
			mblk_t *newmp;
			/*
			 * Unlike the others, we're going to pay the pullup
			 * tax here.
			 */
			newmp = msgpullup(mp, -1);
			freemsg(mp);
			if (newmp == NULL) {
				DTRACE_PROBE1(vxlnat__icmp__pullupfail, void *,
				    NULL);
				return (NULL);
			}
			mp = newmp;
			ipha = (ipha_t *)(mp->b_rptr);
			nexthdr = (uint8_t *)ipha + IPH_HDR_LENGTH(ipha);
			icmph = (icmph_t *)nexthdr;
		}

		switch (icmph->icmph_type) {
		case ICMP_ADDRESS_MASK_REPLY:
		case ICMP_ADDRESS_MASK_REQUEST:
		case ICMP_TIME_STAMP_REPLY:
		case ICMP_TIME_STAMP_REQUEST:
		case ICMP_ECHO_REQUEST:
		case ICMP_ECHO_REPLY:
			/* These merely need to get passed along. */
			break;
		case ICMP_ROUTER_ADVERTISEMENT:
		case ICMP_ROUTER_SOLICITATION:
			/* These shouldn't be traversing a NAT at all. Drop. */
			DTRACE_PROBE1(vxlnat__icmp__cantpass, int,
			    icmph->icmph_type);
			freemsg(mp);
			return (NULL);
		case ICMP_PARAM_PROBLEM:
		case ICMP_TIME_EXCEEDED:
		case ICMP_DEST_UNREACHABLE:
			/* These include inner-IP headers we need to adjust. */
			mp = vxlnat_fix_icmp_inner_v4(mp, icmph, old_one,
			    new_one, to_private);
			break;
		default:
			/* Pass along to receiver, but warn. */
			DTRACE_PROBE1(vxlnat__icmp__unknown, int,
			    icmph->icmph_type);
			break;
		}
	}
	/* Otherwise we can't make any other assumptions for now... */
	default:
		break;
	}

	return (mp);
}

vxlnat_remote_t *
vxlnat_xmit_vxlanv4(mblk_t *mp, in6_addr_t *overlay_dst,
    vxlnat_remote_t *remote, uint8_t *myether, vxlnat_vnet_t *vnet)
{
	struct sockaddr_in6 sin6 = {AF_INET6};
	mblk_t *vlan_mp;
	vxlan_hdr_t *vxh;
	struct ether_vlan_header *evh;

	if (remote == NULL || remote->vxnrem_vnet == NULL) {
		DTRACE_PROBE1(vxlnat__xmit__vxlanv4, vxlnat_remote_t *, remote);
		/* Release the condemned remote. */
		if (remote != NULL)
			VXNREM_REFRELE(remote);

		/* See if we have a remote ready to use... */
		remote = vxlnat_get_remote(vnet, overlay_dst, B_FALSE);

		if (remote == NULL) {
			/*
			 * We need to do the moral equivalent of PF_KEY
			 * ACQUIRE or overlay's queue-resolve so that we can
			 * have someone in user-space send me a remote.  Until
			 * then, drop the reference if condemned, free the
			 * message, and return NULL.
			 */

			freemsg(mp);
			return (NULL);
		}
	}
	ASSERT(vnet == remote->vxnrem_vnet);

	if (DB_REF(mp) > 1 || mp->b_rptr - vxlan_noalloc_min < DB_BASE(mp)) {
		vlan_mp = allocb(vxlan_alloc_size, BPRI_HI);
		if (vlan_mp == NULL) {
			DTRACE_PROBE1(vxlnat__xmit__vxlanv4__allocfail,
			    vxlnat_remote_t *, remote);
			freemsg(mp);
			/* Just drop the packet, but don't tell caller. */
			return (remote);
		}
		vlan_mp->b_wptr = DB_LIM(vlan_mp);
		vlan_mp->b_rptr = vlan_mp->b_wptr;
		vlan_mp->b_cont = mp;
	} else {
		vlan_mp = mp;
	}
	vlan_mp->b_rptr -= sizeof (*vxh) + sizeof (*evh);
	vxh = (vxlan_hdr_t *)vlan_mp->b_rptr;
	vxh->vxlan_flags = VXLAN_F_VDI_WIRE;
	vxh->vxlan_id = vnet->vxnv_vnetid;	/* Already in wire-order. */

	/* Fill in the Ethernet header. */
	evh = (struct ether_vlan_header *)(vxh + 1);
	ether_copy(&remote->vxnrem_ether, &evh->ether_dhost);
	ether_copy(myether, &evh->ether_shost);
	evh->ether_tpid = htons(ETHERTYPE_VLAN);
	evh->ether_tci = remote->vxnrem_vlan;
	evh->ether_type = htons(ETHERTYPE_IP);

	/* Address family and other zeroing already done up top. */
	sin6.sin6_port = htons(IPPORT_VXLAN);
	sin6.sin6_addr = remote->vxnrem_uaddr;

	vxlnat_sendmblk(&vlan_mp, &sin6);

	return (remote);
}

/*
 * Placeholder functions for just dropping packets.
 */
int
vxlnat_fixed_send_drop(ire_t *ire, mblk_t *mp, void *iph_arg,
    ip_xmit_attr_t *ixa, uint32_t *identp)
{
	/* Free the message and return an appropriate error. */
	freemsg(mp);
	return (EOPNOTSUPP);
}

void
vxlnat_fixed_recv_drop(ire_t *ire, mblk_t *mp, void *iph_arg,
    ip_recv_attr_t *ira)
{
	/* Free the message, that's it. */
	freemsg(mp);
}

/*
 * New ire_{recv,send}fn implementations if we're doing 1-1 mappings.
 */
int
vxlnat_fixed_ire_send_v6(ire_t *ire, mblk_t *mp, void *iph_arg,
    ip_xmit_attr_t *ixa, uint32_t *identp)
{
	/* XXX KEBE SAYS FILL ME IN, but for now... */
	return (vxlnat_fixed_send_drop(ire, mp, iph_arg, ixa, identp));
}

void
vxlnat_fixed_ire_recv_v6(ire_t *ire, mblk_t *mp, void *iph_arg,
    ip_recv_attr_t *ira)
{
	/* XXX KEBE SAYS FILL ME IN, but for now... */
	vxlnat_fixed_recv_drop(ire, mp, iph_arg, ira);
}

/*
 * I believe the common case for this will be from self-generated ICMP
 * messages.  Other same-netstack-originated traffic will also come through
 * here (one internal reaching what turns out to be another internal).
 */
int
vxlnat_fixed_ire_send_v4(ire_t *ire, mblk_t *mp, void *iph_arg,
    ip_xmit_attr_t *ixa, uint32_t *identp)
{
	ip_recv_attr_t iras;	/* NOTE: No bzero because we pay more later */
	ipha_t *ipha = (ipha_t *)iph_arg;

	/*
	 * XXX KEBE ASKS, any DTrace probes or other instrumentation that
	 * perhaps should be set?
	 */

	/* Map ixa to ira. */
	iras.ira_pktlen = ixa->ixa_pktlen;
	/* XXX KEBE ASKS more?!? */

	/*
	 * In normal TCP/IP processing, this shortcuts the IP header checksum
	 * AND POSSIBLY THE ULP checksum cases.  Since this is likely to head
	 * back into the internal network, we need to recompute things again.
	 */
	if (!ip_output_sw_cksum_v4(mp, ipha, ixa)) {
		freemsg(mp);
		return (EMSGSIZE);
	}
#if 0
	/* XXX KEBE ASKS Special-case ICMP here? */
	if (ipha->ipha_protocol == IPPROTO_ICMP) {
		icmph_t *icmph;

		icmph = (icmph_t *)((uint8_t *)ipha + IPH_HDR_LENGTH(ipha));
		if ((uint8_t *)icmph >= mp->b_wptr) {
			freemsg(mp);
			return (EMSGSIZE);
		}
		icmph->icmph_checksum = 0;
		icmph->icmph_checksum = IP_CSUM(mp, IPH_HDR_LENGTH(ipha), 0);
	}
#endif

	vxlnat_fixed_ire_recv_v4(ire, mp, iph_arg, &iras);

	return (0);
}

void
vxlnat_fixed_ire_recv_v4(ire_t *ire, mblk_t *mp, void *iph_arg,
    ip_recv_attr_t *ira)
{
	vxlnat_fixed_t *fixed;
	vxlnat_vnet_t *vnet;
	ipha_t *ipha = (ipha_t *)iph_arg;
	int newmtu;

	/* Make a note for DAD that this address is in use */
	ire->ire_last_used_time = LBOLT_FASTPATH;

	/* Only target the IRE_LOCAL with the right zoneid. */
	ira->ira_zoneid = ire->ire_zoneid;

	/*
	 * XXX KEBE ASKS, any DTrace probes or other instrumentation that
	 * perhaps should be set?
	 */

	/*
	 * Reality check some things.
	 */
	fixed = (vxlnat_fixed_t *)ire->ire_dep_sib_next;
	vnet = fixed->vxnf_vnet;

	ASSERT3P(ire, ==, fixed->vxnf_ire);

	if (IRE_IS_CONDEMNED(ire) || vnet == NULL)
		goto detach_ire_and_bail;

	/*
	 * Not a common-case, but a possible one.  If our underlay MTU is
	 * smaller than the external MTU, it is possible that we will have a
	 * size mismatch and therefore need to either fragment at the VXLAN
	 * layer (VXLAN UDP packet sent as two or more IP fragments) OR
	 * if IPH_DF is set, send an ICMP_NEEDS_FRAGMENTATION back to the
	 * sender.  Perform the check here BEFORE we NAT the packet.
	 */
	if (vxlnat_underlay_ire == NULL) {
		/* We're mid-quiesce. Eat the packet and bail. */
		DTRACE_PROBE2(vxlnat__fixed__recv__quiescing, in6_addr_t *,
		    &fixed->vxnf_addr, uint32_t,
		    VXLAN_ID_NTOH(vnet->vxnv_vnetid));
		freemsg(mp);
	}
	ASSERT(vxlnat_underlay_ire->ire_ill != NULL);
	newmtu = vxlnat_underlay_ire->ire_ill->ill_mtu - sizeof (ipha_t) -
	    sizeof (udpha_t) - sizeof (vxlan_hdr_t) -
	    sizeof (struct ether_vlan_header);
	if ((ntohs(ipha->ipha_fragment_offset_and_flags) & IPH_DF) &&
	    ntohs(ipha->ipha_length) > newmtu) {
		icmp_frag_needed(mp, newmtu, ira);
		/* We're done.  Assume icmp_frag_needed() consumed mp. */
		return;
	}

	/*
	 * So we're here, and since we have a refheld IRE, we have a refheld
	 * fixed and vnet. Do some of what ip_input_local_v4() does (inbound
	 * checksum?  some ira checks?), but otherwise, swap the destination
	 * address as mapped in "fixed", recompute any checksums, and send it
	 * along its merry way (with a ttl decement too) to a VXLAN
	 * destination.
	 */
	mp = vxlnat_fixv4(mp, fixed, NULL, B_TRUE);
	if (mp == NULL)
		return; /* Assume it's been freed & dtraced already. */

	/*
	 * Otherwise, we're ready to transmit this packet over the vxlan
	 * socket.
	 */
	fixed->vxnf_remote = vxlnat_xmit_vxlanv4(mp, &fixed->vxnf_addr,
	    fixed->vxnf_remote, fixed->vxnf_myether, vnet);
	if (fixed->vxnf_remote == NULL) {
		/* XXX KEBE ASKS, DTrace probe here?  Or in-function? */
		DTRACE_PROBE2(vxlnat__fixed__xmitdrop,
		    in6_addr_t *, &fixed->vxnf_addr,
		    uint32_t, VXLAN_ID_NTOH(vnet->vxnv_vnetid));
	}
	return;

detach_ire_and_bail:
	/* Oh no, something's condemned.  Drop the IRE now. */
	ire->ire_dep_sib_next = NULL;
	/* Rewire IRE back to normal. */
	if (ire->ire_ipversion == IPV4_VERSION) {
		ire->ire_recvfn = ire_recv_local_v4;
		ire->ire_sendfn = ire_send_local_v4;
	} else {
		ASSERT(ire->ire_ipversion == IPV6_VERSION);
		ire->ire_recvfn = ire_recv_local_v6;
		ire->ire_sendfn = ire_send_local_v6;
	}
	VXNF_REFRELE(fixed);
	/* Pass the packet back... */
	ire->ire_recvfn(ire, mp, iph_arg, ira);
	return;
}
