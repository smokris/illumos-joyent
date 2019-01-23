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
 * Writes (new rules) and reads (rule dump) go here.  So do the
 * ins/outs of reading & writing.
 */

#include <sys/ddi.h>
#include <sys/dtrace.h>
#include <sys/debug.h>
#include <sys/ksocket.h>
#include <sys/strsubr.h>
#include <inet/ip.h>
#include <inet/ipclassifier.h>
#include <inet/vxlnat_impl.h>

/*
 * These are all initialized to NULL or 0.
 *
 * If a VXNM_DUMP is requested, these get allocated/set.  vxlnat_read()
 * calls will consume them, and once delivered the last bytes read will
 * cause these to be freed and reset to NULL/0.  Cheesy, but this is a
 * one-at-a-time thing.  Protected by vxlnat_mutex.
 */
static vxn_msg_t *vxlnat_dumpbuf;
static size_t vxlnat_initial;	/* non-zero if no read yet. */
static size_t vxlnat_dumpcount;
static size_t vxlnat_dumpcurrent;

/*
 * Store per-vnet-state in AVL tree.  We could be handling 1000s or more...
 * Could split this into a hash table of AVL trees if need be.
 */
static krwlock_t vxlnat_vnet_lock;	/* Could be mutex if we use refhold. */
static avl_tree_t vxlnat_vnets;

static void vxlnat_rule_unlink(vxlnat_rule_t *);
static void vxlnat_fixed_unlink(vxlnat_fixed_t *);
/* In vxlnat_nat.c */
extern void vxlnat_remote_unlink(vxlnat_remote_t *);

/*
 * Comparison function for vnet AVL tree.
 */
static int
vxlnat_vnetid_cmp(const void *first, const void *second)
{
	uint32_t first_vnetid, second_vnetid;

	first_vnetid = ((vxlnat_vnet_t *)first)->vxnv_vnetid;
	second_vnetid = ((vxlnat_vnet_t *)second)->vxnv_vnetid;

	if (first_vnetid < second_vnetid)
		return (-1);
	if (first_vnetid > second_vnetid)
		return (1);
	return (0);
}

/*
 *
 * NOTE:  Many structures start with the form:
 *
 *	struct foo {
 *		avl_node_t node;
 *		in6_addr_t address_which_is_search_key;
 *		....
 *
 * We will use this same AVL comparison function for many of these structures.
 */
int
vxlnat_tree_plus_in6_cmp(const void *first, const void *second)
{
	in6_addr_t *firstaddr, *secondaddr;
	int ret;

	firstaddr = (in6_addr_t *)(((avl_node_t *)first) + 1);
	secondaddr = (in6_addr_t *)(((avl_node_t *)second) + 1);

	ret = memcmp(firstaddr, secondaddr, sizeof (in6_addr_t));
	if (ret > 0)
		return (1);
	if (ret < 0)
		return (-1);
	return (0);
}

/*
 * Comparison function for NAT flow.
 */
static int
vxlnat_flow_cmp_v4(const void *first, const void *second)
{
	vxlnat_flow_t *first_flow = (vxlnat_flow_t *)first;
	vxlnat_flow_t *second_flow = (vxlnat_flow_t *)second;
	uint64_t firstaddrs, secondaddrs, firstportproto, secondportproto;

	firstaddrs = first_flow->vxnfl_src._S6_un._S6_u32[3] |
	    (((uint64_t)first_flow->vxnfl_dst._S6_un._S6_u32[3]) << 32ULL);
	secondaddrs = second_flow->vxnfl_src._S6_un._S6_u32[3] |
	    (((uint64_t)second_flow->vxnfl_dst._S6_un._S6_u32[3]) << 32ULL);
	firstportproto = first_flow->vxnfl_ports |
	    (((uint64_t)first_flow->vxnfl_protocol) << 32ULL);
	secondportproto = second_flow->vxnfl_ports |
	    (((uint64_t)second_flow->vxnfl_protocol) << 32ULL);

	if (firstaddrs > secondaddrs)
		return (1);
	else if (firstaddrs < secondaddrs)
		return (-1);
	else if (firstportproto > secondportproto)
		return (1);
	else if (firstportproto < secondportproto)
		return (-1);

	return (0);
}

/*
 * Find-and-reference-hold a vnet.  If none present, create one.
 * "vnetid" MUST be in wire-order and its one byte cleared.
 */
vxlnat_vnet_t *
vxlnat_get_vnet(uint32_t vnetid, boolean_t create_on_miss)
{
	vxlnat_vnet_t *vnet, searcher;
	avl_index_t where;

	/* Cheesy, but we KNOW vxnv_vnetid is the only thing checked. */
	searcher.vxnv_vnetid = vnetid;

	rw_enter(&vxlnat_vnet_lock, create_on_miss ? RW_WRITER : RW_READER);
	vnet = (vxlnat_vnet_t *)avl_find(&vxlnat_vnets, &searcher, &where);
	if (vnet == NULL && create_on_miss) {
		vnet = kmem_zalloc(sizeof (*vnet), KM_SLEEP);
		/* KM_SLEEP means non-NULL guaranteed. */
		vnet->vxnv_refcount = 1; /* Internment reference. */
		vnet->vxnv_vnetid = vnetid;
		/* Initialize 1-1 mappings... */
		rw_init(&vnet->vxnv_fixed_lock, NULL, RW_DRIVER, NULL);
		avl_create(&vnet->vxnv_fixed_ips, vxlnat_tree_plus_in6_cmp,
		    sizeof (vxlnat_fixed_t), 0);
		/* Initialize NAT rules.  (NAT mutex is zeroed-out.) */
		list_create(&vnet->vxnv_rules, sizeof (vxlnat_rule_t), 0);

		/* Initialize NAT flows... */
		rw_init(&vnet->vxnv_flowv4_lock, NULL, RW_DRIVER, NULL);
		avl_create(&vnet->vxnv_flows_v4, vxlnat_flow_cmp_v4,
		    sizeof (vxlnat_flow_t), 0);

		/*
		 * Initialize remote VXLAN destination cache.
		 * (remotes mutex is zeroed-out.)
		 */
		avl_create(&vnet->vxnv_remotes, vxlnat_tree_plus_in6_cmp,
		    sizeof (vxlnat_remote_t), 0);

		avl_insert(&vxlnat_vnets, vnet, where);
	}
	if (vnet != NULL)
		VXNV_REFHOLD(vnet);	/* Caller's reference. */
	rw_exit(&vxlnat_vnet_lock);

	return (vnet);
}

void
vxlnat_vnet_free(vxlnat_vnet_t *vnet)
{
	/* XXX KEBE SAYS FILL ME IN */
	ASSERT0(vnet->vxnv_refcount);
	/* XXX KEBE ASKS -- assert detachment? */

	kmem_free(vnet, sizeof (*vnet));
}

static void
vxlnat_vnet_unlink_locked(vxlnat_vnet_t *vnet)
{
	ASSERT3U(vnet->vxnv_refcount, >=, 1);

	ASSERT(RW_WRITE_HELD(&vxlnat_vnet_lock));
	avl_remove(&vxlnat_vnets, vnet);
	/* XXX KEBE ASKS --> Mark as condemned? */
	
	/* Unlink all NAT rules */
	rw_enter(&vnet->vxnv_rule_lock, RW_WRITER);
	while (!list_is_empty(&vnet->vxnv_rules)) {
		/* Will decrement vnet's refcount too. */
		vxlnat_rule_unlink(
		    (vxlnat_rule_t *)list_head(&vnet->vxnv_rules));
	}
	rw_exit(&vnet->vxnv_rule_lock);
	/* XXX KEBE SAYS unlink all 1-1 mappings */
	rw_enter(&vnet->vxnv_fixed_lock, RW_WRITER);
	while (!avl_is_empty(&vnet->vxnv_fixed_ips)) {
		/* Will decrement vnet's refcount too. */
		vxlnat_fixed_unlink(
		    (vxlnat_fixed_t *)avl_first(&vnet->vxnv_fixed_ips));
	}
	rw_exit(&vnet->vxnv_fixed_lock);

	/* Unlink all remotes */
	mutex_enter(&vnet->vxnv_remote_lock);
	while (!avl_is_empty(&vnet->vxnv_remotes)) {
		/* Will decrement vnet's refcount too. */
		vxlnat_remote_unlink(
		    (vxlnat_remote_t *)avl_first(&vnet->vxnv_remotes));
	}
	mutex_exit(&vnet->vxnv_remote_lock);

	/* XXX KEBE SAYS unlink all NAT flows */

	VXNV_REFRELE(vnet);	/* Internment reference. */
}

/*
 * Assume it's refheld by the caller, so we will drop two references
 * explicitly (caller's and internment), plus free any rules.
 */
void
vxlnat_vnet_unlink(vxlnat_vnet_t *vnet)
{
	ASSERT3U(vnet->vxnv_refcount, >=, 2);
	rw_enter(&vxlnat_vnet_lock, RW_WRITER);
	vxlnat_vnet_unlink_locked(vnet);
	rw_exit(&vxlnat_vnet_lock);
	/*
	 * At this point, we've decremented the refcount by one with the
	 * unlink. Drop the caller's now.
	 */
	VXNV_REFRELE(vnet);
}

/*
 * Add a (vnetid+prefix => external) rule.
 */
static int
vxlnat_nat_rule(vxn_msg_t *vxnm)
{
	vxlnat_vnet_t *vnet;
	vxlnat_rule_t *rule;
	uint32_t vnetid;

	ASSERT(MUTEX_HELD(&vxlnat_mutex));

	/* Reserve the requested public IP for shared use. */
	if (!vxlnat_public_hold(&vxnm->vxnm_public, B_FALSE))
		return (EADDRNOTAVAIL);

	vnetid = VXLAN_ID_HTON(vxnm->vxnm_vnetid);
	vnet = vxlnat_get_vnet(vnetid, B_TRUE);
	if (vnet == NULL) {
		/* RARE case of failed allocation or other disaster. */
		vxlnat_public_rele(&vxnm->vxnm_public);
		return (ENOMEM);
	}

	/* Now we have a reference-held vnet, create a rule for it. */
	rule = kmem_alloc(sizeof (*rule), KM_SLEEP);
	/* KM_SLEEP means non-NULL guaranteed. */
	rule->vxnr_vnet = vnet;	/* vnet already refheld, remember?. */
	/*
	 * XXX KEBE ASKS, check the vxnm more carefully?
	 * Possible checks include:
	 * - 
	 */
	rule->vxnr_myaddr = vxnm->vxnm_private;
	rule->vxnr_pubaddr = vxnm->vxnm_public;
	rule->vxnr_prefix = vxnm->vxnm_prefix;
	/* For easier packet matching, keep vlanid in network order. */
	rule->vxnr_vlanid = htons(vxnm->vxnm_vlanid);
	bcopy(vxnm->vxnm_ether_addr, rule->vxnr_myether, ETHERADDRL);
	rule->vxnr_refcount = 1;	/* Internment reference. */
	list_link_init(&rule->vxnr_link);

	/* Put rule into vnet. */
	rw_enter(&vnet->vxnv_rule_lock, RW_WRITER);
	/* XXX KEBE ASKS --> Check for collisions?!? */
	list_insert_tail(&vnet->vxnv_rules, rule);
	rw_exit(&vnet->vxnv_rule_lock);

	return (0);
}

void
vxlnat_rule_free(vxlnat_rule_t *rule)
{
	ASSERT3P(rule->vxnr_vnet, ==, NULL);
	ASSERT3P(rule->vxnr_link.list_next, ==, NULL);
	ASSERT3P(rule->vxnr_link.list_prev, ==, NULL);
	ASSERT0(rule->vxnr_refcount);
	vxlnat_public_rele(&rule->vxnr_pubaddr);
	kmem_free(rule, sizeof (*rule));
}

static void
vxlnat_rule_unlink(vxlnat_rule_t *rule)
{
	vxlnat_vnet_t *vnet = rule->vxnr_vnet;

	ASSERT3P(vnet, !=, NULL);
	ASSERT(RW_WRITE_HELD(&vnet->vxnv_rule_lock));

	list_remove(&vnet->vxnv_rules, rule);
	VXNV_REFRELE(vnet);
	rule->vxnr_vnet = NULL;	/* This condemns this rule. */
	VXNR_REFRELE(rule);
}

/*
 * Find a NAT rule based on an IP address.
 */
vxlnat_rule_t *
vxlnat_rule_lookup(vxlnat_vnet_t *vnet, uint32_t *addr, boolean_t isv4)
{
	vxlnat_rule_t *rule;

	/* No IPv6 support for now... */
	if (!isv4)
		return (NULL);

	rw_enter(&vnet->vxnv_rule_lock, RW_READER);
	rule = list_head(&vnet->vxnv_rules);

	/*
	 * search for a match in the nat rules
	 * XXX investigate perf issues with with respect to list_t size
	 * XXX KEBE SAYS rewhack when we start doing IPv6 to use
	 * IN6_ARE_PREFIXEDADDR_EQUAL() and a local-variable IPv6 "ipaddr".
	 */
	while (rule != NULL) {
		ipaddr_t ipaddr;
		uint32_t netmask = 0xffffffff;
		uint8_t prefix = rule->vxnr_prefix - 96;

		/* calculate the v4 netmask */
		netmask <<= (32 - prefix);
		netmask = htonl(netmask);

		IN6_V4MAPPED_TO_IPADDR(&rule->vxnr_myaddr, ipaddr);
		/* XXX ASSERT vlanid? */
		if ((ipaddr & netmask) == (*addr & netmask)) {
			VXNR_REFHOLD(rule);
			break;
		}

		rule = list_next(&vnet->vxnv_rules, rule);
	}

	rw_exit(&vnet->vxnv_rule_lock);

	return (rule);
}

static int
vxlnat_flush(void)
{
	vxlnat_quiesce_traffic();
	vxlnat_closesock();
	/* XXX KEBE SAYS DO OTHER STATE FLUSHING TOO. */

	/* Flush out vnets. */
	rw_enter(&vxlnat_vnet_lock, RW_WRITER);
	while (!avl_is_empty(&vxlnat_vnets))
		vxlnat_vnet_unlink_locked(avl_first(&vxlnat_vnets));
	rw_exit(&vxlnat_vnet_lock);
	if (vxlnat_dumpbuf != NULL) {
		kmem_free(vxlnat_dumpbuf,
		    vxlnat_dumpcount * sizeof (vxn_msg_t));
		vxlnat_dumpbuf = NULL;
		vxlnat_initial = vxlnat_dumpcount = vxlnat_dumpcurrent = 0;
	}

	/*
	 * NOTE: No need to call vxlnat_quiesce_traffic ==> no traffic
	 * sources left!
	 */

	return (0);
}

void
vxlnat_fixed_free(vxlnat_fixed_t *fixed)
{
	ASSERT0(fixed->vxnf_refcount);

	vxlnat_public_rele(&fixed->vxnf_pubaddr);
	kmem_free(fixed, sizeof (*fixed));
}

static void
vxlnat_fixed_unlink(vxlnat_fixed_t *fixed)
{
	vxlnat_vnet_t *vnet = fixed->vxnf_vnet;
	ire_t *ire = fixed->vxnf_ire;

	ASSERT3P(vnet, !=, NULL);
	ASSERT(RW_WRITE_HELD(&vnet->vxnv_fixed_lock));

	/* Rid ourselves of the IRE now. */
	if (ire != NULL) {
		ASSERT(ire->ire_type == IRE_LOCAL);
		ASSERT3P((void *)ire->ire_dep_sib_next, ==, (void *)fixed);

		ire->ire_dep_sib_next = NULL;
		VXNF_REFRELE(fixed);	/* ire's hold on us. */
		/* Rewire IRE back to normal. */
		if (ire->ire_ipversion == IPV4_VERSION) {
			ire->ire_recvfn = ire_recv_local_v4;
			ire->ire_sendfn = ire_send_local_v4;
		} else {
			ASSERT(ire->ire_ipversion == IPV6_VERSION);
			ire->ire_recvfn = ire_recv_local_v6;
			ire->ire_sendfn = ire_send_local_v6;
		}
		ire_refrele(ire);
	}

	/* And the remote, if it's there. */
	if (fixed->vxnf_remote != NULL) {
		VXNREM_REFRELE(fixed->vxnf_remote);
		fixed->vxnf_remote = NULL;
	}

	avl_remove(&vnet->vxnv_fixed_ips, fixed);
	fixed->vxnf_vnet = NULL; /* This condemns this 1-1 mapping. */
	VXNV_REFRELE(vnet);
	VXNF_REFRELE(fixed);
}

/*
 * Add a 1-1 (vnetid+IP <==> external) rule.
 */
static int
vxlnat_fixed_ip(vxn_msg_t *vxnm)
{
	vxlnat_vnet_t *vnet;
	vxlnat_fixed_t *fixed;
	vxlnat_rule_t *rule;
	uint32_t vnetid, *addrptr;
	boolean_t private_isv4;
	avl_index_t where;
	int rc;
	ire_t *ire;
	ip_stack_t *ipst;

	/* XXX KEBE SAYS FILL ME IN. */
	ASSERT(MUTEX_HELD(&vxlnat_mutex));

	/* Reserve the requested public IP for exclusive use. */
	if (!vxlnat_public_hold(&vxnm->vxnm_public, B_TRUE))
		return (EADDRNOTAVAIL);

	vnetid = VXLAN_ID_HTON(vxnm->vxnm_vnetid);
	vnet = vxlnat_get_vnet(vnetid, B_TRUE);
	if (vnet == NULL) {
		/* RARE case of failed allocation or other disaster. */
		rc = ENOMEM;
		goto fail;
	}

	/*
	 * Cannot add a fixed IP until we have a general NAT-prefix rule,
	 * otherwise there's no default router for the prefix.
	 */
	if (IN6_IS_ADDR_V4MAPPED(&vxnm->vxnm_private)) {
		addrptr = &vxnm->vxnm_private.s6_addr32[3];
		private_isv4 = B_TRUE;
	} else {
		addrptr = &vxnm->vxnm_private.s6_addr32[0];
		private_isv4 = B_FALSE;
	}
	rule = vxlnat_rule_lookup(vnet, addrptr, private_isv4);
	if (rule == NULL) {
		VXNV_REFRELE(vnet);
		rc = EINVAL;
		goto fail;
	}
	/*
	 * Okay, we have confirmation there's an existing NAT prefix and
	 * default-router for the private-side of the fixed entry.
	 */

	fixed = kmem_zalloc(sizeof (*fixed), KM_SLEEP);
	bcopy(&rule->vxnr_myether, &fixed->vxnf_myether, ETHERADDRL);
	VXNR_REFRELE(rule);
	/* KM_SLEEP means non-NULL guaranteed. */
	fixed->vxnf_vnet = vnet; /* vnet already refheld, remember? */
	/* XXX KEBE ASKS, check the vxnm more carefully? */
	fixed->vxnf_addr = vxnm->vxnm_private;
	fixed->vxnf_pubaddr = vxnm->vxnm_public;
	fixed->vxnf_refcount = 1;	/* Internment reference. */
	fixed->vxnf_vlanid = htons(vxnm->vxnm_vlanid);

	/*
	 * Find a local-address IRE for the public address.
	 */
	ipst = vxlnat_netstack->netstack_ip;
	ire = IN6_IS_ADDR_V4MAPPED(&fixed->vxnf_pubaddr) ?
	    ire_ftable_lookup_simple_v4(fixed->vxnf_pubaddr._S6_un._S6_u32[3],
	    0, ipst, NULL) :
	    ire_ftable_lookup_simple_v6(&fixed->vxnf_pubaddr, 0, ipst, NULL);

	if (ire == NULL) {
		/*
		 * Can't find a local IRE. For now, return.
		 * XXX KEBE ASKS --> Do we instead put a new entry in
		 * there?  Or do we count on zone/netstack configuration
		 * to make sure the requested external address is there?!
		 */
		kmem_free(fixed, sizeof (*fixed));
		rc = EADDRNOTAVAIL;
		goto fail;
	}

	/*
	 * Check the IRE for appropriate properties.
	 *
	 * This may change as we implement, but for now, we MUST have an ipif
	 * (local address) for the public IP.  This can/should be on the
	 * public NIC OR on a my-netstack-only etherstub to enable
	 * instantiating redundant versions of vxlnat on other netstacks on
	 * other {zones,machines} without triggering DAD.
	 */
	if (ire->ire_type != IRE_LOCAL) {
		ire_refrele(ire);
		kmem_free(fixed, sizeof (*fixed));
		rc = EADDRNOTAVAIL;	/* XXX KEBE ASKS different errno? */
		goto fail;
	}

	/* Put the 1-1 mapping in place. */
	rw_enter(&vnet->vxnv_fixed_lock, RW_WRITER);
	if (avl_find(&vnet->vxnv_fixed_ips, fixed, &where) != NULL) {
		/* Oh crap, we have an internal IP mapped already. */
		ire_refrele(ire);
		kmem_free(fixed, sizeof (*fixed));
		rc = EEXIST;
	} else {
		avl_insert(&vnet->vxnv_fixed_ips, fixed, where);
		rc = 0;
		/*
		 * ODD USE OF POINTERS WARNING: I'm going to use
		 * ire_dep_sib_next for this IRE_LOCAL as a backpointer to
		 * this 'fixed'.  This'll allow rapid packet processing.
		 * Inspection seems to indicate that IRE_LOCAL ires NEVER use
		 * the ire_dep* pointers, so we'll use one (and independent of
		 * ip_stack_t's ips_ire_dep_lock as well).  If I'm wrong,
		 * fix it here and add a new pointer in ip.h for ire_t.
		 */
		ire->ire_dep_sib_next = (ire_t *)fixed;
		VXNF_REFHOLD(fixed);	/* ire holds us too... */
		fixed->vxnf_ire = ire;
		/* and then rewire the ire receive and send functions. */
		if (ire->ire_ipversion == IPV4_VERSION) {
			ire->ire_recvfn = vxlnat_fixed_ire_recv_v4;
			ire->ire_sendfn = vxlnat_fixed_ire_send_v4;
		} else {
			ASSERT(ire->ire_ipversion == IPV6_VERSION);
			ire->ire_recvfn = vxlnat_fixed_ire_recv_v6;
			ire->ire_sendfn = vxlnat_fixed_ire_send_v6;
		}
	}
	rw_exit(&vnet->vxnv_fixed_lock);

fail:
	if (rc != 0)
		vxlnat_public_rele(&vxnm->vxnm_public);

	return (rc);
}

static void
vxlnat_rule_to_msg(vxn_msg_t *msg, vxlnat_rule_t *rule)
{
	msg->vxnm_type = VXNM_RULE;
	msg->vxnm_vnetid = VXLAN_ID_NTOH(rule->vxnr_vnet->vxnv_vnetid);
	msg->vxnm_prefix = rule->vxnr_prefix;
	msg->vxnm_vlanid = ntohs(rule->vxnr_vlanid);
	bcopy(rule->vxnr_myether, msg->vxnm_ether_addr, ETHERADDRL);
	msg->vxnm_public = rule->vxnr_pubaddr;
	msg->vxnm_private = rule->vxnr_myaddr;
}

static void
vxlnat_fixed_to_msg(vxn_msg_t *msg, vxlnat_fixed_t *fixed)
{
	msg->vxnm_type = VXNM_FIXEDIP;
	msg->vxnm_vnetid = VXLAN_ID_NTOH(fixed->vxnf_vnet->vxnv_vnetid);
	msg->vxnm_prefix = 0;
	msg->vxnm_vlanid = ntohs(fixed->vxnf_vlanid);
	bcopy(fixed->vxnf_myether, msg->vxnm_ether_addr, ETHERADDRL);
	msg->vxnm_public = fixed->vxnf_pubaddr;
	msg->vxnm_private = fixed->vxnf_addr;
}

static int
vxlnat_dump(void)
{
	int rc = 0;
	size_t entries = 0;
	vxlnat_vnet_t *vnet;
	vxlnat_fixed_t *fixed;
	vxlnat_rule_t *rule;
	vxn_msg_t *current;

	ASSERT(MUTEX_HELD(&vxlnat_mutex));

	/*
	 * XXX KEBE SAYS setup vxlnat_dump* above.
	 * XXX KEBE SAYS If function fails for reasons that aren't "dump in
	 * progress", make sure it keeps vxlnat_dump* stuff clean
	 *
	 * NOTE: Other commands are excluded at this point, but packet
	 * processing is not.  OTOH, packet processing doesn't affect any
	 * entities we dump (at this time).  We only dump things that can be
	 * added with commands.  (So no remote VXLAN peers and no NAT flows.)
	 */

	/* Lock down things. */
	rw_enter(&vxlnat_vnet_lock, RW_READER);
	if (avl_numnodes(&vxlnat_vnets) == 0)
		goto bail;	/* Nothing to see here, move along. */

	/*
	 * This is going to be inefficient, requiring two passes through each
	 * vnet.  The first pass locks-down and counts.  Then we allocate
	 * based on the count.  The second pass copies out and unlocks.
	 */
	for (vnet = avl_first(&vxlnat_vnets); vnet != NULL;
	    vnet = AVL_NEXT(&vxlnat_vnets, vnet)) {
		rw_enter(&vnet->vxnv_fixed_lock, RW_READER);
		entries += avl_numnodes(&vnet->vxnv_fixed_ips);
		rw_enter(&vnet->vxnv_rule_lock, RW_READER);
		/* Let's hope this isn't a big number... */
		for (rule = list_head(&vnet->vxnv_rules); rule != NULL;
		    rule = list_next(&vnet->vxnv_rules, rule)) {
			entries++;
		}
		/* XXX KEBE ASKS -- other fields?!? */
	}
	if (entries == 0)
		goto bail;	/* VNETs but with no rules AND no 1-1s?!? */
	/* Don't be too agressive in allocating this. */
	vxlnat_dumpbuf = kmem_alloc(entries * sizeof (vxn_msg_t),
	    KM_NOSLEEP | KM_NORMALPRI);
	if (vxlnat_dumpbuf == NULL)
		rc = ENOMEM;	/* We still have to unlock everything. */
	current = vxlnat_dumpbuf;

	/* Second pass. */
	for (vnet = avl_first(&vxlnat_vnets); vnet != NULL;
	    vnet = AVL_NEXT(&vxlnat_vnets, vnet)) {
		/* XXX KEBE ASKS -- other fields?!? */
		for (rule = list_head(&vnet->vxnv_rules); rule != NULL;
		    rule = list_next(&vnet->vxnv_rules, rule)) {
			if (rc == 0) {
				vxlnat_rule_to_msg(current, rule);
				current++;
			}
		}
		rw_exit(&vnet->vxnv_rule_lock);
		for (fixed = avl_first(&vnet->vxnv_fixed_ips); fixed != NULL;
		    fixed = AVL_NEXT(&vnet->vxnv_fixed_ips, fixed)) {
			if (rc == 0) {
				vxlnat_fixed_to_msg(current, fixed);
				current++;
			}
		}
		rw_exit(&vnet->vxnv_fixed_lock);
	}
	vxlnat_dumpcount = vxlnat_initial = entries;
	vxlnat_dumpcurrent = 0;
	ASSERT3P((vxlnat_dumpbuf + entries), ==, current);

bail:
	rw_exit(&vxlnat_vnet_lock);
	return (rc);
}

int
vxlnat_command(vxn_msg_t *vxnm)
{
	int rc;

	switch (vxnm->vxnm_type) {
	case VXNM_VXLAN_ADDR:
		rc = vxlnat_vxlan_addr(&vxnm->vxnm_private);
		break;
	case VXNM_RULE:
		rc = vxlnat_nat_rule(vxnm);
		break;
	case VXNM_FIXEDIP:
		rc = vxlnat_fixed_ip(vxnm);
		break;
	case VXNM_FLUSH:
		rc = vxlnat_flush();
		break;
	case VXNM_DUMP:
		rc = vxlnat_dump();
		break;
	default:
		rc = EINVAL;
		break;
	}

	return (rc);
}

void
vxlnat_state_init(void)
{
	ASSERT(MUTEX_HELD(&vxlnat_mutex));
	rw_init(&vxlnat_vnet_lock, NULL, RW_DRIVER, NULL);
	avl_create(&vxlnat_vnets, vxlnat_vnetid_cmp, sizeof (vxlnat_vnet_t), 0);
	vxlnat_public_init();
	/* XXX KEBE SAYS -- more here. */
}

void
vxlnat_state_fini(void)
{
	ASSERT(MUTEX_HELD(&vxlnat_mutex));
	(void) vxlnat_flush(); /* If we fail, we're in bigger trouble anyway. */
	vxlnat_public_fini();
	avl_destroy(&vxlnat_vnets);
	rw_destroy(&vxlnat_vnet_lock);
}

int
vxlnat_read_dump(struct uio *uiop)
{
	int rc = 0;
	size_t dumpprogress = 0;

	mutex_enter(&vxlnat_mutex);

	/*
	 * Initial-case ==> dumpbuf with none delivered yet.
	 * Utter an 8-byte count.
	 */
	if (vxlnat_initial != 0 && uiop->uio_resid >= sizeof (uint64_t)) {
		uint64_t total = vxlnat_dumpcount;

		ASSERT(vxlnat_dumpbuf != NULL && vxlnat_dumpcurrent == 0);
		rc = uiomove(&total, sizeof (uint64_t), UIO_READ, uiop);
		if (rc != 0)
			goto bail;
		vxlnat_initial = 0;
	}

	/* XXX KEBE THINKS -- if no dump buffer, just return w/o data. */
	while (rc == 0 && vxlnat_dumpbuf != NULL &&
	    uiop->uio_resid >= sizeof (vxn_msg_t)) {
		rc = uiomove(vxlnat_dumpbuf + vxlnat_dumpcurrent,
		    sizeof (vxn_msg_t), UIO_READ, uiop);
		if (rc != 0) {
			/*
			 * XXX KEBE ASKS, destroy or preserve dumpstate?
			 * Fill in answer here.
			 */
			break;
		}
		vxlnat_dumpcurrent++;
		dumpprogress++;
		if (vxlnat_dumpcurrent == vxlnat_dumpcount) {
			kmem_free(vxlnat_dumpbuf,
			    vxlnat_dumpcount * sizeof (vxn_msg_t));
			vxlnat_dumpbuf = NULL;
			vxlnat_dumpcount = vxlnat_dumpcurrent = 0;
		}
	}

bail:
	/*
	 * If there's room at the end, just ignore that space for now.	Handy
	 * DTrace probe below notes amount of extra bytes..
	 */
	DTRACE_PROBE1(vxlnat__read__extrabytes, ssize_t, uiop->uio_resid);
	/* Note progress of dump with DTrace probes. */
	DTRACE_PROBE3(vxlnat__read__dumpprogress, size_t, dumpprogress, size_t,
	    vxlnat_dumpcurrent, size_t, vxlnat_dumpcount);

	mutex_exit(&vxlnat_mutex);
	return (rc);
}


/* ARGSUSED */
static boolean_t
vxlnat_vxlan_input_quiesce(ksocket_t insock, mblk_t *chain, size_t msgsize,
    int oob, void *ignored)
{
	/*
	 * Return FALSE to keep subsequent packets from coming here at all.
	 * the vxlnat_enable_traffic() below will have to call
	 * ksocket_krecv_unblock().  If a new vxlnat_underlay got created,
	 * the unblock will be a NOP.
	 */
	freemsgchain(chain);
	return (B_FALSE);
}

/* ARGSUSED */
static void
vxlnat_connrecv_drop(void *arg, mblk_t *mp, void *arg2, ip_recv_attr_t *ira)
{
	freemsg(mp);
}

/*
 * Rewire inbound-to-vxlnat traffic functions.  A NULL function pointer means
 * DO NOT REPLACE THAT ONE.
 *
 * XXX KEBE SAYS: verifyicmp not available at the moment
 */
static void
vxlnat_traffic_setting(pfirerecv_t fixed_recv4, pfiresend_t fixed_send4,
    pfirerecv_t fixed_recv6, pfiresend_t fixed_send6,
    edesc_rpf tcp_recv4, edesc_rpf tcp_recvicmp4,
    edesc_rpf tcp_recv6, edesc_rpf tcp_recvicmp6,
    edesc_rpf udp_recv4, edesc_rpf udp_recvicmp4,
    edesc_rpf udp_recv6, edesc_rpf udp_recvicmp6,
    edesc_rpf icmp_recv4, edesc_rpf icmp_recvicmp4,
    edesc_rpf icmp_recv6, edesc_rpf icmp_recvicmp6)
{
	ASSERT(MUTEX_HELD(&vxlnat_mutex));

	/* Iterate over all the vnets... */
	rw_enter(&vxlnat_vnet_lock, RW_WRITER);
	for (vxlnat_vnet_t *vnet = avl_first(&vxlnat_vnets); vnet != NULL;
	    vnet = AVL_NEXT(&vxlnat_vnets, vnet)) {
		/* First attack the 1-1s. */
		rw_enter(&vnet->vxnv_fixed_lock, RW_WRITER);
		for (vxlnat_fixed_t *fixed = avl_first(&vnet->vxnv_fixed_ips);
		    fixed != NULL;
		    fixed = AVL_NEXT(&vnet->vxnv_fixed_ips, fixed)) {
			ire_t *ire = fixed->vxnf_ire;

			/* Have the IRE functions drop for now. */
			if (ire->ire_ipversion == IPV4_VERSION) {
				if (fixed_recv4 != NULL)
					ire->ire_recvfn = fixed_recv4;
				if (fixed_send4 != NULL)
					ire->ire_sendfn = fixed_send4;
			} else {
				if (fixed_recv6 != NULL)
					ire->ire_recvfn = fixed_recv6;
				if (fixed_send6 != NULL)
					ire->ire_sendfn = fixed_send6;
			}
		}
		rw_exit(&vnet->vxnv_fixed_lock);

		/* Then attack the NAT flows. */
		rw_enter(&vnet->vxnv_flowv4_lock, RW_WRITER);
		for (vxlnat_flow_t *flow = avl_first(&vnet->vxnv_flows_v4);
		    flow != NULL; flow = AVL_NEXT(&vnet->vxnv_flows_v4, flow)) {
			conn_t *connp = flow->vxnfl_connp;

			switch (connp->conn_proto) {
			case IPPROTO_TCP:
				if (flow->vxnfl_isv4) {
					if (tcp_recv4 != NULL)
						connp->conn_recv = tcp_recv4;
					if (tcp_recvicmp4 != NULL)
						connp->conn_recvicmp =
						    tcp_recvicmp4;
				} else {
					if (tcp_recv6 != NULL)
						connp->conn_recv = tcp_recv6;
					if (tcp_recvicmp6 != NULL)
						connp->conn_recvicmp =
						    tcp_recvicmp6;
				}
				break;
			case IPPROTO_UDP:
				if (flow->vxnfl_isv4) {
					if (udp_recv4 != NULL)
						connp->conn_recv = udp_recv4;
					if (udp_recvicmp4 != NULL)
						connp->conn_recvicmp =
						    udp_recvicmp4;
				} else {
					if (udp_recv6 != NULL)
						connp->conn_recv = udp_recv6;
					if (udp_recvicmp6 != NULL)
						connp->conn_recvicmp =
						    udp_recvicmp6;
				}
				break;
			case IPPROTO_ICMP:
				ASSERT(flow->vxnfl_isv4);
				if (icmp_recv4 != NULL)
					connp->conn_recv = icmp_recv4;
				if (icmp_recvicmp4 != NULL)
					connp->conn_recvicmp = icmp_recvicmp4;
				break;
			case IPPROTO_ICMPV6:
				ASSERT(!flow->vxnfl_isv4);
				if (icmp_recv6 != NULL)
					connp->conn_recv = icmp_recv6;
				if (icmp_recvicmp6 != NULL)
					connp->conn_recvicmp = icmp_recvicmp6;
				break;
			default:
				/* XXX KEBE ASKS, panic?!? */
				ASSERT(B_FALSE);
				break;
			}

			/* Have the flow functions drop for now. */
			flow->vxnfl_connp->conn_recv = vxlnat_connrecv_drop;
			flow->vxnfl_connp->conn_recvicmp = vxlnat_connrecv_drop;
		}
		rw_exit(&vnet->vxnv_flowv4_lock);

	}
	rw_exit(&vxlnat_vnet_lock);
}

/*
 * Make all inbound packets to vxlnat black-hole or cease, to stop races.
 */
void
vxlnat_quiesce_traffic(void)
{
	ASSERT(MUTEX_HELD(&vxlnat_mutex));

	if (vxlnat_underlay != NULL) {
		/*
		 * First stop the VXLAN socket, as its packets can
		 * create new flows.
		 */
		VERIFY3U(ksocket_krecv_set(vxlnat_underlay,
		    vxlnat_vxlan_input_quiesce, NULL), ==, 0);

		/* Sleep a little here to allow stragglers through... */
		delay(drv_usectohz(500000));	/* Half a second... */
	}

	/* Quiesce all of the conns-for-nat-flows and IRE_LOCALs-for-fixed. */
	vxlnat_traffic_setting(vxlnat_fixed_recv_drop, vxlnat_fixed_send_drop,
	    vxlnat_fixed_recv_drop, vxlnat_fixed_send_drop,
	    vxlnat_connrecv_drop, vxlnat_connrecv_drop, 
	    vxlnat_connrecv_drop, vxlnat_connrecv_drop, 
	    vxlnat_connrecv_drop, vxlnat_connrecv_drop, 
	    vxlnat_connrecv_drop, vxlnat_connrecv_drop, 
	    vxlnat_connrecv_drop, vxlnat_connrecv_drop, 
	    vxlnat_connrecv_drop, vxlnat_connrecv_drop);

	/* Sleep a little here to allow stragglers through... */
	delay(drv_usectohz(500000));	/* Half a second... */
}

/*
 * Re-enable packet-processing.
 */
void
vxlnat_enable_traffic(void)
{
	ASSERT(MUTEX_HELD(&vxlnat_mutex));

	/* Reactivate public-side (conns and IRE_LOCALs). */
	vxlnat_traffic_setting(vxlnat_fixed_ire_recv_v4,
	    vxlnat_fixed_ire_send_v4, vxlnat_fixed_ire_recv_v6,
	    vxlnat_fixed_ire_send_v6,
	    vxlnat_external_tcp_v4, vxlnat_external_tcp_icmp_v4,
	    vxlnat_external_tcp_v6, vxlnat_external_tcp_icmp_v6,
	    vxlnat_external_udp_v4, vxlnat_external_udp_icmp_v4,
	    vxlnat_external_udp_v6, vxlnat_external_udp_icmp_v6,
	    vxlnat_external_icmp_v4, vxlnat_external_icmp_icmp_v4,
	    /* No ICMPv6 yet... */ NULL, NULL);

	/*
	 * THEN Activate the VXLAN socket.
	 *
	 * NOTE: If this is a newly-created vxlnat_underlay, this should
	 * be a NOP.
	 */
	VERIFY3U(ksocket_krecv_set(vxlnat_underlay, vxlnat_vxlan_input, NULL),
	    ==, 0);

	/* This too, is a NOP on a newly-created one. */
	ksocket_krecv_unblock(vxlnat_underlay);
}
