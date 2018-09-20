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
static int vxlnat_dumpcount;
static int vxlnat_dumpcurrent;

/*
 * Store per-vnet-state in AVL tree.  We could be handling 1000s or more...
 * Could split this into a hash table of AVL trees if need be.
 */
static krwlock_t vxlnat_vnet_lock;	/* Could be mutex if we use refhold. */
static avl_tree_t vxlnat_vnets;

static void vxlnat_rule_unlink(vxlnat_rule_t *);
static void vxlnat_fixed_unlink(vxlnat_fixed_t *);

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
		/*
		 * NAT rules already initialized, because mutex and
		 * list are zeroed-out.
		 */
#ifdef notyet
		/* XXX KEBE SAYS INITIALIZE NAT flows... */
		/* XXX KEBE SAYS INITIALIZE remotes... */
		rw_init(&vnet->vxnv_remote_lock, NULL, RW_DRIVER, NULL);
		avl_create(&vnet->vxnv_remotes, vxlnat_remote_cmp,
		    sizeof (vxlnat_remote_t), 0);
#endif /* notyet */
		avl_insert(&vxlnat_vnets, vnet, where);
	}
	VXNV_REFHOLD(vnet);	/* Caller's reference. */
	rw_exit(&vxlnat_vnet_lock);

	return (vnet);
}

void
vxlnat_vnet_free(vxlnat_vnet_t *vnet)
{
	/* XXX KEBE SAYS FILL ME IN */
	ASSERT0(vnet->vnet_refcnt);
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
	mutex_enter(&vnet->vxnv_rule_lock);
	while (!list_is_empty(&vnet->vxnv_rules)) {
		/* Will decrement vnet's refcount too. */
		vxlnat_rule_unlink(
		    (vxlnat_rule_t *)list_head(&vnet->vxnv_rules));
	}
	mutex_exit(&vnet->vxnv_rule_lock);
	/* XXX KEBE SAYS unlink all 1-1 mappings */
	rw_enter(&vnet->vxnv_fixed_lock, RW_WRITER);
	while (!avl_is_empty(&vnet->vxnv_fixed_ips)) {
		/* Will decrement vnet's refcount too. */
		vxlnat_fixed_unlink(
		    (vxlnat_fixed_t *)avl_first(&vnet->vxnv_fixed_ips));
	}
	rw_exit(&vnet->vxnv_fixed_lock);

	/* XXX KEBE SAYS unlink all NAT flows */
	/* XXX KEBE SAYS unlink all remotes */

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
 * XXX KEBE SAYS add a (vnetid+prefix => external) rule.
 */
static int
vxlnat_nat_rule(vxn_msg_t *vxnm)
{
	vxlnat_vnet_t *vnet;
	vxlnat_rule_t *rule;
	uint32_t vnetid;
	int rc;

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
	/* XXX KEBE ASKS, check the vxnm more carefully? */
	rule->vxnr_myaddr = vxnm->vxnm_private;
	rule->vxnr_pubaddr = vxnm->vxnm_public;
	rule->vxnr_prefix = vxnm->vxnm_prefix;
	rule->vxnr_vlanid = vxnm->vxnm_vlanid;
	bcopy(vxnm->vxnm_ether_addr, rule->vxnr_myether, ETHERADDRL);
	rule->vxnr_refcount = 1;	/* Internment reference. */
	list_link_init(&rule->vxnr_link);

	/* Put rule into vnet. */
	mutex_enter(&vnet->vxnv_rule_lock);
	/* XXX KEBE ASKS --> Check for collisions?!? */
	list_insert_tail(&vnet->vxnv_rules, rule);
	mutex_enter(&vnet->vxnv_rule_lock);

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
	ASSERT(MUTEX_HELD(&vnet->vxnv_rule_lock));

	list_remove(&vnet->vxnv_rules, rule);
	VXNV_REFRELE(vnet);
	rule->vxnr_vnet = NULL;	/* This condemns this rule. */
	VXNR_REFRELE(rule);
}

static int
vxlnat_flush(void)
{
	vxlnat_closesock();
	/* XXX KEBE SAYS DO OTHER STATE FLUSHING TOO. */

	/* Flush out vnets. */
	rw_enter(&vxlnat_vnet_lock, RW_WRITER);
	while (!avl_is_empty(&vxlnat_vnets))
		vxlnat_vnet_unlink_locked(avl_first(&vxlnat_vnets));
	rw_exit(&vxlnat_vnet_lock);
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

	ASSERT3P(vnet, !=, NULL);
	/* XXX KEBE SAYS rwlock-writer assert... */

	avl_remove(&vnet->vxnv_fixed_ips, fixed);
	VXNV_REFRELE(vnet);
	fixed->vxnf_vnet = NULL; /* This condemns the 1-1 mapping. */
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
	uint32_t vnetid;
	avl_index_t where;
	int rc;

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

	fixed = kmem_alloc(sizeof (*fixed), KM_SLEEP);
	/* KM_SLEEP means non-NULL guaranteed. */
	fixed->vxnf_vnet = vnet; /* vnet already refheld, remember? */
	/* XXX KEBE ASKS, check the vxnm more carefully? */
	fixed->vxnf_addr = vxnm->vxnm_private;
	fixed->vxnf_pubaddr = vxnm->vxnm_public;
	fixed->vxnf_refcount = 1;	/* Internment reference. */

	/*
	 * XXX KEBE SAYS we likely need to do some ip/netstack magic at this
	 * point, but I'm not sure what that is.  It WILL, however, go here.
	 */

	/* Put the 1-1 mapping in place. */
	rw_enter(&vnet->vxnv_fixed_lock, RW_WRITER);
	if (avl_find(&vnet->vxnv_fixed_ips, fixed, &where) != NULL) {
		/* Oh crap, we have an internal IP mapped already. */
		kmem_free(fixed, sizeof (*fixed));
		rc = EEXIST;
	} else {
		avl_insert(&vnet->vxnv_fixed_ips, fixed, where);
		rc = 0;
	}
	rw_exit(&vnet->vxnv_fixed_lock);

fail:
	if (rc != 0)
		vxlnat_public_rele(&vxnm->vxnm_public);

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
		/*
		 * XXX KEBE SAYS setup vxlnat_dump* above.
		 * XXX KEBE SAYS If function fails for reasons that aren't
		 * "dump in progress", make sure it keeps vxlnat_dump* stuff
		 * clean
		 */
		/* rc = vxlnat_dump(); */
		rc = EOPNOTSUPP;	/* XXX KEBE SAYS NUKE ME */
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
	vxlnat_public_init();
	avl_destroy(&vxlnat_vnets);
	rw_destroy(&vxlnat_vnet_lock);
}

int
vxlnat_read_dump(struct uio *uiop)
{
	int rc = 0;
	int dumpprogress = 0;

	mutex_enter(&vxlnat_mutex);
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

	/*
	 * If there's room at the end, just ignore that space for now.	Handy
	 * DTrace probe below notes amount of extra bytes..
	 */
	DTRACE_PROBE1(vxlnat__read__extrabytes, ssize_t, uiop->uio_resid);
	/* Note progress of dump with DTrace probes. */
	DTRACE_PROBE3(vxlnat__read__dumpprogress, int, dumpprogress, int,
	    vxlnat_dumpcurrent, int, vxlnat_dumpcount);

	mutex_exit(&vxlnat_mutex);
	return (rc);
}
