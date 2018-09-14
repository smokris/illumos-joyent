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

static int
vxlnat_remote_cmp(const void *first, const void *second)
{
	return (0);
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
	 * If there's room at the end, just ignore that space for now.  Handy
	 * DTrace probe below notes amount of extra bytes..
	 */
	DTRACE_PROBE1(vxlnat__read__extrabytes, ssize_t, uiop->uio_resid);
	/* Note progress of dump with DTrace probes. */
	DTRACE_PROBE3(vxlnat__read__dumpprogress, int, dumpprogress, int,
	    vxlnat_dumpcurrent, int, vxlnat_dumpcount);

	mutex_exit(&vxlnat_mutex);
	return (rc);
}

/*
 * Find-and-reference-hold a vnet.  If none present, create one.
 */
vxlnat_vnet_t *
vxlnat_get_vnet(uint32_t vnetid, boolean_t create_on_miss)
{
	vxlnat_vnet_t *vnet, searcher;
	avl_index_t where;

	/* Cheesy, but we KNOW vxnv_vnetid is the only thing checked. */
	searcher.vxnv_vnetid = vnetid;

	rw_enter(&vxlnat_vnet_lock, RW_READER);
	vnet = (vxlnat_vnet_t *)avl_find(&vxlnat_vnets, &searcher, &where);
	if (vnet == NULL && create_on_miss) {
		/* XXX KEBE SAYS FILL ME IN!!! */
	}
	rw_exit(&vxlnat_vnet_lock);

	return (vnet);
}

static void
vxlnat_vnet_free(vxlnat_vnet_t *vnet)
{
	/* XXX KEBE SAYS FILL ME IN */
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

	VXNM_GET_VNETID(vnetid, vxnm);
	vnet = vxlnat_get_vnet(vnetid, B_TRUE);
	if (vnet == NULL) {
		/*
		 * RARE case where we failed allocation or some other such
		 * problem.
		 */
		return (ENOMEM);
	}

	/* Now we have a reference-held vnet. */
	rule = kmem_alloc(sizeof (*rule), KM_SLEEP);
	if (rule == NULL) {
		rc = ENOMEM;	/* Also a memory problem. */
		goto bail;
	}

	VXNV_REFHOLD(vnet);
	rule->vxnr_vnet = vnet;
	/* XXX KEBE ASKS, check the vxnm more carefully? */
	rule->vxnr_myaddr = vxnm->vxnm_private;
	rule->vxnr_pubaddr = vxnm->vxnm_public;
	rule->vxnr_prefix = vxnm->vxnm_prefix;
	rule->vxnr_vlanid = vxnm->vxnm_vlanid;
	bcopy(vxnm->vxnm_ether_addr, rule->vxnr_myether, ETHERADDRL);
	rw_init(&rule->vxnr_remotes_lock, NULL, RW_DRIVER, NULL);
	avl_create(&rule->vxnr_remotes, vxlnat_remote_cmp,
	    sizeof (vxlnat_remote_t), 0);
	rule->vxnr_refcount = 1;	/* Internment reference. */
	list_link_init(&rule->vxnr_link);
	mutex_enter(&vnet->vxnv_rule_lock);
	list_insert_tail(&vnet->vxnv_rules, rule);
	mutex_enter(&vnet->vxnv_rule_lock);

bail:
	VXNV_REFRELE(vnet);
	return (0);
}

static int
vxlnat_flush(void)
{
	vxlnat_closesock();
	/* XXX KEBE SAYS DO OTHER STATE FLUSHING TOO. */
	return (0);
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
		/*
		 * XXX KEBE SAYS add a 1-1 (vnetid+IP <==> external) rule.
		 */
		/* rc = vxlnat_fixed_ip(vxnm); */
		rc = EOPNOTSUPP;	/* XXX KEBE SAYS NUKE ME */
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
	/* XXX KEBE SAYS -- more here. */
}

void
vxlnat_state_fini(void)
{
	ASSERT(MUTEX_HELD(&vxlnat_mutex));
	(void) vxlnat_flush(); /* If we fail, we're in bigger trouble anyway. */
	avl_destroy(&vxlnat_vnets);
	rw_destroy(&vxlnat_vnet_lock);
}
