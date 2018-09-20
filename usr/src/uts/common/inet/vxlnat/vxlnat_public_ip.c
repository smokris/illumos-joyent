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

#include <sys/kmem.h>
#include <sys/debug.h>
#include <inet/vxlnat_impl.h>

static kmutex_t vxlnat_public_lock;
static avl_tree_t vxlnat_public_tree;


/*
 * Entire tree contents are protected by the lock.
 *
 * Reference count works differently here.  If it's -1, it's reserved for a
 * 1-1 mapping.  If it's > 0, it's shared across multiple NAT rules.
 */
typedef struct vxlnat_public_ip_s {
	avl_node_t vxnpip_node;
	in6_addr_t vxnpip_addr;
	int vxnpip_refcount;
} vxlnat_public_ip_t;

void
vxlnat_public_init(void)
{
	/* mutex already created by being zeroed... */
	avl_create(&vxlnat_public_tree, vxlnat_tree_plus_in6_cmp,
	    sizeof (vxlnat_public_ip_t), 0);
}

void
vxlnat_public_fini(void)
{
	avl_destroy(&vxlnat_public_tree);
}

static vxlnat_public_ip_t *
vxlnat_public_create(in6_addr_t *public, avl_index_t *where,
    boolean_t exclusive)
{
	vxlnat_public_ip_t *vxnpip;

	ASSERT(MUTEX_HELD(&vxlnat_public_lock));

	vxnpip = kmem_alloc(sizeof (*vxnpip), KM_SLEEP);
	/* KM_SLEEP assures non-NULL. */
	vxnpip->vxnpip_addr = *public;
	avl_insert(&vxlnat_public_tree, vxnpip, *where);
	vxnpip->vxnpip_refcount = (exclusive) ? -1 : 1;
	return (vxnpip);
}

static void
vxlnat_public_delete(vxlnat_public_ip_t *vxnpip)
{
	ASSERT(MUTEX_HELD(&vxlnat_public_lock));
	avl_remove(&vxlnat_public_tree, vxnpip);
	kmem_free(vxnpip, sizeof (*vxnpip));
}

boolean_t
vxlnat_public_hold(in6_addr_t *public, boolean_t exclusive)
{
	vxlnat_public_ip_t *vxnpip, search;
	avl_index_t where;
	boolean_t rc;

	search.vxnpip_addr = *public;
	mutex_enter(&vxlnat_public_lock);
	vxnpip = avl_find(&vxlnat_public_tree, &search, &where);
	if (vxnpip == NULL) {
		vxnpip = vxlnat_public_create(public, &where, exclusive);
		rc = B_TRUE;
	} else {
		/*
		 * If I'm requesting exclusive, finding one is bad.
		 *
		 * If I'm not, finding one with refcnt == -1 (reserved for
		 * exclusive use) is also bad.
		 */
		if (!exclusive && (vxnpip->vxnpip_refcount != -1)) {
			vxnpip->vxnpip_refcount++;
			rc = B_TRUE;
		} else {
			rc = B_FALSE;
		}
			
	}
	mutex_exit(&vxlnat_public_lock);

	return (rc);
}

void
vxlnat_public_rele(in6_addr_t *public)
{
	vxlnat_public_ip_t *vxnpip, search;
	avl_index_t where;
	search.vxnpip_addr = *public;
	mutex_enter(&vxlnat_public_lock);
	vxnpip = avl_find(&vxlnat_public_tree, &search, &where);
	VERIFY(vxnpip != NULL);
	/*
	 * Cheesy hack -- on refcount decrement, exclusives go to -2, shareds
	 * go to N >= 0.  Always free exclusives, and 0 for shareds also means
	 * free.
	 */
	--(vxnpip->vxnpip_refcount);
	if (vxnpip->vxnpip_refcount <= 0)
		vxlnat_public_delete(vxnpip);
	mutex_exit(&vxlnat_public_lock);
}
