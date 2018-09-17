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
 * Copyright 2018, Joyent, Inc.
 */

#ifndef	_INET_VXLNAT_IMPL_H
#define	_INET_VXLNAT_IMPL_H

#include <inet/vxlnat.h>
#include <sys/avl.h>
#include <sys/list.h>
#include <sys/byteorder.h>
#include <sys/vxlan.h>

/*
 * XXX KEBE ASKS --> do we assume port IPPORT_VXLAN all the time?
 * IF NOT, then we need to add ports to various things here that deal
 * with the underlay network.
 *
 * NOTE:  All reference counts *include* table/tree/list/whatever internment.
 * Once an entry is removed, *_REFRELE() must be invoked, and it may or may
 * not free something.
 */

#ifdef __cplusplus
extern "C" {
#endif

/*
 * NAT RULES.  Instantiated per-vnet, write-once/read-only entries,
 * linkage/entries protected by "rule lock" outside this structure.
 */
typedef struct vxlnat_rule_s {
	list_node_t vxnr_link;
	struct vxlnat_vnet_s *vxnr_vnet; /* refheld */
	in6_addr_t vxnr_myaddr;
	in6_addr_t vxnr_pubaddr;
	uint8_t vxnr_myether[ETHERADDRL];
	uint16_t vxnr_vlanid;	/* Fabrics use this too. */
	krwlock_t vxnr_remotes_lock;
	avl_tree_t vxnr_remotes;
	uint32_t vxnr_refcount;
	uint8_t vxnr_prefix;
} vxlnat_rule_t;
#define	VXNR_REFHOLD(vxnr) {			\
	atomic_inc_32(&(vxnr)->vxnr_refcount);	\
	ASSERT((vxnr)->vxnr_refcount > 0);	\
}
#define	VXNR_REFRELE(vxnr) {					\
	ASSERT((vxnr)->vxnr_refcount > 0);			\
	membar_exit();						\
	if (atomic_dec_32_nv(&(vxnr)->vxnr_refcnt) == 0)	\
		vxlnat_vnet_free(vxnr);				\
}

/*
 * REMOTE VXLAN destinations.
 */
typedef struct vxlnat_remote_s {
	avl_node_t vxnrem_treenode;
	in6_addr_t vxnrem_addr;	/* Same prefix as one in rule. */
	in6_addr_t vxnrem_uaddr; /* Underlay VXLAN destination. */
	uint32_t vxnrem_refcount;
	uint8_t vxnrem_ether[ETHERADDRL];
} vxlnat_remote_t;
#define	VXNREM_REFHOLD(vxnrem) {			\
	atomic_inc_32(&(vxnrem)->vxnrem_refcount);	\
	ASSERT((vxnrem)->vxnrem_refcount > 0);		\
}
#define	VXNREM_REFRELE(vxnrem) {				\
	ASSERT((vxnrem)->vxnrem_refcount > 0);			\
	membar_exit();						\
	if (atomic_dec_32_nv(&(vxnrem)->vxnrem_refcnt) == 0)	\
		vxlnat_vnet_free(vxnrem);			\
}

/*
 * per-vnetid overarching structure.  AVL tree keyed by vnetid.
 * NOTE:  Could be split into vnetid-hashed buckets to split any
 * locks.
 */
typedef struct vxlnat_vnet_s {
	avl_node_t vxnv_treenode;
	kmutex_t vxnv_rule_lock;
	list_t vxnv_rules;
	/* XXX KEBE SAYS other things like flows go in here too... */
	uint32_t vxnv_refcount;
	uint32_t vxnv_vnetid;	/* Wire byteorder for less swapping on LE */
} vxlnat_vnet_t;
#define	VXNV_REFHOLD(vxnv) {			\
	atomic_inc_32(&(vxnv)->vxnv_refcount);	\
	ASSERT((vxnv)->vxnv_refcount > 0);	\
}
#define	VXNV_REFRELE(vxnv) {					\
	ASSERT((vxnv)->vxnv_refcount > 0);			\
	membar_exit();						\
	if (atomic_dec_32_nv(&(vxnv)->vxnv_refcount) == 0)	\
		vxlnat_vnet_free(vxnv);				\
}

/*
 * Endian-independent macros for rapid off-wire header reading. i.e. avoid
 * [nh]to[hn]*()
 *
 * VXLAN_ID_WIRE32(id) ==> Zero-out "reserved" bits, preserve wire-order
 * and position of vnetid.
 * VXLAN_FLAGS_WIRE32(vni) ==> Zero-out reserved bits, preserve wire-order
 * and position of flags.
 * VXLAN_F_VDI_WIRE ==> VXLAN_F_VDI, but w/o needing to swap.
 *
 * ALSO:  HTON/NTOH for kernel-makes-right interactions with userland, which
 * means shifting actual ID to/from low-24-bits of 32-bit word.
 * VXLAN_ID_HTON(id)
 * VXLAN_ID_NTOH(id)
 *
 * XXX KEBE ASKS ==> If not confusing to folks, move into sys/vxlan.h and
 * have overlay's VXLAN encap adopt them?
 */
#ifdef LITTLE_ENDIAN
#define	VXLAN_ID_WIRE32(id) ((id) & 0xFFFFFF)
#define	VXLAN_F_VDI_WIRE 0x08
#define	VXLAN_ID_HTON(id) htonl((id) << VXLAN_ID_SHIFT)
#define	VXLAN_ID_NTOH(id) (ntohl(id) >> VXLAN_ID_SHIFT)
#else	/* i.e. not-LITTLE_ENDIAN */
#define	VXLAN_ID_WIRE32(id) ((id) & 0xFFFFFF00)
#define	VXLAN_F_VDI_WIRE VXLAN_F_VDI
/* XXX KEBE ASKS, do masking here? */
#define	VXLAN_ID_HTON(id) ((id) << VXLAN_ID_SHIFT)
#define	VXLAN_ID_NTOH(id) ((id) >> VXLAND_ID_SHIFT)
#endif	/* LITTLE_ENDIAN */
#define	VXLAN_FLAGS_WIRE32(flags) ((flags) & VXLAN_F_VDI_WIRE)

extern kmutex_t vxlnat_mutex;
extern netstack_t *vxlnat_netstack;
extern int vxlnat_command(vxn_msg_t *);
extern int vxlnat_read_dump(struct uio *);
extern int vxlnat_vxlan_addr(in6_addr_t *);
extern void vxlnat_closesock(void);
extern void vxlnat_state_init(void);
extern void vxlnat_state_fini(void);

#ifdef __cplusplus
}
#endif

#endif /* _INET_VXLNAT_IMPL_H */
