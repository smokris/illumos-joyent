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
#include <inet/ip.h>
#include <inet/ip6.h>
#include <inet/ip_ire.h>
#include <sys/clock_impl.h>
#include <sys/avl.h>
#include <sys/uio.h>
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
	/* refheld link, or if NULL, this rule is "condemned" and no good. */
	struct vxlnat_vnet_s *vxnr_vnet;
	in6_addr_t vxnr_myaddr;
	in6_addr_t vxnr_pubaddr;
	uint8_t vxnr_myether[ETHERADDRL];
	uint16_t vxnr_vlanid;	/* Fabrics use this too. */
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
	if (atomic_dec_32_nv(&(vxnr)->vxnr_refcount) == 0)	\
		vxlnat_rule_free(vxnr);				\
}
extern void vxlnat_rule_free(vxlnat_rule_t *);

/*
 * 1-1 IP mapping.
 */
typedef struct vxlnat_fixed_s {
	avl_node_t vxnf_treenode;
	in6_addr_t vxnf_addr;	/* XXX KEBE ASKS - must it match to a rule? */
	in6_addr_t vxnf_pubaddr; /* External IP. */
	struct vxlnat_vnet_s *vxnf_vnet;
	ire_t *vxnf_ire;	/* Should be a local IRE from the ftable. */
	struct vxlnat_remote_s *vxnf_remote;
	uint8_t vxnf_myether[ETHERADDRL];
	uint16_t vxnf_vlanid;	/* Stored in network order for quick xmit. */
	uint32_t vxnf_refcount;
	boolean_t vxnf_clear_router;	/* XXX KEBE SAYS CHEESY HACK */
} vxlnat_fixed_t;
#define	VXNF_REFHOLD(vxnf) {			\
	atomic_inc_32(&(vxnf)->vxnf_refcount);	\
	ASSERT((vxnf)->vxnf_refcount > 0);	\
}
#define	VXNF_REFRELE(vxnf) {					\
	ASSERT((vxnf)->vxnf_refcount > 0);			\
	membar_exit();						\
	if (atomic_dec_32_nv(&(vxnf)->vxnf_refcount) == 0)	\
		vxlnat_fixed_free(vxnf);			\
}
extern void vxlnat_fixed_free(vxlnat_fixed_t *);

/*
 * REMOTE VXLAN destinations.
 */
typedef struct vxlnat_remote_s {
	avl_node_t vxnrem_treenode;
	in6_addr_t vxnrem_addr;	/* Same prefix as one in rule. */
	in6_addr_t vxnrem_uaddr; /* Underlay VXLAN destination. */
	struct vxlnat_vnet_s *vxnrem_vnet;	/* Reference-held. */
	uint32_t vxnrem_refcount;
	uint8_t vxnrem_ether[ETHERADDRL];
	uint16_t vxnrem_vlan;
	/*
	 * XXX KEBE SAYS put some lifetime/usetime/etc. here
	 * so we don't keep too many of these.  Either that, or maybe
	 * convert to a qqcache or (patents expiring) ARC.
	 */
} vxlnat_remote_t;
#define	VXNREM_REFHOLD(vxnrem) {			\
	atomic_inc_32(&(vxnrem)->vxnrem_refcount);	\
	ASSERT((vxnrem)->vxnrem_refcount > 0);		\
}
#define	VXNREM_REFRELE(vxnrem) {				\
	ASSERT((vxnrem)->vxnrem_refcount > 0);			\
	membar_exit();						\
	if (atomic_dec_32_nv(&(vxnrem)->vxnrem_refcount) == 0)	\
		vxlnat_remote_free(vxnrem);			\
}
extern void vxlnat_remote_free(vxlnat_remote_t *);

/*
 * per-vnetid overarching structure.  AVL tree keyed by vnetid.
 * NOTE:  Could be split into vnetid-hashed buckets to split any
 * locks.
 */
typedef struct vxlnat_vnet_s {
	avl_node_t vxnv_treenode;
	/*
	 * 1-1 IP mappings. (1st lookup for an in-to-out packet.)
	 * Will map to SOMETHING in IP.
	 * XXX KEBE ASKS - conn_t or something else TBD?!
	 */
	krwlock_t vxnv_fixed_lock;
	avl_tree_t vxnv_fixed_ips;
	/*
	 * NAT flows. (2nd lookup for an in-to-out packet.)
	 * These are also conn_ts with outer-packet fields for out-to-in
	 * matches against a conn_t.
	 */
	krwlock_t vxnv_flow_lock;
	avl_tree_t vxnv_flows;
	/* NAT rules. (3rd lookup for an in-to-out packet.) */
	kmutex_t vxnv_rule_lock;
	list_t vxnv_rules;
	/*
	 * Internal-network remote-nodes. (only lookup for out-to-in packet.)
	 * Entries here are also refheld by 1-1s or NAT flows.
	 */
	kmutex_t vxnv_remote_lock;
	avl_tree_t vxnv_remotes;

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
extern void vxlnat_vnet_free(vxlnat_vnet_t *);

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
#ifdef _BIG_ENDIAN
#define	VXLAN_ID_WIRE32(id) ((id) & 0xFFFFFF00)
#define	VXLAN_F_VDI_WIRE VXLAN_F_VDI
/* XXX KEBE ASKS, do masking here? */
#define	VXLAN_ID_HTON(id) ((id) << VXLAN_ID_SHIFT)
#define	VXLAN_ID_NTOH(id) ((id) >> VXLAN_ID_SHIFT)
#else	/* i.e. _LITTLE_ENDIAN */
#define	VXLAN_ID_WIRE32(id) ((id) & 0xFFFFFF)
#define	VXLAN_F_VDI_WIRE 0x08
#define	VXLAN_ID_HTON(id) htonl((id) << VXLAN_ID_SHIFT)
#define	VXLAN_ID_NTOH(id) (ntohl(id) >> VXLAN_ID_SHIFT)
#endif	/* _BIG_ENDIAN */
#define	VXLAN_FLAGS_WIRE32(flags) ((flags) & VXLAN_F_VDI_WIRE)

extern kmutex_t vxlnat_mutex;
extern netstack_t *vxlnat_netstack;
extern int vxlnat_command(vxn_msg_t *);
extern int vxlnat_read_dump(struct uio *);
extern int vxlnat_vxlan_addr(in6_addr_t *);
extern void vxlnat_closesock(void);
extern void vxlnat_state_init(void);
extern void vxlnat_state_fini(void);

extern void vxlnat_public_init(void);
extern void vxlnat_public_fini(void);
extern boolean_t vxlnat_public_hold(in6_addr_t *, boolean_t);
extern void vxlnat_public_rele(in6_addr_t *);

extern int vxlnat_tree_plus_in6_cmp(const void *, const void *);

/* ire_recvfn & ire_sendfn functions for 1-1/fixed maps. */
extern void vxlnat_fixed_ire_recv_v4(ire_t *, mblk_t *, void *,
    ip_recv_attr_t *);
extern void vxlnat_fixed_ire_recv_v6(ire_t *, mblk_t *, void *,
    ip_recv_attr_t *);
extern int vxlnat_fixed_ire_send_v4(ire_t *, mblk_t *, void *,
    ip_xmit_attr_t *, uint32_t *);
extern int vxlnat_fixed_ire_send_v6(ire_t *, mblk_t *, void *,
    ip_xmit_attr_t *, uint32_t *);


extern vxlnat_vnet_t *vxlnat_get_vnet(uint32_t, boolean_t);

#ifdef __cplusplus
}
#endif

#endif /* _INET_VXLNAT_IMPL_H */
