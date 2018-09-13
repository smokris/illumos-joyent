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

#ifndef	_INET_VXLNAT_H
#define	_INET_VXLNAT_H

/*
 * Primitives for /dev/vxlnet.
 */

#include <sys/types.h>
#include <sys/ethernet.h>
#include <sys/netstack.h>
#include <netinet/in.h>

#ifdef __cplusplus
extern "C" {
#endif

#define	VXLNAT_PATH "/dev/vxlnat"

/*
 * Fixed-size messages for communicating with /dev/vxlnat.
 */
typedef struct vxn_msg_s {
	uint32_t vxnm_type;	/* A bit much, but good alignment this way. */
	uint8_t	vxnm_prefix;	/* Prefix-length for private address. */
	uint8_t vxnm_vnetid[3];	/* VXLAN vnetid in network order. */
	uint8_t vxnm_ether_addr[ETHERADDRL]; /* My local ethernet address. */
	uint16_t vxnm_vlanid;	/* My VLAN id. */
	in6_addr_t vxnm_public;	/* Public-facing IP. */
	/*
	 * VXLAN IP (VXLAN addr), private prefix (rule), or private address
	 * (fixed).
	 */
	in6_addr_t vxnm_private;
} vxn_msg_t;

#define	VXNM_SET_VNETID(vxnm, vnetid) \
	((vxnm)->vxnm_vnetid[0] = (((vnetid) >> 16) & 0xff),	\
	(vxnm)->vxnm_vnetid[1] = (((vnetid) >> 8) & 0xff),	\
	(vxnm)->vxnm_vnetid[2] = ((vnetid) & 0xff))
#define	VXNM_GET_VNETID(vnetid, vxnm) \
	(vnetid) = (((vxnm)->vxnm_vnetid[0] << 16) |		\
		((vxnm)->vxnm_vnetid[1] << 8) | (vxnm)->vxnm_vnetid[2]);

/* Message types. (fields not-ignored in comments) */
#define	VXNM_VXLAN_ADDR	0x1	/* type, private */
#define	VXNM_RULE	0x2	/* type, pfx, vnetid, pub, priv, eth, vlanid */
#define	VXNM_FIXEDIP	0x3	/* type, vnetid, private, public */
#define	VXNM_FLUSH	0x4	/* type */
#define	VXNM_DUMP	0x5	/* type, generates list of RULE and FIXEDIP */

#ifdef _KERNEL
extern kmutex_t vxlnat_mutex;
extern netstack_t *vxlnat_netstack;
extern int vxlnat_command(vxn_msg_t *);
extern int vxlnat_read_dump(struct uio *);
extern int vxlnat_vxlan_addr(in6_addr_t *);
#endif /* _KERNEL */

#ifdef __cplusplus
}
#endif

#endif /* _INET_VXLNAT_H */
