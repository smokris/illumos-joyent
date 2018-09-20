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
 * NOTE:  THIS MUST match on both 32-bit and 64-bit compilations.
 */
typedef struct vxn_msg_s {
	uint32_t vxnm_type;	/* A bit much, but good alignment this way. */
	/* XXX KEBE ASKS, can I get away with this? */
	uint_t vxnm_vnetid:24;	/* Host-order, kernel will normalize. */
	uint_t	vxnm_prefix:8;	/* Prefix-length for private address. */
	uint16_t vxnm_vlanid;	/* My VLAN id. */
	uint8_t vxnm_ether_addr[ETHERADDRL]; /* My local ethernet address. */
	in6_addr_t vxnm_public;	/* Public-facing IP. */
	/*
	 * VXLAN IP (VXLAN addr), private prefix (rule), or private address
	 * (fixed).
	 */
	in6_addr_t vxnm_private;
} vxn_msg_t;

/* Message types. (fields not-ignored in comments) */
#define	VXNM_VXLAN_ADDR	0x1	/* type, private */
#define	VXNM_RULE	0x2	/* type, pfx, vnetid, pub, priv, eth, vlanid */
#define	VXNM_FIXEDIP	0x3	/* type, vnetid, private, public, (vlanid?) */
#define	VXNM_FLUSH	0x4	/* type */
#define	VXNM_DUMP	0x5	/* type, generates list of RULE and FIXEDIP */

#ifdef __cplusplus
}
#endif

#endif /* _INET_VXLNAT_H */
