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
	uint8_t vxnm_vlanid[3];	/* VXLAN vnetid in network order. */
	in6_addr_t vxnm_public;	/* Public-facing IP. */
	/*
	 * VXLAN IP (VXLAN addr), private prefix (rule), or private address
	 * (fixed).
	 */
	in6_addr_t vxnm_private;
} vxn_msg_t;

#define	VXNM_SET_VLANID(vxnm, vlanid) \
	((vxnm)->vxnm_vlanid[0] = (((vlanid) >> 16) & 0xff),	\
	(vxnm)->vxnm_vlanid[1] = (((vlanid) >> 8) & 0xff),	\
	(vxnm)->vxnm_vlanid[2] = ((vlanid) & 0xff))
#define	VXNM_GET_VLANID(vlanid, vxnm) \
	(vlanid) = (((vxnm)->vxnm_vlanid[0] << 16) |		\
		((vxnm)->vxnm_vlanid[1] << 8) | (vxnm)->vxnm_vlanid[2]);

/* Message types. (fields not-ignored in comments) */
#define	VXNM_VXLAN_ADDR	0x1	/* type, private */
#define	VNXM_RULE	0x2	/* type, prefix, vlanid, public, private */
#define	VXNM_FIXEDIP	0x3	/* type, vlanid, private, public */
#define	VXNM_FLUSH	0x4	/* type */
#define	VXNM_DUMP	0x5	/* type, generates list of RULE and FIXEDIP */

#ifdef _KERNEL
extern kmutex_t vxlnat_mutex;
extern int vxlnat_command(vxn_msg_t *);
extern int vxlnat_read_dump(struct uio *);
#endif /* _KERNEL */

#ifdef __cplusplus
}
#endif

#endif /* _INET_VXLNAT_H */
