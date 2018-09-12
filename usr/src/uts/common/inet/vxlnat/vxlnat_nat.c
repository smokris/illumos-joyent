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
#include <sys/ksynch.h>
#include <sys/ksocket.h>
#include <sys/sysmacros.h>
#include <sys/debug.h>
#include <sys/errno.h>

#include <inet/vxlnat.h>

/*
 * Initialized to NULL, read/write protected by vxlnat_mutex.
 * Receive functions shouldn't have to access this directly.
 */
ksocket_t vxlnat_underlay;

static void
vxlnat_closesock(void)
{
	ASSERT(MUTEX_HELD(&vxlnat_mutex));
	(void) ksocket_close(vxlnat_underlay, zone_kcred());
}

/*
 * XXX KEBE SAYS ESTABLISH ksock.
 * XXX KEBE ASKS ==> Support more than one VXLAN address?
 */
/* ARGSUSED */
int
vxlnat_vxlan_addr(in6_addr_t *underlay_ip)
{
	/* int rc; */

	mutex_enter(&vxlnat_mutex);
	/* For now, we make this a one-underlay-address-only solution. */
	if (vxlnat_underlay != NULL)
		vxlnat_closesock();
	/* rc = vxlnat_opensock(underlay_ip); */
	mutex_exit(&vxlnat_mutex);
	return (EOPNOTSUPP);
}
