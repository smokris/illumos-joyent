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
 * Copyright 2020 Joyent, Inc.
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <inet/ip.h>
#include <inet/tcp_impl.h>
#include <inet/udp_impl.h>

#include <inet/vxlnat_impl.h>

/*
 * Functions for handling conn_t AND for new conn_t receive-side functions
 * so we can exploit ipclassifier for NAT flows.
 */

void
vxlnat_external_tcp_v4(void *arg, mblk_t *mp, void *arg2, ip_recv_attr_t *ira)
{
	mblk_t *newmp;
	in6_addr_t *overlay_dst;
#ifdef NOTYET
	vxlnat_remote_t *remote;
#endif /* NOTYET */
	uint8_t *myether;
	vxlnat_vnet_t *vnet;
	conn_t * connp = (conn_t *)arg;
	vxlnat_flow_t *flow = (vxlnat_flow_t *)connp->conn_priv;

	if (flow == NULL) {
		freemsg(mp);
		return;
	}

	/* vxlnat_fixv4 will consume mp so don't attempt to free it again */
	if ((newmp = vxlnat_fixv4(mp, NULL, flow, B_TRUE)) == NULL)
		return;

#ifdef NOTYET
	remote = flow->vxnfl_remote;
#endif /* NOTYET */

	VXNFL_REFHOLD(flow);
	overlay_dst = &flow->vxnfl_src;
	myether = flow->vxnfl_rule->vxnr_myether;
	vnet = flow->vxnfl_rule->vxnr_vnet;

	(void) vxlnat_xmit_vxlanv4(newmp, overlay_dst, NULL,
	    myether, vnet);

	VXNFL_REFRELE(flow);
}

void
vxlnat_external_tcp_v6(void *arg, mblk_t *mp, void *arg2, ip_recv_attr_t *ira)
{
	/* XXX KEBE SAYS FOR NOW, drop. */
	freemsg(mp);
}

void
vxlnat_external_tcp_icmp_v4(void *arg, mblk_t *mp, void *arg2,
    ip_recv_attr_t *ira)
{
	/* XXX KEBE SAYS FOR NOW, drop. */
	freemsg(mp);
}

void
vxlnat_external_tcp_icmp_v6(void *arg, mblk_t *mp, void *arg2,
    ip_recv_attr_t *ira)
{
	/* XXX KEBE SAYS FOR NOW, drop. */
	freemsg(mp);
}

void
vxlnat_external_udp_v4(void *arg, mblk_t *mp, void *arg2, ip_recv_attr_t *ira)
{
	/* XXX KEBE SAYS FOR NOW, drop. */
	freemsg(mp);
}

void
vxlnat_external_udp_v6(void *arg, mblk_t *mp, void *arg2, ip_recv_attr_t *ira)
{
	/* XXX KEBE SAYS FOR NOW, drop. */
	freemsg(mp);
}

void
vxlnat_external_udp_icmp_v4(void *arg, mblk_t *mp, void *arg2,
    ip_recv_attr_t *ira)
{
	/* XXX KEBE SAYS FOR NOW, drop. */
	freemsg(mp);
}

void
vxlnat_external_udp_icmp_v6(void *arg, mblk_t *mp, void *arg2,
    ip_recv_attr_t *ira)
{
	/* XXX KEBE SAYS FOR NOW, drop. */
	freemsg(mp);
}

void
vxlnat_external_icmp_v4(void *arg, mblk_t *mp, void *arg2, ip_recv_attr_t *ira)
{
	/* XXX KEBE SAYS FOR NOW, drop. */
	freemsg(mp);
}

void
vxlnat_external_icmp_icmp_v4(void *arg, mblk_t *mp, void *arg2,
    ip_recv_attr_t *ira)
{
	/* XXX KEBE SAYS FOR NOW, drop. */
	freemsg(mp);
}

boolean_t
vxlnat_new_conn(vxlnat_flow_t *flow)
{
	conn_t *connp;
	uint16_t new_lport;
	uint8_t protocol = flow->vxnfl_protocol;
	int rc, error, ntries = 3;

	/*
	 * XXX KEBE SAYS -- Use KM_NORMALPRI because we're likely in interrupt
	 * context when we call this function.  If ipcl_conn_create() becomes
	 * a problem even with these flags, we may need to go asynchronous.
	 * XXX KEBE ALSO SAYS -- See TCP's handling of new inbound
	 * connections.
	 */
	switch (protocol) {
	case IPPROTO_TCP:
	case IPPROTO_UDP:
	case IPPROTO_ICMP:
		/* case IPPROTO_ICMP6: */
		break;
	default:
		return (B_FALSE);
	}
	connp = ipcl_conn_create(IPCL_IPCCONN, KM_NOSLEEP | KM_NORMALPRI,
	    vxlnat_netstack);
	if (connp == NULL)
		return (B_FALSE);

	/*
	 * XXX KEBE SAYS FILL IN ALL SORTS OF conn_t STUFF HERE.
	 * Draw inspiration from iptun_conn_create, but also include
	 * protocol-specific thingies.
	 *
	 * NOTE: As of right this moment, I'm imagining that for
	 * inside-to-outside, conn_ip_output() will NOT be used, but rather
	 * ire_forward_recv_v*() will be, not unlike the fixed/1-1 path, and
	 * that the conn_t's *receive-side* features are the only ones to be
	 * used.
	 *
	 * Also, like UDP, there will be no verifyicmp method assigned.
	 * (Oddly, iptun does this, but it always returns true. Maybe that's a
	 * bug in iptun?)
	 */

	/* connp->conn_flags |= .... */
	connp->conn_priv = flow;  /* XXX is this a problem for freeing? */

	/*
	 * XXX KEBE SAYS Don't worry about conn_ixa FOR NOW, but maybe
	 * fill it in for use later?
	 */

	/*
	 * ALWAYS set this to GLOBAL_ZONEID.  We check at open() for
	 * a non-exclusive zone open (we disallow it), and for exclusive-
	 * stack zones, we want IP thinking (correctly) we own the netstack.
	 */
	connp->conn_zoneid = GLOBAL_ZONEID;
	/*
	 * cred_t dance is because we may be getting this straight from
	 * interrupt context.
	 */
	connp->conn_cred = zone_get_kcred(netstack_get_zoneid(vxlnat_netstack));
	connp->conn_cpid = NOPID;

	ASSERT(connp->conn_ref == 1);

	connp->conn_family = flow->vxnfl_isv4 ? AF_INET : AF_INET6;
	connp->conn_ipversion = flow->vxnfl_isv4 ? IPV4_VERSION : IPV6_VERSION;

	CONN_INC_REF(connp);	/* For the following... */
	flow->vxnfl_connp = connp;

	/* XXX KEBE SAYS Assume the right thing v4/v6-wise happens for now. */
	connp->conn_laddr_v6 = flow->vxnfl_rule->vxnr_pubaddr;
	connp->conn_faddr_v6 = flow->vxnfl_dst;

	/*
	* NOTE:  conn_ports puts them in foreign/local order. This makes sense
	* when optimizing for inbound lookup (source-port == first-two-bytes
	* == foreign on inbound packets).
	* We create vxnfl_ports from the first OUTBOUND PACKET, because we
	* optimize for outbound lookup of flows (source-port == first-two-bytes
	* == LOCAL on outbound packets).
	*
	* We therefore need to swap the two ports when populating the conn_t.
	* (XXX KEBE SAYS we may need to NOT do this for non-TCP/UDP protocols
	* like ICMP...)
	*/
	connp->conn_lport = VXNFL_SPORT(flow->vxnfl_ports);
	connp->conn_fport = VXNFL_DPORT(flow->vxnfl_ports);
	connp->conn_proto = protocol;

	/* XXX KEBE ASKS INSERT HERE? */
	do {

		switch (protocol) {
		case IPPROTO_TCP: {
			tcp_stack_t *tcps = vxlnat_netstack->netstack_tcp;
			tcp_t dummy = {.tcp_tcps = tcps, .tcp_connp = connp};

			/* Fill in with TCP-specific recv/recvicmp. */
			if (flow->vxnfl_isv4) {
				connp->conn_recv = vxlnat_external_tcp_v4;
				connp->conn_recvicmp =
				    vxlnat_external_tcp_icmp_v4;
			} else {
				connp->conn_recv = vxlnat_external_tcp_v6;
				connp->conn_recvicmp =
				    vxlnat_external_tcp_icmp_v6;
			}
			/* And set new_lport. */
			new_lport = tcp_update_next_port(
			    tcps->tcps_next_port_to_try, &dummy, B_TRUE);
			break;
		}
		case IPPROTO_UDP: {
			udp_stack_t *udps = vxlnat_netstack->netstack_udp;
			udp_t dummy = {.udp_us = udps, .udp_connp = connp };

			/* Fill in with UDP-specific recv/recvicmp. */
			if (flow->vxnfl_isv4) {
				connp->conn_recv = vxlnat_external_udp_v4;
				connp->conn_recvicmp =
				    vxlnat_external_udp_icmp_v4;
			} else {
				connp->conn_recv = vxlnat_external_udp_v6;
				connp->conn_recvicmp =
				    vxlnat_external_udp_icmp_v6;
			}
			/* And set new_lport. */
			new_lport = udp_update_next_port(&dummy,
			    udps->us_next_port_to_try, B_TRUE);
			break;
		}
		case IPPROTO_ICMP: {
			/* NOTE:  Only an IPv4 version of this is needed. */
			connp->conn_recv = vxlnat_external_icmp_v4;
			connp->conn_recv = vxlnat_external_icmp_icmp_v4;
			/*
			 * XXX KEBE SAYS -- I don't think we can tell the real
			 * IP code to bind an ICMP socket to anything beyond
			 * the addresses.  But also we allow multiple ICMP
			 * conn_ts, which could mean duplicate packets.  :-/
			 */
			new_lport = 0;
			break;
		}
		default:
			/* Should never reach here... */
			cmn_err(CE_PANIC, "vxnfl_protocol corruption!");
		}
		connp->conn_lport = new_lport;

		rc = ipcl_conn_insert(connp);
		switch (rc) {
		case 0:
			break;
		case EADDRINUSE:
			/* Try rewhacking the ports if we can. */
			switch (protocol) {
			case IPPROTO_TCP:
			case IPPROTO_UDP:
				/* Try again... */
				break;
			default:
				/* Give up now. */
				ntries = 1;
				break;
			}
			break;
		default:
			/* GET OUT, NOW! */
			DTRACE_PROBE1(vxlnat__new__conn__badins, int, rc);
			ntries = 1;
			break;
		}
	} while (rc != 0 && --ntries > 0);

	if (rc != 0) {
		/* Trash this conn. */
		DTRACE_PROBE3(vxlnat__new__conn__collision, int, rc,
		    conn_t *, connp, vxlnat_flow_t *, flow);
		CONN_DEC_REF(connp);
		CONN_DEC_REF(connp);
		/*
		 * XXX KEBE ASKS Anything else?  Last CONN_DEC_REF should
		 * trigger destroy.
		 */
		flow->vxnfl_connp = NULL;
		return (B_FALSE);
	}

	/* conn_connect requires we hold the mutex */
	mutex_enter(&connp->conn_lock);
	error = conn_connect(connp, NULL, IPDF_VERIFY_DST);
	mutex_exit(&connp->conn_lock);
	if (error != 0) {
		/*
		 * XXX MIKE how do we cleanup after this?
		 * This will store a bad connp in the flow until fixed
		 */
		DTRACE_PROBE1(vxlnat__mike__conn__connect__failure,
		    conn_t *, connp);
		return (B_FALSE);
	}

	return (B_TRUE);
}

void
vxlnat_activate_conn(vxlnat_flow_t *flow)
{
	conn_t *connp = flow->vxnfl_connp;

	mutex_enter(&connp->conn_lock);
	connp->conn_state_flags &= ~CONN_INCIPIENT;
	mutex_exit(&connp->conn_lock);
	/* XXX KEBE ASKS OR INSERT HERE? */
}

#ifdef notyet
void
vxlnat_deactivate_conn(vxlnat_flow_t *flow)
{
	conn_t *connp = flow->vxnfl_connp;

	ip_quiesce_conn(connp);
	/* XXX KEBE ASKS ipcl_hash_remove()? */
}
#endif
