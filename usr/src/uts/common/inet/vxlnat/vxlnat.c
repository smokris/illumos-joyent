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
 * The VXLAN NAT (aka. meta-NAT).  Big-theory-comment-style cribbed from
 * overlay.
 *
 * This open-once driver opens to receive configuration over its open file,
 * and will emit configuration dumps one-full-dump-at-a-time if requested.
 * It's a driver mostly to have an in-zone process open it so the underlying
 * NAT engine can find the netstack it's using.
 *
 * --------------------
 * General Architecture
 * --------------------
 *
 * XXX KEBE SAYS FILL ME IN!
 *
 * ------------------
 * Sample Packet Flow
 * ------------------
 *
 * XXX KEBE SAYS FILL ME IN!
 *
 * ------------------
 * Netstack Awareness
 * ------------------
 *
 * The VXLAN NAT can attach to any netstack, including the global zone's.  It
 * will not run in a shared-stack zone, but those are rare in greater illumos,
 * and outright obsolete in SmartOS.  For now, only one open VXLAN NAT
 * instance is allowed, and whatever zone opens that instance has its netstack
 * employed for VXLAN NAT.
 */

#include <sys/conf.h>
#include <sys/errno.h>
#include <sys/stat.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/modctl.h>
#include <sys/policy.h>
#include <sys/types.h>
#include <sys/kmem.h>
#include <sys/param.h>
#include <sys/sysmacros.h>
#include <sys/ddifm.h>

#include <sys/netstack.h>
#include <sys/vlan.h>
#include <inet/vxlnat.h>

static dev_info_t *vxlnat_dip;

/*
 * For read/write ops only, NOT NAT engine.
 * This lock MUST be held first before any traversing of NAT engine structures
 * and/or locks.  This lock MUST NOT EVER be held by packet-processing.
 */
kmutex_t vxlnat_mutex;
netstack_t *vxlnat_netstack;

static int
vxlnat_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	if (cmd != DDI_ATTACH)
		return (DDI_FAILURE);

	if (vxlnat_dip != NULL || ddi_get_instance(dip) != 0)
		return (DDI_FAILURE);

	if (ddi_create_minor_node(dip, "vxlnat", S_IFCHR,
	    ddi_get_instance(dip), DDI_PSEUDO, 0) == DDI_FAILURE)
		return (DDI_FAILURE);

	vxlnat_dip = dip;
	return (DDI_SUCCESS);
}

/* ARGSUSED */
static int
vxlnat_getinfo(dev_info_t *dip, ddi_info_cmd_t cmd, void *arg, void **resp)
{
	int error;

	switch (cmd) {
	case DDI_INFO_DEVT2DEVINFO:
		*resp = (void *)vxlnat_dip;
		error = DDI_SUCCESS;
		break;
	case DDI_INFO_DEVT2INSTANCE:
		*resp = (void *)0;
		error = DDI_SUCCESS;
		break;
	default:
		error = DDI_FAILURE;
		break;
	}

	return (error);
}

static int
vxlnat_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	if (cmd != DDI_DETACH)
		return (DDI_FAILURE);

	ddi_remove_minor_node(dip, "vxlnat");
	vxlnat_dip = NULL;
	return (DDI_SUCCESS);
}

/* ARGSUSED */
static int
vxlnat_open(dev_t *devp, int flags, int otype, cred_t *credp)
{
	zoneid_t zoneid;
	zone_t *zone;

	if (secpolicy_ip_config(credp, B_FALSE) != 0)
		return (EPERM);

	zoneid = getzoneid();
	zone = zone_find_by_id(zoneid);
	if (zone == NULL)
		return (ENOENT);
	if ((zone->zone_flags & ZF_NET_EXCL) == 0 &&
	    getzoneid() != GLOBAL_ZONEID) {
		zone_rele(zone);
		return (EINVAL);
	}

	/*
	 * For now, just one process opens, and it can feed stuff in
	 * using SIGHUP/whatever.
	 */
	mutex_enter(&vxlnat_mutex);
	if (vxlnat_netstack != NULL) {
		mutex_exit(&vxlnat_mutex);
		return (EBUSY);
	}

	vxlnat_netstack = netstack_find_by_zoneid(zoneid);
	if (vxlnat_netstack == NULL) {
		mutex_exit(&vxlnat_mutex);
		zone_rele(zone);
		return (ESRCH);
	}

	/* XXX KEBE SAYS FILL ME IN -- initialization! */

	mutex_exit(&vxlnat_mutex);
	zone_rele(zone);
	return (0);
}

/* ARGSUSED */
static int
vxlnat_close(dev_t dev, int flags, int otype, cred_t *credp)
{
	/* XXX KEBE SAYS FILL ME IN -- teardown! */

	mutex_enter(&vxlnat_mutex);
	VERIFY(vxlnat_netstack != NULL);
	netstack_rele(vxlnat_netstack);
	vxlnat_netstack = NULL;
	mutex_exit(&vxlnat_mutex);
	return (0);
}

/* ARGSUSED */
static int
vxlnat_read(dev_t dev, struct uio *uiop, cred_t *credp)
{
	if (secpolicy_ip_config(credp, B_FALSE) != 0)
		return (EPERM);

	/* XXX KEBE SAYS FILL ME IN -- more?!? */

	/* All the state is in vxlnat_rules.c, so do the work there. */
	return (vxlnat_read_dump(uiop));
}

/* ARGSUSED */
static int
vxlnat_write(dev_t dev, struct uio *uiop, cred_t *credp)
{
	vxn_msg_t one;
	int error;

	if (secpolicy_ip_config(credp, B_FALSE) != 0)
		return (EPERM);

	while (uiop->uio_resid >= sizeof (one)) {
		/* We're not seekable, stop growing offsets now. */
		uiop->uio_loffset = 0;
		error = uiomove(&one, sizeof (one), UIO_WRITE, uiop);
		if (error != 0)
			return (error);

		error = vxlnat_command(&one);
		/*
		 * If the rule is misformed, etc., everything after is
		 * ignored. Since we have one supported consumer, it's
		 * okay, just as long as random entity doesn't panic
		 * the kernel.
		 */
		if (error != 0)
			return (error);
	}

	/*
	 * If there's garbage at the end, consume and discard for now.  Handy
	 * DTrace probe below notes amount of garbage.
	 */
	DTRACE_PROBE1(vxlnat__write__garbage, ssize_t, uiop->uio_resid);
	return (uiop->uio_resid == 0 ? 0 :
	    uiomove(&one, uiop->uio_resid, UIO_WRITE, uiop));
}

static struct cb_ops vxlnat_cbops = {
	vxlnat_open,		/* cb_open */
	vxlnat_close,		/* cb_close */
	nodev,			/* cb_strategy */
	nodev,			/* cb_print */
	nodev,			/* cb_dump */
	vxlnat_read,		/* cb_read */
	vxlnat_write,		/* cb_write */
	nodev,			/* cb_ioctl */
	nodev,			/* cb_devmap */
	nodev,			/* cb_mmap */
	nodev,			/* cb_segmap */
	nochpoll,		/* cb_chpoll */
	ddi_prop_op,		/* cb_prop_op */
	NULL,			/* cb_stream */
	D_MP,			/* cb_flag */
	CB_REV,			/* cb_rev */
	nodev,			/* cb_aread */
	nodev,			/* cb_awrite */
};

static struct dev_ops vxlnat_dev_ops = {
	DEVO_REV,		/* devo_rev */
	0,			/* devo_refcnt */
	vxlnat_getinfo,		/* devo_getinfo */
	nulldev,		/* devo_identify */
	nulldev,		/* devo_probe */
	vxlnat_attach,		/* devo_attach */
	vxlnat_detach,		/* devo_detach */
	nulldev,		/* devo_reset */
	&vxlnat_cbops,		/* devo_cb_ops */
	NULL,			/* devo_bus_ops */
	NULL,			/* devo_power */
	ddi_quiesce_not_supported	/* devo_quiesce */
};

static struct modldrv vxlnat_modldrv = {
	&mod_driverops,
	"VXLAN NAT Control Driver",
	&vxlnat_dev_ops
};

static struct modlinkage vxlnat_linkage = {
	MODREV_1,
	&vxlnat_modldrv
};

static int
vxlnat_init(void)
{
	/* XXX KEBE SAYS FILL ME IN. */
	return (DDI_SUCCESS);
}

static void
vxlnat_fini(void)
{
}

int
_init(void)
{
	int err;

	if ((err = vxlnat_init()) != DDI_SUCCESS)
		return (err);

	err = mod_install(&vxlnat_linkage);
	if (err != DDI_SUCCESS) {
		vxlnat_fini();
		return (err);
	}

	return (0);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&vxlnat_linkage, modinfop));
}

int
_fini(void)
{
	int err;

	err = mod_remove(&vxlnat_linkage);
	if (err != 0)
		return (err);

	vxlnat_fini();
	return (0);
}
