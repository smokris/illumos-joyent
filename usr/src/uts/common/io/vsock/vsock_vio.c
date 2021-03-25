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
 * Copyright 2021 Joyent, Inc.
 */

/*
 * AF_VSOCK VIRTIO TRANSPORT 
 */

#include <sys/stropts.h>
#include <sys/stream.h>
#include <sys/strsubr.h>
#include <sys/modctl.h>
#include <sys/strsun.h>

#include "virtio.h"
#include "vsock.h"

static struct cb_ops vsock_vio_cb_ops = {
	.cb_rev			CB_REV,
	.cb_flags =		D_MP | D_NEW,

	.cb_open =		nulldev,
	.cb_close =		nulldev,
	.cb_strategy =		nodev,
	.cb_print =		nodev,
	.cb_dump =		nodev,
	.cb_read =		nodev,
	.cb_write =		nodev,
	.cb_ioctl =		nodev,
	.cb_devmap = 		nodev,
	.cb_mmap =		nodev,
	.cb_segmap =		nodev,
	.cb_chpoll =		nochpoll,
	.cb_prop_op =		ddi_prop_op,
	.cb_str =		NULL,
	.cb_aread =		nodev,
	.cb_awrite =		nodev,
};

statuc struct dev_ops vsock_vio_dev_ops = {
	.devo_rev =		DEVO_REV,
	.devo_refcnt = 		0,

	.devo_attach =		vsock_vio_attach,
	.devo_detach =		vsock_vio_detach,
	.devo_quiesce =		vsock_vio_quiesce,

	.devo_cb_ops =		&vsock_vio_cb_ops,

	.devo_getinfo =		NULL,
	.devo_identify =	nulldev,
	.devo_probe =		nulldev,
	.devo_reset = 		nodev,
	.devo_bus_ops =		NULL,
	.devo_power =		NULL,
};

static struct modldrv vsock_vio_modldrv = {
	.drv_modops =		&mod_driverops,
	.drv_linkinfo =		"AF_VSOCK VIRTIO transport driver",
	.drv_dev_ops =		&vsock_vio_dev_ops,
};

static struct modlinkage vsock_vio_modlinkage = {
	.ml_rev =		MODREV_1,
	.ml_linkage =		{ &vsock_vio_modldrv, NULL }
};

int
_init(void)
{
	int rc;

	rc = mod_install(&vsock_vio_modlinkage);
	return (rc);
}

int
_fini(void)
{
	int rc;

	rc = mod_remove(&vsock_vio_modlinkage);
	return (rc);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&vsock_vio_modlinkage, modinfop));
}
