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

#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <door.h>
#include <err.h>
#include <errno.h>
#include <sys/socket.h>
#include <ikedoor.h>
#include <stropts.h>

#include "defs.h"

int door_fd = -1;

static void
send_error(ike_svccmd_t cmd, uint32_t ike_err, uint32_t unix_err)
{
	ike_err_t ierr = {
		.cmd = cmd,
		.ike_err = ike_err,
		.ike_err_unix = unix_err
	};

	door_return((char *)&ierr, sizeof (ierr), NULL, 0);
}

static void
ikev2_door_server(void *cookie __unused, char *arg, size_t arglen,
    door_desc_t *descp, uint_t n_desc)
{
	ike_service_t *svc = (ike_service_t *)arg;
	ike_service_t resp = { 0 };
	size_t resplen = 0;

	if (arglen < sizeof (ike_cmd_t)) {
		/* XXX: Log */
		goto fail;
	}

	switch (svc->svc_cmd.cmd) {
	case IKE_SVC_GET_DBG:
	case IKE_SVC_SET_DBG:
	case IKE_SVC_GET_PRIV:
	case IKE_SVC_SET_PRIV:
	case IKE_SVC_GET_STATS:
	case IKE_SVC_GET_P1:
	case IKE_SVC_DEL_P1:
	case IKE_SVC_DUMP_P1S:
	case IKE_SVC_FLUSH_P1S:
	case IKE_SVC_GET_RULE:
	case IKE_SVC_NEW_RULE:
	case IKE_SVC_DEL_RULE:
	case IKE_SVC_DUMP_RULES:
	case IKE_SVC_READ_RULES:
	case IKE_SVC_WRITE_RULES:
	case IKE_SVC_GET_PS:
	case IKE_SVC_NEW_PS:
	case IKE_SVC_DEL_PS:
	case IKE_SVC_DUMP_PS:
	case IKE_SVC_READ_PS:
	case IKE_SVC_WRITE_PS:
	case IKE_SVC_DBG_RBDUMP:
	case IKE_SVC_GET_DEFS:
	case IKE_SVC_SET_PIN:
	case IKE_SVC_DEL_PIN:
	case IKE_SVC_DUMP_CERTCACHE:
	case IKE_SVC_FLUSH_CERTCACHE:
	case IKE_SVC_DUMP_GROUPS:
	case IKE_SVC_DUMP_ENCRALGS:
	case IKE_SVC_DUMP_AUTHALGS:
	case IKE_SVC_ERROR:
		break;
	}

	(void) door_return(NULL, 0, NULL, 0);

fail:
	send_error(IKE_SVC_ERROR, IKE_ERR_REQ_INVALID, 0);
}

void
ikev2_door_init(const char *path)
{
	int fd = -1;
	mode_t oldmask;

	door_fd = door_create(ikev2_door_server, NULL, 0);
	if (door_fd == -1)
		err(EXIT_FAILURE, "Cannot create door server");

	oldmask = umask(0);
	fd = open(path, O_RDWR | O_CREAT | O_EXCL, 0644);
	(void) umask(oldmask);

	if (fattach(door_fd, path) < 0) {
		if ((errno != EBUSY) || fdetach(path) < 0 ||
		    fattach(door_fd, path) < 0)
			err(EXIT_FAILURE, "Cannot attach door server");
	}
}
