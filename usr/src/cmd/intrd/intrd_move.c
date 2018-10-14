<F28>/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */

/*
 * Copyright (c) 2005, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2018, Joyent, Inc.
 */

#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/pci_tools.h>

static int
open_dev(const char *path)
{
	char intrpath[MAXPATHLEN];

	if (snprintf(intrpath, sizeof (intrpath), "/devices/%s:intr", path) >
	    sizeof (intrpath)) {
		errno = ENAMETOOLONG;
		return (-1);
	}

	return (open(intrpath, O_RDWR));
}

int
intrmove(const char *path, int oldcpu, int ino, int newcpu, int num_ino)
{
	pcitool_intr_set_t iset = {
		.old_cpu = oldcpu,
		.ino = ino,
		.cpu_id = newcpu,
		.flags = (num_ino > 1) ? PCITOOL_INTR_FLAG_SET_GROUP : 0,
		.user_version = PCITOOL_VERSION
	};
	int fd, ret;

	if ((fd = open_dev(path)) == -1)
		return (errno);

	ret = ioctl(fd, PCITOOL_DEVICE_SET_INTR, &iset);
	(void) close(fd);
	if (ret == -1)
		return (errno);

	return (0);
}
