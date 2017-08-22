/*
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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright 2017 Jason King.
 * Copyright (c) 2017 Joyent, Inc.
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <locale.h>
#include <ipsec_util.h>
#include "random.h"
#include "defs.h"

/* Start off with invalid values until init */
static int low_random = -1;
static int high_random = -1;

void
random_init(void)
{
	if ((low_random = open("/dev/urandom", 0)) == -1)
		err(EXIT_FAILURE, "/dev/urandom open failed");

	if ((high_random = open("/dev/random", 0)) == -1)
		err(EXIT_FAILURE, "/dev/random open failed");
}

uint64_t
random_high_64(void)
{
	uint64_t rc;

	random_high(&rc, sizeof (rc));
	return (rc);
}

uint64_t
random_low_64(void)
{
	uint64_t rc;

	random_low(&rc, sizeof (rc));
	return (rc);
}

void
random_high(void *buf, size_t nbytes)
{
	ssize_t rc;

	if ((rc = read(high_random, buf, nbytes)) == -1)
		err(EXIT_FAILURE, "/dev/random read failed");

	if (rc < nbytes) {
		errx(EXIT_FAILURE, "/dev/random read insufficient bytes, "
		    "%zd instead of %zu.", rc, nbytes);
	}
}

void
random_low(void *buf, size_t nbytes)
{
	ssize_t rc;

	if ((rc = read(low_random, buf, nbytes)) == -1)
		err(EXIT_FAILURE, "/dev/urandom read failed");

	if (rc < nbytes) {
		errx(EXIT_FAILURE, "/dev/urandom read insufficient bytes, "
		    "%zd instead of %zu.", rc, nbytes);
	}
}

extern uint32_t random_high_32(void);
extern uint16_t random_high_16(void);
extern uint8_t random_high_8(void);
extern uint32_t random_low_32(void);
extern uint16_t random_low_16(void);
extern uint8_t random_low_8(void);
