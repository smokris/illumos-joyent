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
 * Copyright 2014 Jason King.
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <locale.h>
#include <ipsec_util.h>
#include "buf.h"
#include "defs.h"

/* Start off with invalid values until init */
static int low_random = -1;
static int high_random = -1;

static void random_high_impl(void *, size_t);
static void random_low_impl(void *, size_t);

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

	random_high_impl(&rc, sizeof (rc));
	return (rc);
}

uint64_t
random_low_64(void)
{
	uint64_t rc;

	random_low_impl(&rc, sizeof (rc));
	return (rc);
}

void
random_high_impl(void *buf, size_t nbytes)
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
random_high(buf_t *buf)
{
	buf_reset(buf);
	random_high_impl(buf->b_buf, buf->b_len);
}

static void
random_low_impl(void *buf, size_t nbytes)
{
	ssize_t rc;

	if ((rc = read(low_random, buf, nbytes)) == -1)
		err(EXIT_FAILURE, "/dev/urandom read failed");

	if (rc < nbytes) {
		errx(EXIT_FAILURE, "/dev/urandom read insufficient bytes, "
		    "%zd instead of %zu.", rc, nbytes);
	}
}

void
random_low(buf_t *buf)
{
	buf_reset(buf);
	random_low_impl(buf->b_ptr, buf->b_len);
}

extern uint32_t random_high_32(void);
extern uint16_t random_high_16(void);
extern uint8_t random_high_8(void);
extern uint32_t random_low_32(void);
extern uint16_t random_low_16(void);
extern uint8_t random_low_8(void);
