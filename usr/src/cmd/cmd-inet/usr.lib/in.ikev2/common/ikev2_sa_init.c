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
 * Copyright (c) 2017 Joyent, Inc.
 */

#include <pthread.h>
#include <umem.h>
#include <err.h>
#include <sys/debug.h>
#include <bunyan.h>
#include <time.h>
#include "defs.h"
#include "worker.h"
#include "pkt.h"
#include "timer.h"
#include "pkcs11.h"
#include "ikev2_proto.h"
#include "ikev2_sa.h"

void
ikev2_sa_init_inbound(pkt_t *pkt)
{
}

void
ikev2_sa_init_outbound(ikev2_sa_t *i2sa)
{
}
