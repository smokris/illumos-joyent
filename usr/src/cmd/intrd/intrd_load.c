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
#include <err.h>
#include <errno.h>
#include <inttypes.h>
#include <kstat.h>
#include <libcmdutils.h>
#include <libcustr.h>
#include <limits.h>
#include <priv.h>
#include <signal.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <syslog.h>
#include <unistd.h>
#include <umem.h>
#include <sys/debug.h>
#include <sys/errno.h>
#include <sys/kstat.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "intrd.h"


static void
calc_avgs(load_t *ld)
{
	double intr = (double)ld->ld_intrtotal;

	if (ld->ld_ncpu == 0) {
		ld->ld_avgnsec = 0.0;
		ld->ld_avgload = 0.0;
		return;
	}

	ld->ld_avgnsec = intr;
	ld->ld_avgload = intr / ld->ld_total;

	if (ld->ld_ncpu > 1) {
		ld->ld_avgnsec /= ld->ld_ncpu;
		ld->ld_avgload /= ld->ld_ncpu;
	}
}

static void
calc_lgrp_load(cpugrp_t *grp, load_t *ld, lgrp_id_t id)
{
	cpugrp_t *cg = grp + id;
	load_t *lgrp = LOAD_LGRP(ld, id);

	for (size_t i = 0; i < cg->cg_nchildren; i++) {
		/*
		 * The values of an lgrp load_t entry are the sums of all
		 * the children lgrps (for ld_bigint, it is the interrupt
		 * consuming the most time in any of the child lgrps) of
		 * this lgrp.  Recursively calculate any children first so
		 * their values are calculated before we calculate ours.
		 */
		calc_lgrp_load(grp, ld, cg->cg_children[i]);

		load_t *lchild = LOAD_LGRP(ld, cg->cg_children[i]);

		lgrp->ld_total += lchild->ld_total;
		lgrp->ld_intrtotal += lchild->ld_intrtotal;
		lgrp->ld_bigint = LOAD_MAXINT(lgrp, lchild);
		lgrp->ld_ncpu += lchild->ld_ncpu;
	}
	calc_avgs(lgrp);
}

static intrd_walk_ret_t
calc_load_cb(stats_t *stp, cpustat_t *cs, void *arg)
{
	load_t *load = arg;
	load_t *lcpu = LOAD_CPU(load, cs->cs_cpuid);
	ivec_t *iv;

	lcpu->ld_total = cs->cs_cpu_nsec_idle + cs->cs_cpu_nsec_user +
	    cs->cs_cpu_nsec_kernel + cs->cs_cpu_nsec_dtrace +
	    cs->cs_cpu_nsec_intr;
	lcpu->ld_ncpu = 1;

	for (iv = list_head(&cs->cs_ivecs); iv != NULL;
	    iv = list_next(&cs->cs_ivecs, iv)) {
		lcpu->ld_intrtotal += iv->ivec_time;
		if (LOAD_BIGINT_LOAD(lcpu) < iv->ivec_time)
			lcpu->ld_bigint = iv;
	}
	calc_avgs(lcpu);

	load_t *lgrp = LOAD_LGRP(load, cs->cs_lgrp);

	lgrp->ld_total += lcpu->ld_total;
	lgrp->ld_intrtotal += lcpu->ld_intrtotal;
	lgrp->ld_bigint = LOAD_MAXINT(lgrp, lcpu);
	lgrp->ld_ncpu++;

	return (INTRD_WALK_NEXT);
}

load_t *
load_calc(stats_t *stp)
{
	load_t *ld = xcalloc(max_cpu + stp->sts_nlgrp, sizeof (load_t));

	/*
	 * Calculate the load_t values for all the CPU entries first.  If one
	 * thinks of the locality topology as a tree, the leaf lgrps (ones
	 * without any child lgrps) are the ones that will directly contain
	 * CPUs (these are also the lgrp_id_t values stored in
	 * cpustat_t->cs_lgrp).  We also calculate those lgrp leaves at the same
	 * time we are calculating the per-CPU values in calc_load_cb().
	 * We can then calculate any parent lgrps in calc_lgrp_load().
	 */
	VERIFY3S(cpu_iter(stp, calc_load_cb, ld), ==, INTRD_WALK_DONE);
	calc_lgrp_load(stp->sts_lgrp, ld, 0);
	return (ld);
}

void
load_free(load_t *ld)
{
	if (ld == NULL)
		return;
	free(ld);
}
