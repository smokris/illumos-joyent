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

#define __EXTENSIONS__

#include <err.h>
#include <errno.h>
#include <inttypes.h>
#include <kstat.h>
#include <libcustr.h>
#include <limits.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <syslog.h>
#include <unistd.h>
#include <umem.h>
#include <sys/debug.h>
#include <sys/errno.h>
#include <sys/kstat.h>

#include "intrd.h"

struct count_info {
	size_t	ci_ncpuinfo;
	size_t	ci_ncpu;
	size_t	ci_nivec;
};

struct read_info {
	cpustat_t **ri_cpu;
	size_t ri_ncpu;
	ivec_t **ri_ivec;
	size_t ri_nivec;
	size_t ri_ivecalloc;
	boolean_t ri_changed;
};

enum {
	KITER_NEXT = 0,
	KITER_DONE,
	KITER_STOP
};


static umem_cache_t *ivec_cache;
static umem_cache_t *cpustat_cache;
static umem_cache_t *stats_cache;

typedef int (*kstat_itercb_t)(kstat_ctl_t *restrict, kstat_t *restrict,
    void *restrict);
static int kstat_iter(kstat_ctl_t *restrict, kstat_itercb_t, void *restrict);

static int count_kstats(kstat_ctl_t *restrict, kstat_t *restrict, void *);
static int get_cpuinfo(kstat_ctl_t *restrict, kstat_t *restrict,
    void *restrict);
static int get_cpu(kstat_ctl_t *restrict, kstat_t *restrict, void *restrict);
static int get_ivecs(kstat_ctl_t *restrict, kstat_t *restrict, void *restrict);
static boolean_t build_lgrp_tree(stats_t *);

static void consolidate_ivecs(ivec_t **restrict, size_t *restrict);
static void set_timerange(stats_t *, cpustat_t **, size_t, ivec_t **, size_t);
static boolean_t getstat_tooslow(stats_t *, uint_t, double);
static boolean_t stats_differ(const stats_t *s1, const stats_t *s2);

static boolean_t ivec_shared_intr(const ivec_t *, const ivec_t *);
static boolean_t ivec_shared_msi(const ivec_t *, const ivec_t *);
static int ivec_cmp_msi(const void *, const void *);

static stats_t *stats_new(void);

stats_t *
stats_get(const config_t *restrict cfg, kstat_ctl_t *restrict kcp,
    uint_t interval)
{
	static struct count_info ci = { 0 };
	static boolean_t first = B_TRUE;

	stats_t *sts = NULL;
	kstat_t *ksp;
	kid_t kid;
	struct read_info read_info = { 0 };
	size_t i, j;

	if ((kid = kstat_chain_update(kcp)) == -1) {
		if (errno == EAGAIN)
			return (NULL);
		err(EXIT_FAILURE, "failed to update kstat chain");
	}

	if (first || kid != 0) {
		(void) memset(&ci, 0, sizeof (ci));
		(void) kstat_iter(kcp, count_kstats, &ci);

		(void) printf("count: cpuinfo %zu cpu %zu ivec: %zu\n",
		    ci.ci_ncpuinfo, ci.ci_ncpu, ci.ci_nivec);

		if (ci.ci_ncpuinfo != ci.ci_ncpu) {
			(void) printf("CPU totals mismatch: "
			    "cpuinfo: %zu cpu: %zu\n",
			    ci.ci_ncpuinfo, ci.ci_ncpu);
			return (NULL);
		}
		first = B_FALSE;
	}

	read_info.ri_cpu = xcalloc(max_cpu, sizeof (cpustat_t *));

	read_info.ri_ivec = xcalloc(ci.ci_nivec, sizeof (ivec_t *));
	read_info.ri_ivecalloc = ci.ci_nivec;

	kstat_iter(kcp, get_cpuinfo, &read_info);
	if (read_info.ri_changed)
		goto fail;

	kstat_iter(kcp, get_cpu, &read_info);
	if (read_info.ri_changed)
		goto fail;

	kstat_iter(kcp, get_ivecs, &read_info);
	if (read_info.ri_changed)
		goto fail;


	sts = stats_new();

	set_timerange(sts, read_info.ri_cpu, max_cpu, read_info.ri_ivec,
	    read_info.ri_nivec);

	if (getstat_tooslow(sts, interval, cfg->cfg_tooslow)) {
		goto fail;
	}

	/*
	 * Move the cpustat data into sts.  Since read_info.ri_cpu is
	 * indexed by CPU ID, we can merely move it to sts_cpu_byid.
	 * sts->sts_cpu is merely all the present and on-line CPUs.  We
	 * iterate by CPU id, so sts->sts_cpu ends up sorted by CPU id without
	 * needing to do an additional sort.
	 */
	sts->sts_cpu = xcalloc(read_info.ri_ncpu, sizeof (cpustat_t *));
	sts->sts_ncpu = read_info.ri_ncpu;
	sts->sts_cpu_byid = read_info.ri_cpu;
	for (i = j = 0; i < max_cpu; i++) {
		if (sts->sts_cpu_byid[i] != NULL)
			sts->sts_cpu[j++] = sts->sts_cpu_byid[i];
	}
	read_info.ri_cpu = NULL;
	read_info.ri_ncpu = 0;

	/*
	 * Combine any shared or grouped interrupts before assigning
	 * to cpustat_t's.
	 */
	consolidate_ivecs(read_info.ri_ivec, &read_info.ri_nivec);

	/*
	 * Sort by instance.  This will mean as we add them to their respective
	 * cpustat_t's, the interrupts will be ordered by instance.  Keeping
	 * the list sorted by instance simplifies comparisons when doing
	 * diffs or when combining diffs.
	 */
	qsort(read_info.ri_ivec, read_info.ri_nivec, sizeof (ivec_t *),
	    ivec_cmp_id);

	sts->sts_ivecs = xcalloc(read_info.ri_nivec, sizeof (ivec_t *));
	bcopy(read_info.ri_ivec, sts->sts_ivecs,
	    read_info.ri_nivec * sizeof (ivec_t *));
	sts->sts_nivecs = read_info.ri_nivec;

	/* Assign interrupts to their corresponding cpustat_t */
	for (i = 0; i < sts->sts_nivecs; i++) {
		ivec_t *ivp = sts->sts_ivecs[i];
		cpustat_t *cs = sts->sts_cpu_byid[ivp->ivec_cpuid];

		list_insert_tail(&cs->cs_ivecs, ivp);
		cs->cs_nivecs++;
	}

	free(read_info.ri_ivec);
	read_info.ri_ivec = NULL;
	read_info.ri_nivec = read_info.ri_ivecalloc = 0;

	if (!build_lgrp_tree(sts))
		goto fail;

	return (sts);

fail:
	printf("%s fail\n", __func__);

	for (size_t i = 0; i < max_cpu; i++)
		cpustat_free(read_info.ri_cpu[i]);
	free(read_info.ri_cpu);

	for (size_t i = 0; i < read_info.ri_nivec; i++)
		ivec_free(read_info.ri_ivec[i]);
	free(read_info.ri_ivec);

	stats_free(sts);
	return (NULL);
}

static boolean_t
build_lgrp_tree(stats_t *st)
{
	lgrp_cookie_t cookie;
	int nlgrp;

	cookie = lgrp_init(LGRP_VIEW_OS);
	VERIFY(cookie != LGRP_COOKIE_NONE);

	if ((nlgrp = lgrp_nlgrps(cookie)) == -1) {
		VERIFY0(lgrp_fini(cookie));
		return (B_FALSE);
	}

	if (nlgrp == 0) {
		VERIFY0(lgrp_fini(cookie));
		return (B_TRUE);
	}

	st->sts_lgrp = xcalloc(nlgrp, sizeof (cpugrp_t));
	st->sts_nlgrp = (size_t)nlgrp;

	/*
	 * If we ever have systems so large that these sizes pose a problem,
	 * this whole application will likely need to be rewritten or discarded.
	 */
	processorid_t cpuids[max_cpu];
	lgrp_id_t lgrpids[nlgrp];

	for (lgrp_id_t lgrpid = 0; lgrpid < nlgrp; lgrpid++) {
		cpugrp_t *cg = &st->sts_lgrp[lgrpid];

		cg->cg_id = lgrpid;

		bzero(lgrpids, nlgrp * sizeof (lgrp_id_t));
		int nkids = lgrp_children(cookie, lgrpid, lgrpids, nlgrp);
		if (nkids == -1)
			goto fail;

		cg->cg_nchildren = (size_t)nkids;
		if (nkids > 0) {
			cg->cg_children = xcalloc(nkids, sizeof (lgrp_id_t));
			bcopy(lgrpids, cg->cg_children,
			    nkids * sizeof (lgrp_id_t));
		}

		for (int i = 0; i < nkids; i++) {
			lgrp_id_t childid = cg->cg_children[i];
			cpugrp_t *child = &st->sts_lgrp[childid];
			child->cg_parent = lgrpid;
		}

		bzero(cpuids, max_cpu * sizeof (processorid_t));
		int ncpu = lgrp_cpus(cookie, lgrpid, cpuids, max_cpu,
		    LGRP_CONTENT_DIRECT);

		if (ncpu == -1)
			goto fail;

		for (int i = 0; i < ncpu; i++) {
			processorid_t cpuid = cpuids[i];
			VERIFY3S(cpuid, <, max_cpu);

			cpustat_t *cs = st->sts_cpu_byid[cpuid];
			if (cs == NULL)
				continue;

			cs->cs_lgrp = lgrpid;
		}
	}

	lgrp_fini(cookie);
	return (B_TRUE);

fail:
	lgrp_fini(cookie);
	return (B_FALSE);
}

/*
 * Combine ivec_t's for any shared interrupts into a single consolidated
 * entry (since they have to move together).  On X86, also group MSI
 * interrupts for the same device (for similar reasons).
 */
static void
consolidate_ivecs(ivec_t **restrict ivecs, size_t *restrict np)
{
#if 0
	ivec_t **temp;
	size_t i, j, n, nout;

	/*
	 * Only one interrupt on a system seems unlikely to the point of
	 * impossibility, but to be on the safe side, make sure we have at
	 * least two to examine.
	 */
	n = *np;
	if (n < 2)
		return;

	temp = xcalloc(n, sizeof (ivec_t *));
	bcopy(ivecs, temp, n * sizeof (ivec_t *));

	/*
	 * First, consolidate interrupts sharing the same CPU, bus, and
	 * interrupt number (ino).  To simplify, we first sort the interrupts
	 * by CPU, bus, interrupt number, and inst.  Then we collapse any
	 * consecutive runs of ivecs that share the same CPU, bus, and
	 * interrupt number.
	 *
	 * XXX: Should we look for and explicitly limit this to fixed
	 * interrupts?
	 */
	qsort(temp, n, sizeof (ivec_t *), ivec_cmp_cpu);

	for (i = j = nout = 0; i < n; i = j) {
		ivec_t *iv = temp[i];

		for (j = i + 1; j < n; j++) {
			ivec_t *ivnext = temp[j];
			if (!ivec_shared_intr(iv, ivnext))
				break;

			iv->ivec_nshared++;
			iv->ivec_time += ivnext->ivec_time;
			VERIFY0(custr_appendc(iv->ivec_name, '/'));
			VERIFY0(custr_append(iv->ivec_name,
			    custr_cstr(ivnext->ivec_name)));

			ivec_free(ivnext);
			temp[j] = NULL;
		}
		ivecs[nout++] = iv;
	}

	for (i = nout; i < n; i++)
		ivecs[i] = NULL;
	*np = nout;

#ifdef __x86
	/*
	 * Per the original perl intrd implementation MSI instances of the
	 * same name share the same MSI address on X86 systems and must be
	 * moved as a group.  Therefore we sort by MSI/non-MSI (note MSIX
	 * are _not_ considered MSI interrupts), then by name, then instance.
	 * We then do a similar grouping as above.
	 */

	n = *np;
	bcopy(ivecs, temp, n * sizeof (ivec_t *));
	qsort(temp, n, sizeof (ivec_t *), ivec_cmp_msi);
	for (i = j = nout = 0; i < n; i = j) {
		ivec_t *iv = temp[i];

		/*
		 * We sorted the MSI interrupts first, once we hit the first
		 * non-MSI interrupt, we can stop.
		 */
		if (strcmp(iv->ivec_type, "msi") != 0)
			break;

		for (j = i + 1; j < n; j++) {
			ivec_t *ivnext = temp[j];

			if (!ivec_shared_msi(iv, ivnext))
				break;

			iv->ivec_time += ivnext->ivec_time;
			iv->ivec_num_ino++;
			ivec_free(ivnext);
			temp[j] = NULL;
		}
		ivecs[nout++] = iv;
	}

	for (i = nout; i < n; i++)
		ivecs[i] = NULL;
	*np = nout;

#endif

	free(temp);
#endif
}

static boolean_t
ivec_shared_intr(const ivec_t *i1, const ivec_t *i2)
{
	if (i1->ivec_ino != i2->ivec_ino)
		return (B_FALSE);
	if (strcmp(i1->ivec_buspath, i2->ivec_buspath) != 0)
		return (B_FALSE);

	return (B_TRUE);
}

static boolean_t
ivec_shared_msi(const ivec_t *i1, const ivec_t *i2)
{
	if (strcmp(custr_cstr(i1->ivec_name), custr_cstr(i2->ivec_name)) != 0)
		return (B_FALSE);
	return (B_TRUE);
}

static int
ivec_cmp_msi(const void *a, const void *b)
{
	const ivec_t *l = *((ivec_t **)a);
	const ivec_t *r = *((ivec_t **)b);
	int ret;

	if (strcmp(l->ivec_type, r->ivec_type) != 0) {
		if (strcmp(l->ivec_type, "msi") == 0)
			return (-1);
		if (strcmp(r->ivec_type, "msi") == 0)
			return (1);
	}

	if ((ret = strcmp(custr_cstr(l->ivec_name),
	    custr_cstr(r->ivec_name))) != 0) {
		return ((ret < 0) ? -1 : 1);
	}

	if (l->ivec_instance == r->ivec_instance)
		return (0);
	return ((l->ivec_instance < r->ivec_instance) ? -1 : 1);
}

static int
count_kstats(kstat_ctl_t *restrict kcp, kstat_t *restrict ksp, void *arg)
{
	struct count_info *count = arg;

	if (strcmp(ksp->ks_module, "cpu_info") == 0) {
		VERIFY3S(ksp->ks_instance, <, max_cpu);
		count->ci_ncpuinfo++;
	} else if (strcmp(ksp->ks_module, "cpu") == 0 &&
	    strcmp(ksp->ks_name, "sys") == 0) {
		VERIFY3S(ksp->ks_instance, <, max_cpu);
		count->ci_ncpu++;
	} else if (strcmp(ksp->ks_module, "pci_intrs") == 0 &&
	    strcmp(ksp->ks_name, "npe") == 0) {
		count->ci_nivec++;
	}

	return (KITER_NEXT);
}

static int
get_cpuinfo(kstat_ctl_t *restrict kcp, kstat_t *restrict ksp, void *arg)
{
	/*
	 * Cache the index of the cpu state field in the cpu_info kstat.
	 */
	static uint_t hint = -1;

	struct read_info *rip = arg;

	if (strcmp(ksp->ks_module, "cpu_info") != 0)
		return (KITER_NEXT);

	if (kstat_read(kcp, ksp, NULL) == -1) {
		if (errno == ENXIO) {
			rip->ri_changed = B_TRUE;
			return (KITER_DONE);
		}
		err(EXIT_FAILURE, "unable to read kstat %s:%d",
		    ksp->ks_name, ksp->ks_instance);
	}

	VERIFY3S(ksp->ks_type, ==, KSTAT_TYPE_NAMED);
	kstat_named_t *nm = KSTAT_NAMED_PTR(ksp);

	if (hint == -1) {
		for (uint_t i = 0; i < ksp->ks_ndata; i++) {
			if (strcmp(nm[i].name, "state") != 0)
				continue;

			hint = i;
			break;
		}
	}

	VERIFY3S(ksp->ks_instance, >=, 0);
	VERIFY3S(ksp->ks_instance, <, max_cpu);

	if (strcmp(nm[hint].value.c, "on-line") != 0)
		return (KITER_NEXT);

	cpustat_t *cs = cpustat_new();

	cs->cs_cpuid = ksp->ks_instance;
	rip->ri_cpu[cs->cs_cpuid] = cs;
	rip->ri_ncpu++;

	return (KITER_NEXT);
}

static int
get_cpu(kstat_ctl_t *restrict kcp, kstat_t *restrict ksp, void *restrict arg)
{
	static int idle = -1;
	static int kernel = -1;
	static int user = -1;
	static int dtrace = -1;
	static int intr = -1;

	struct read_info *rip = arg;
	cpustat_t *cs = NULL;

	if (strcmp(ksp->ks_module, "cpu") != 0)
		return (KITER_NEXT);
	if (strcmp(ksp->ks_name, "sys") != 0)
		return (KITER_NEXT);

	VERIFY3S(ksp->ks_instance, <, max_cpu);
	if ((cs = rip->ri_cpu[ksp->ks_instance]) == NULL)
		return (KITER_NEXT);

	if (kstat_read(kcp, ksp, NULL) == -1) {
		if (errno == ENXIO) {
			rip->ri_changed = B_TRUE;
			return (KITER_DONE);
		}
		err(EXIT_FAILURE, "unable to read kstat %s:%d",
		    ksp->ks_name, ksp->ks_instance);
	}

	VERIFY3S(ksp->ks_type, ==, KSTAT_TYPE_NAMED);

	kstat_named_t *nm = KSTAT_NAMED_PTR(ksp);

	if (idle == -1) {
		for (uint_t i = 0; i < ksp->ks_ndata; i++) {
			if (strcmp(nm[i].name, "cpu_nsec_dtrace") == 0)
				dtrace = i;
			else if (strcmp(nm[i].name, "cpu_nsec_idle") == 0)
				idle = i;
			else if (strcmp(nm[i].name, "cpu_nsec_intr") == 0)
				intr = i;
			else if (strcmp(nm[i].name, "cpu_nsec_kernel") == 0)
				kernel = i;
			else if (strcmp(nm[i].name, "cpu_nsec_user") == 0)
				user = i;
		}
	}

	VERIFY3S(dtrace, >, -1);
	VERIFY3S(idle, >, -1);
	VERIFY3S(intr, >, -1);
	VERIFY3S(kernel, >, -1);
	VERIFY3S(user, >, -1);

	cs->cs_snaptime = ksp->ks_snaptime;
	cs->cs_cpu_nsec_idle = nm[idle].value.ui64;
	cs->cs_cpu_nsec_user = nm[user].value.ui64;
	cs->cs_cpu_nsec_intr = nm[intr].value.ui64;
	cs->cs_cpu_nsec_kernel = nm[kernel].value.ui64;
	cs->cs_cpu_nsec_dtrace = nm[dtrace].value.ui64;

	return (KITER_NEXT);
}

static int
get_ivecs(kstat_ctl_t *restrict kcp, kstat_t *restrict ksp, void *restrict arg)
{
	static int cookie = -1;
	static int cpu = -1;
	static int buspath = -1;
	static int ino = -1;
	static int pil = -1;
	static int type = -1;
	static int name = -1;
	static int f_time = -1;

	struct read_info *rip = arg;

	if (strcmp(ksp->ks_module, "pci_intrs") != 0)
		return (KITER_NEXT);
	if (strcmp(ksp->ks_name, "npe") != 0)
		return (KITER_NEXT);

	if (kstat_read(kcp, ksp, NULL) == -1) {
		if (errno == ENXIO) {
			rip->ri_changed = B_TRUE;
			return (KITER_DONE);
		}
		err(EXIT_FAILURE, "unable to read kstat %s:%d",
		    ksp->ks_name, ksp->ks_instance);
	}

	VERIFY3S(ksp->ks_type, ==, KSTAT_TYPE_NAMED);

	kstat_named_t *nm = KSTAT_NAMED_PTR(ksp);

	if (cookie == -1) {
		for (uint_t i = 0; i < ksp->ks_ndata; i++) {
			if (strcmp(nm[i].name, "buspath") == 0)
				buspath = i;
			else if (strcmp(nm[i].name, "cpu") == 0)
				cpu = i;
			else if (strcmp(nm[i].name, "cookie") == 0)
				cookie = i;
			else if (strcmp(nm[i].name, "ino") == 0)
				ino = i;
			else if (strcmp(nm[i].name, "pil") == 0)
				pil = i;
			else if (strcmp(nm[i].name, "type") == 0)
				type = i;
			else if (strcmp(nm[i].name, "name") == 0)
				name = i;
			else if (strcmp(nm[i].name, "time") == 0)
				f_time = i;
		}
	}

	VERIFY3S(cookie, >, -1);
	VERIFY3S(cpu, >, -1);
	VERIFY3S(buspath, >, -1);
	VERIFY3S(ino, >, -1);
	VERIFY3S(pil, >, -1);
	VERIFY3S(type, >, -1);
	VERIFY3S(name, >, -1);
	VERIFY3S(f_time, >, -1);

	if (strcmp(nm[type].value.c, "disabled") == 0)
		return (KITER_NEXT);

	if (rip->ri_nivec == rip->ri_ivecalloc) {
		(void) printf("ivec mismatch: nivec %zu alloc %zu\n",
		    rip->ri_nivec, rip->ri_ivecalloc);

		rip->ri_changed = B_TRUE;
		return (KITER_DONE);
	}

	ivec_t *ivp = ivec_new();

	ivp->ivec_instance = ksp->ks_instance;
	ivp->ivec_snaptime = ksp->ks_snaptime;
	ivp->ivec_cookie = nm[cookie].value.ui64;
	ivp->ivec_pil = nm[pil].value.ui64;
	ivp->ivec_ino = nm[ino].value.ui64;
	VERIFY3U(nm[ino].value.ui64, <=, INT_MAX);
	ivp->ivec_cpuid = ivp->ivec_oldcpuid = (int)nm[cpu].value.ui64;
	ivp->ivec_time = nm[f_time].value.ui64;
	ivp->ivec_num_ino = 1;
	ivp->ivec_nshared = 1;
	ivp->ivec_buspath = xstrdup(KSTAT_NAMED_STR_PTR(&nm[buspath]));
	VERIFY0(custr_append(ivp->ivec_name, nm[name].value.c));
	(void) strlcpy(ivp->ivec_type, nm[type].value.c,
	    sizeof (ivp->ivec_type));

	rip->ri_ivec[rip->ri_nivec++] = ivp;

	return (KITER_NEXT);
}

/*
 * Determine if the amount of time spent collecting our stats, as well as set
 * the min and max timestamp of all the stats collected in stp.
 */
static boolean_t
getstat_tooslow(stats_t *stp, uint_t interval, double tooslow)
{
	hrtime_t diff;
	double portion;
	size_t i;

	VERIFY3S(stp->sts_maxtime, >=, stp->sts_mintime);

	diff = stp->sts_maxtime - stp->sts_mintime;
	portion = (double)diff / (double)(interval * NANOSEC);

	syslog(LOG_DEBUG,
	    "spent %.1f%% of the polling interval collecting stats "
	    "(max: %.1f%%)", portion * 100.0, tooslow * 100.0);

	(void) printf("spent %.1f%% of the polling interval collecting stats "
	    "(max: %.1f%%)\n", portion * 100.0, tooslow * 100.0);

	return ((portion < tooslow) ? B_FALSE : B_TRUE);
}

static void
set_timerange(stats_t *stp, cpustat_t **cpus, size_t ncpu, ivec_t **ivecs,
    size_t nivec)
{
	size_t i;

	stp->sts_mintime = INT64_MAX;
	stp->sts_maxtime = INT64_MIN;

	for (i = 0; i < ncpu; i++) {
		if (cpus[i] == NULL)
			continue;

		hrtime_t crtime = cpus[i]->cs_snaptime;

		if (crtime > stp->sts_maxtime)
			stp->sts_maxtime = crtime;
		if (crtime < stp->sts_mintime)
			stp->sts_mintime = crtime;
	}

	for (i = 0; i < nivec; i++) {
		hrtime_t crtime = ivecs[i]->ivec_snaptime;

		if (crtime > stp->sts_maxtime)
			stp->sts_maxtime = crtime;
		if (crtime < stp->sts_mintime)
			stp->sts_mintime = crtime;
	}
}


static inline boolean_t
uint64_add(uint64_t a, uint64_t b, uint64_t *res)
{
#if 0
	if (__builtin_uaddll_overflow(a, b, res))
		return (B_TRUE);
#else
	*res = a + b;
	if (*res < a || *res < b)
		return (B_TRUE);
#endif

	return (B_FALSE);
}

stats_t *
stats_delta(const stats_t *restrict st, const stats_t *restrict stprev)
{
	stats_t *delta = NULL;
	const cpustat_t *cs;
	cpustat_t *csd;
	ivec_t *iv, *ivd;
	size_t i;

	if (st == NULL || stprev == NULL)
		return (NULL);

	if (stats_differ(st, stprev))
		return (NULL);

	delta = stats_dup(st);

#define	CS_SUB(field, d, c) \
	if ((d)->cs_ ## field < (c)->cs_ ## field) { \
		syslog(LOG_WARNING, "%s kstat is decreasing", #field); \
		goto fail; \
	} \
	(d)->cs_ ## field -= (c)->cs_ ## field;

	for (i = 0; i < st->sts_ncpu; i++) {
		cs = stprev->sts_cpu[i];
		csd = delta->sts_cpu[i];

		VERIFY3S(csd->cs_cpuid, ==, cs->cs_cpuid);

		if (csd->cs_snaptime < cs->cs_snaptime) {
			syslog(LOG_WARNING, "kstat time is not increasing");
			goto fail;
		}

		CS_SUB(cpu_nsec_idle, csd, cs);
		CS_SUB(cpu_nsec_user, csd, cs);
		CS_SUB(cpu_nsec_kernel, csd, cs);
		CS_SUB(cpu_nsec_dtrace, csd, cs);
		CS_SUB(cpu_nsec_intr, csd, cs);

		iv = list_head((list_t *)&cs->cs_ivecs);
		ivd = list_head(&csd->cs_ivecs);
		while(iv != NULL && ivd != NULL) {
			/*
			 * If !stats_differ(st, stprev), then these entries
			 * should always correspond.
			 */
			VERIFY3S(iv->ivec_instance, ==, ivd->ivec_instance);
			if (ivd->ivec_snaptime < iv->ivec_snaptime) {
				syslog(LOG_WARNING,
				    "kstat time is not increasing");
				goto fail;
			}

			if (ivd->ivec_time < iv->ivec_time) {
				syslog(LOG_WARNING,
				    "interrupt time kstat not increasing");
				goto fail;
			}
			ivd->ivec_time -= iv->ivec_time;

			iv = list_next((list_t *)&cs->cs_ivecs, iv);
			ivd = list_next(&csd->cs_ivecs, ivd);
		}
	}
#undef CS_SUB

	delta->sts_mintime = stprev->sts_mintime;
	delta->sts_maxtime = st->sts_maxtime;
	return (delta);

fail:
	stats_free(delta);
	return (NULL);
}

stats_t *
stats_sum(stats_t * const *restrict deltas, size_t n, size_t *restrict total)
{
	VERIFY3U(n, >, 0);
	VERIFY3P(deltas[0], !=, NULL);

	stats_t *sum = stats_dup(deltas[0]);
	boolean_t overflow = B_FALSE;

	*total = 0;
	for (size_t i = 1; i < n; i++) {
		const stats_t *d = deltas[i];

		if (stats_differ(sum, d))
			continue;

		sum->sts_maxtime = d->sts_maxtime;

#define	CS_ADD(field, a, b) \
	uint64_add((a)->cs_ ## field, (b)->cs_ ## field, &(a)->cs_ ## field)

		for (size_t j = 0; i < sum->sts_ncpu; i++) {
			cpustat_t *sumcs = sum->sts_cpu[j];
			cpustat_t *dcs = d->sts_cpu[j];

			overflow |= CS_ADD(cpu_nsec_idle, sumcs, dcs);
			overflow |= CS_ADD(cpu_nsec_user, sumcs, dcs);
			overflow |= CS_ADD(cpu_nsec_kernel, sumcs, dcs);
			overflow |= CS_ADD(cpu_nsec_dtrace, sumcs, dcs);
			overflow |= CS_ADD(cpu_nsec_intr, sumcs, dcs);
			if (overflow)
				goto fail;

			list_t *sumivl = &sumcs->cs_ivecs;
			list_t *sumdl = &dcs->cs_ivecs;

			ivec_t *sumiv = list_head(sumivl);
			ivec_t *sumd = list_head(sumdl);
			while (sumiv != NULL && sumd != NULL) {
				overflow |= uint64_add(sumiv->ivec_time,
				    sumd->ivec_time, &sumiv->ivec_time);

				if (overflow)
					goto fail;

				sumiv = list_next(sumivl, sumiv);
				sumd = list_next(sumdl, sumd);
			}
			VERIFY3P(sumiv, ==, NULL);
			VERIFY3P(sumd, ==, NULL);
		}
		*total++;
	}
#undef CS_ADD

	return (sum);

fail:
	*total = 0;
	stats_free(sum);
	return (NULL);
}

stats_t *
stats_dup(const stats_t *src)
{
	stats_t *stp;

	stp = stats_new();
	stp->sts_cpu_byid = xcalloc(max_cpu, sizeof (cpustat_t *));
	stp->sts_cpu = xcalloc(src->sts_ncpu, sizeof (cpustat_t *));
	stp->sts_ivecs = xcalloc(src->sts_nivecs, sizeof (ivec_t *));
	stp->sts_lgrp = xcalloc(src->sts_nlgrp, sizeof (cpugrp_t));

	stp->sts_mintime = src->sts_mintime;
	stp->sts_maxtime = src->sts_maxtime;

	for (stp->sts_ncpu = 0; stp->sts_ncpu < src->sts_ncpu;
	    stp->sts_ncpu++) {
		cpustat_t *cs = cpustat_dup(src->sts_cpu[stp->sts_ncpu]);

		stp->sts_cpu_byid[cs->cs_cpuid] = cs;
		stp->sts_cpu[stp->sts_ncpu] = cs;

		ivec_t *iv;
		list_t *ivlist = &cs->cs_ivecs;

		for (iv = list_head(ivlist); iv != NULL;
		    iv = list_next(ivlist, iv)) {
			stp->sts_ivecs[stp->sts_nivecs++] = iv;
		}
	}
	VERIFY3U(stp->sts_nivecs, ==, src->sts_nivecs);

	for (stp->sts_nlgrp = 0; stp->sts_nlgrp < src->sts_nlgrp;
	    stp->sts_nlgrp++) {
		const cpugrp_t *srcgrp = &src->sts_lgrp[stp->sts_nlgrp];
		cpugrp_t *grp = &stp->sts_lgrp[stp->sts_nlgrp];

		grp->cg_id = srcgrp->cg_id;
		grp->cg_parent = srcgrp->cg_parent;
		grp->cg_children = xcalloc(srcgrp->cg_nchildren,
		    sizeof (lgrp_id_t));
		bcopy(srcgrp->cg_children, grp->cg_children,
		    srcgrp->cg_nchildren * sizeof (lgrp_id_t));
		grp->cg_nchildren = srcgrp->cg_nchildren;
	}

	return (stp);
}

static boolean_t
stats_differ(const stats_t *s1, const stats_t *s2)
{
	if (s1 == NULL || s2 == NULL)
		return (B_TRUE);

	if (s1->sts_ncpu != s2->sts_ncpu)
		return (B_TRUE);

	for (size_t i = 0; i < s1->sts_ncpu; i++) {
		const cpustat_t *c1 = s1->sts_cpu[i];
		const cpustat_t *c2 = s2->sts_cpu[i];

		/*
		 * A new stats_t generated from a kstat snapshot will
		 * have its cpustat_t's sorted by CPU ID, so both lists
		 * should be in the same order.
		 */
		if (c1->cs_cpuid != c2->cs_cpuid)
			return (B_TRUE);

		if (c1->cs_nivecs != c2->cs_nivecs)
			return (B_TRUE);

		list_t *l1 = (list_t *)&c1->cs_ivecs;
		list_t *l2 = (list_t *)&c2->cs_ivecs;

		const ivec_t *iv1 = list_head(l1);
		const ivec_t *iv2 = list_head(l2);

		while (iv1 != NULL && iv2 != NULL) {
			/*
			 * Similarly to cpustat_t's, ivec_t's are sorted by
			 * instance id, so l1 and l2 should be in the same
			 * order.
			 */
			if (iv1->ivec_instance != iv2->ivec_instance)
				return (B_TRUE);
			if (iv1->ivec_cpuid != iv2->ivec_cpuid)
				return (B_TRUE);
			if (iv1->ivec_ino != iv2->ivec_ino)
				return (B_TRUE);
			if (strcmp(iv1->ivec_buspath, iv2->ivec_buspath) != 0)
				return (B_TRUE);

			iv1 = list_next(l1, (ivec_t *)iv1);
			iv2 = list_next(l2, (ivec_t *)iv2);
		}
		if (iv1 != NULL || iv2 != NULL)
			return (B_TRUE);
	}

	return (B_FALSE);
}

void
stats_dump(const stats_t *stp)
{
	(void) printf("Mintime: %lld Maxtime: %lld (%lld)\n",
	    stp->sts_mintime, stp->sts_maxtime,
	    stp->sts_maxtime - stp->sts_mintime);

	for (size_t i = 0; i < stp->sts_ncpu; i++) {
		cpustat_t *cs = stp->sts_cpu[i];
		uint64_t total = cs->cs_cpu_nsec_idle + cs->cs_cpu_nsec_user +
			cs->cs_cpu_nsec_kernel + cs->cs_cpu_nsec_dtrace +
			cs->cs_cpu_nsec_intr;

		(void) printf("    CPU %d Snaptime: %+lld\n",
		    cs->cs_cpuid, cs->cs_snaptime - stp->sts_mintime);

		(void) printf("        idle: %3llu%% %llu\n"
		    "        user: %3llu%% %llu\n"
		    "      kernel: %3llu%% %llu\n"
		    "      dtrace: %3llu%% %llu\n"
		    "        intr: %3llu%% %llu%\n",
		    cs->cs_cpu_nsec_idle * 100 / total, cs->cs_cpu_nsec_idle,
		    cs->cs_cpu_nsec_user * 100 / total, cs->cs_cpu_nsec_user,
		    cs->cs_cpu_nsec_kernel * 100 / total,
		    cs->cs_cpu_nsec_kernel,
		    cs->cs_cpu_nsec_dtrace * 100 / total,
		    cs->cs_cpu_nsec_dtrace,
		    cs->cs_cpu_nsec_intr * 100 / total, cs->cs_cpu_nsec_intr);
		(void) printf("       total:      %llu\n", total);

		total = 0;

		ivec_t *iv;
		for (iv = list_head(&cs->cs_ivecs); iv != NULL;
		    iv = list_next(&cs->cs_ivecs, iv)) {
			total += iv->ivec_time;
			(void) printf("%*s %-16s int#%llu pil %llu %llu\n",
			    (int)8, "", custr_cstr(iv->ivec_name), iv->ivec_ino,
			    iv->ivec_pil, iv->ivec_time);
		}
		(void) printf("  intr total:      %llu\n", total);
	}

	(void) fputc('\n', stdout);
}

static int
kstat_iter(kstat_ctl_t *restrict kcp, kstat_itercb_t cb, void *restrict arg)
{
	int ret = KITER_DONE;

	for (kstat_t *ksp = kcp->kc_chain; ksp != NULL; ksp = ksp->ks_next) {
		if ((ret = cb(kcp, ksp, arg)) != KITER_NEXT)
			return (ret);
	}

	return (ret);
}

static stats_t *
stats_new(void)
{
	return (umem_cache_alloc(stats_cache, UMEM_NOFAIL));
}

void
stats_free(stats_t *stp)
{
	size_t i;

	if (stp == NULL)
		return;

	for (i = 0; i < stp->sts_ncpu; i++) {
		cpustat_t *cs = stp->sts_cpu[i];
		cpustat_free(cs);
	}
	free(stp->sts_cpu);
	free(stp->sts_cpu_byid);
	free(stp->sts_ivecs);

	for (i = 0; i < stp->sts_nlgrp; i++)
		free(stp->sts_lgrp[i].cg_children);

	bzero(stp, sizeof (*stp));

	umem_cache_free(stats_cache, stp);
}

ivec_t *
ivec_dup(const ivec_t *iv)
{
	ivec_t *newiv = ivec_new();

	newiv->ivec_snaptime = iv->ivec_snaptime;
	newiv->ivec_instance = iv->ivec_instance;
	newiv->ivec_cpuid = iv->ivec_cpuid;
	newiv->ivec_oldcpuid = iv->ivec_oldcpuid;
	newiv->ivec_cookie = iv->ivec_cookie;
	newiv->ivec_pil = iv->ivec_pil;
	newiv->ivec_ino = iv->ivec_ino;
	newiv->ivec_time = iv->ivec_time;
	newiv->ivec_num_ino = iv->ivec_num_ino;
	newiv->ivec_nshared = iv->ivec_nshared;
	newiv->ivec_buspath = xstrdup(iv->ivec_buspath);
	VERIFY0(custr_append(newiv->ivec_name, custr_cstr(iv->ivec_name)));
	(void) strlcpy(newiv->ivec_type, iv->ivec_type, sizeof (iv->ivec_type));

	return (newiv);
}

ivec_t *
ivec_new(void)
{
	return (umem_cache_alloc(ivec_cache, UMEM_NOFAIL));
}

void
ivec_free(ivec_t *iv)
{
	if (iv == NULL)
		return;

	custr_t *cu = iv->ivec_name;

	VERIFY(!list_link_active(&iv->ivec_node));
	free(iv->ivec_buspath);
	bzero(iv, sizeof (*iv));
	iv->ivec_num_ino = 1;
	iv->ivec_nshared = 1;
	iv->ivec_name = cu;
	custr_reset(cu);
	umem_cache_free(ivec_cache, iv);
}

cpustat_t *
cpustat_new(void)
{
	return (umem_cache_alloc(cpustat_cache, UMEM_NOFAIL));
}

void
cpustat_free(cpustat_t *cs)
{
	if (cs == NULL)
		return;

	ivec_t *iv;

	while ((iv = list_remove_head(&cs->cs_ivecs)) != NULL) {
		ivec_free(iv);
		cs->cs_nivecs--;
	}

	cs->cs_snaptime = 0;
	cs->cs_cpuid = 0;
	cs->cs_cpu_nsec_idle = cs->cs_cpu_nsec_user = cs->cs_cpu_nsec_kernel =
	    cs->cs_cpu_nsec_dtrace = cs->cs_cpu_nsec_intr = 0;
	cs->cs_lgrp = LGRP_NONE;

	umem_cache_free(cpustat_cache, cs);
}

cpustat_t *
cpustat_dup(const cpustat_t *src)
{
	cpustat_t *cs = cpustat_new();
	list_t *srclist = (list_t *)(&src->cs_ivecs);
	ivec_t *ivsrc;

	cs->cs_snaptime = src->cs_snaptime;
	cs->cs_cpuid = src->cs_cpuid;
	cs->cs_cpu_nsec_idle = src->cs_cpu_nsec_idle;
	cs->cs_cpu_nsec_user = src->cs_cpu_nsec_user;
	cs->cs_cpu_nsec_kernel = src->cs_cpu_nsec_kernel;
	cs->cs_cpu_nsec_dtrace = src->cs_cpu_nsec_dtrace;
	cs->cs_cpu_nsec_intr = src->cs_cpu_nsec_intr;

	for (ivsrc = list_head(srclist); ivsrc != NULL;
	    ivsrc = list_next(srclist, ivsrc)) {
		list_insert_tail(&cs->cs_ivecs, ivec_dup(ivsrc));
		cs->cs_nivecs++;
	}

	return (cs);
}

static int
stats_ctor(void *buf, void *dummy __unused, int flags __unused)
{
	stats_t *st = buf;

	bzero(st, sizeof (*st));
	return (0);
}

static int
cpustat_ctor(void *buf, void *dummy __unused, int flags __unused)
{
	cpustat_t *cs = buf;

	bzero(cs, sizeof (*cs));
	cs->cs_lgrp = LGRP_NONE;
	list_create(&cs->cs_ivecs, sizeof (ivec_t),
	    offsetof(ivec_t, ivec_node));

	return (0);
}

static void
cpustat_dtor(void *buf, void *dummy __unused)
{
	cpustat_t *cs = buf;

	VERIFY0(cs->cs_nivecs);
	list_destroy(&cs->cs_ivecs);
}

static int
ivec_ctor(void *buf, void *dummy __unused, int flags __unused)
{
	ivec_t *iv = buf;
	int ret;

	bzero(iv, sizeof (*iv));
	if ((ret = custr_alloc(&iv->ivec_name)) != 0)
		return (ret);
	iv->ivec_num_ino = 1;
	iv->ivec_nshared = 1;

	return (0);
}

static void
ivec_dtor(void *buf, void *dummy __unused)
{
	ivec_t *iv = buf;
	custr_free(iv->ivec_name);
}

void
intrd_kstat_init(void)
{
	if ((ivec_cache = umem_cache_create("ivec_t cache", sizeof (ivec_t), 8,
	    ivec_ctor, ivec_dtor, NULL, NULL, NULL, 0)) == NULL) {
		err(EXIT_FAILURE, "unable to create ivec_cache");
	}

	if ((cpustat_cache = umem_cache_create("cpustat_t cache",
	    sizeof (cpustat_t), 8, cpustat_ctor, cpustat_dtor, NULL, NULL,
	    NULL, 0)) == NULL) {
		err(EXIT_FAILURE, "unable to create cpustat_cache");
	}

	if ((stats_cache = umem_cache_create("stats_t cache",
	    sizeof (stats_t), 8, stats_ctor, NULL, NULL, NULL, NULL,
	    0)) == NULL) {
		err(EXIT_FAILURE, "unable to create stats cache");
	}
}
