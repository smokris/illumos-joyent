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

static umem_cache_t *ivec_cache;
static umem_cache_t *cpustat_cache;
static umem_cache_t *stats_cache;

typedef intrd_walk_ret_t (*kstat_itercb_t)(kstat_ctl_t *restrict,
    kstat_t *restrict, void *restrict);
static intrd_walk_ret_t kstat_iter(kstat_ctl_t *restrict, kstat_itercb_t,
    void *restrict);

static intrd_walk_ret_t get_cpu(kstat_ctl_t *restrict, kstat_t *restrict,
    void *restrict);
static intrd_walk_ret_t get_ivecs(kstat_ctl_t *restrict, kstat_t *restrict,
    void *restrict);
static boolean_t build_lgrp_tree(stats_t *);

static void consolidate_ivecs(stats_t *);
static void set_timerange(stats_t *, cpustat_t **, size_t, ivec_t **, size_t);
static boolean_t getstat_tooslow(stats_t *, uint_t, double);

static boolean_t ivec_shared_intr(const ivec_t *, const ivec_t *);
static boolean_t ivec_shared_msi(const ivec_t *, const ivec_t *);

static stats_t *stats_new(void);

stats_t *
stats_get(const config_t *restrict cfg, kstat_ctl_t *restrict kcp,
    uint_t interval)
{
	stats_t *sts = NULL;
	kstat_t *ksp;
	kid_t kid;
	size_t i, j;

	if ((kid = kstat_chain_update(kcp)) == -1) {
		if (errno == EAGAIN)
			return (NULL);
		err(EXIT_FAILURE, "failed to update kstat chain");
	}

	sts = stats_new();
	sts->sts_kid = kcp->kc_chain_id;

	if (kstat_iter(kcp, get_cpu, sts) != INTRD_WALK_DONE) {
		stats_free(sts);
		return (NULL);
	}

	/*
	 * We must read the CPU stats first to create all the cpustat_t
	 * instances that will hold the ivec_t instances.
	 */
	if (kstat_iter(kcp, get_ivecs, sts) != INTRD_WALK_DONE) {
		stats_free(sts);
		return (NULL);
	}

	if (getstat_tooslow(sts, interval, cfg->cfg_tooslow)) {
		goto fail;
	}

	/*
	 * Combine any shared or grouped interrupts before assigning
	 * to cpustat_t's.
	 */
	consolidate_ivecs(sts);

	if (!build_lgrp_tree(sts))
		goto fail;

	return (sts);

fail:
	printf("%s fail\n", __func__);
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

			cpustat_t *cs = STATS_CPU(st, cpuid);
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
static int
ivec_cmp(const void *a, const void *b)
{
	const ivec_t *l = *((ivec_t **)a);
	const ivec_t *r = *((ivec_t **)b);
	int ret;

	VERIFY3S(l->ivec_cpuid, ==, r->ivec_cpuid);
	if ((ret = strcmp(l->ivec_buspath, r->ivec_buspath)) != 0)
		return (ret);

	if (l->ivec_ino < r->ivec_ino)
		return (-1);
	if (l->ivec_ino > r->ivec_ino)
		return (1);

	if (l->ivec_instance < r->ivec_instance)
		return (-1);
	if (l->ivec_instance > r->ivec_instance)
		return (1);

	return (0);
}

static intrd_walk_ret_t
consolidate_ivec_cb(stats_t *stp, cpustat_t *cs, void *arg)
{
	if (cs->cs_nivecs == 0)
		return (INTRD_WALK_NEXT);

	list_t *ivlist = &cs->cs_ivecs;
	ivec_t *iv;
	ivec_t *temp[cs->cs_nivecs];
	size_t n, i, j;

	n = 0;
	for (iv = list_head(ivlist); iv != NULL; iv = list_next(ivlist, iv))
		temp[n++] = iv;
	VERIFY3U(n, ==, cs->cs_nivecs);

	qsort(temp, n, sizeof (ivec_t *), ivec_cmp);

	for (i = 0; i < n; i = j) {
		iv = temp[i];

		for (j = i + 1; j < n; j++) {
			ivec_t *ivnext = temp[j];

			if (!ivec_shared_intr(iv, ivnext))
				break;

			iv->ivec_nshared++;
			iv->ivec_time += ivnext->ivec_time;
			VERIFY0(custr_appendc(iv->ivec_name, '/'));
			VERIFY0(custr_append(iv->ivec_name,
			    custr_cstr(ivnext->ivec_name)));

			list_remove(ivlist, ivnext);
			ivec_free(ivnext);
		}
	}

	return (INTRD_WALK_NEXT);
}

static void
consolidate_ivecs(stats_t *stp)
{
	cpu_iter(stp, consolidate_ivec_cb, NULL);
}

static boolean_t
ivec_shared_intr(const ivec_t *i1, const ivec_t *i2)
{
#if 0
	if (i1->ivec_ino != i2->ivec_ino)
		return (B_FALSE);
	if (strcmp(i1->ivec_buspath, i2->ivec_buspath) != 0)
		return (B_FALSE);

	return (B_TRUE);
#else
	return (B_FALSE);
#endif
}

static boolean_t
ivec_shared_msi(const ivec_t *i1, const ivec_t *i2)
{
#if 0
	if (strcmp(custr_cstr(i1->ivec_name), custr_cstr(i2->ivec_name)) != 0)
		return (B_FALSE);
	return (B_TRUE);
#else
	return (B_FALSE);
#endif
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

static intrd_walk_ret_t
get_cpu(kstat_ctl_t *restrict kcp, kstat_t *restrict ksp, void *restrict arg)
{
	/*
	 * Cache index of the kstat_named_t fields we want.  These should never
	 * change while the system is running.
	 */
	static int idle = -1;
	static int kernel = -1;
	static int user = -1;
	static int dtrace = -1;
	static int intr = -1;

	if (strcmp(ksp->ks_module, "cpu") != 0)
		return (INTRD_WALK_NEXT);
	if (strcmp(ksp->ks_name, "sys") != 0)
		return (INTRD_WALK_NEXT);

	VERIFY3S(ksp->ks_instance, <, max_cpu);
	if (kstat_read(kcp, ksp, NULL) == -1) {
		/* ENXIO means the kstat chain has changed.  Abort and retry */
		if (errno == ENXIO)
			return (INTRD_WALK_ERROR);

		err(EXIT_FAILURE, "unable to read kstat %s:%d",
		    ksp->ks_name, ksp->ks_instance);
	}

	VERIFY3S(ksp->ks_type, ==, KSTAT_TYPE_NAMED);

	stats_t *stp = arg;
	cpustat_t *cs = NULL;
	kstat_named_t *nm = KSTAT_NAMED_PTR(ksp);

	STATS_CPU(stp, ksp->ks_instance) = cs = cpustat_new();
	cs->cs_cpuid = ksp->ks_instance;

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

	if (cs->cs_snaptime < stp->sts_mintime)
		stp->sts_mintime = cs->cs_snaptime;
	if (cs->cs_snaptime > stp->sts_maxtime)
		stp->sts_maxtime = cs->cs_snaptime;

	stp->sts_ncpu++;

	return (INTRD_WALK_NEXT);
}

static intrd_walk_ret_t
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

	if (strcmp(ksp->ks_module, "pci_intrs") != 0)
		return (INTRD_WALK_NEXT);
	if (strcmp(ksp->ks_name, "npe") != 0)
		return (INTRD_WALK_NEXT);

	if (kstat_read(kcp, ksp, NULL) == -1) {
		/* ENXIO means the kstat chain has changed.  Abort and retry */
		if (errno == ENXIO)
			return (INTRD_WALK_ERROR);
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
		return (INTRD_WALK_NEXT);

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

	stats_t *stp = arg;
	cpustat_t *cs = STATS_CPU(stp, ivp->ivec_cpuid);

	list_insert_tail(&cs->cs_ivecs, ivp);
	cs->cs_nivecs++;

	if (ivp->ivec_snaptime < stp->sts_mintime)
		stp->sts_mintime = ivp->ivec_snaptime;
	if (ivp->ivec_snaptime > stp->sts_maxtime)
		stp->sts_maxtime = ivp->ivec_snaptime;

	return (INTRD_WALK_NEXT);
}

/*
 * Determine if the amount of time spent collecting our stats, as well as set
 * the min and max timestamp of all the stats collected in stp.
 */
static boolean_t
getstat_tooslow(stats_t *stp, uint_t interval, double tooslow)
{
	char numbuf[NN_NUMBUF_SZ];
	hrtime_t diff;
	double portion;

	VERIFY3S(stp->sts_maxtime, >=, stp->sts_mintime);

	diff = stp->sts_maxtime - stp->sts_mintime;
	nanonicenum(diff, numbuf, sizeof (numbuf));

	portion = (double)diff / (double)(interval * NANOSEC);

	syslog(LOG_DEBUG,
	    "spent %.1f%% of the polling interval collecting stats "
	    "(max: %.1f%%)", portion * 100.0, tooslow * 100.0);

	(void) printf("spent %ss %.1f%% of the polling interval collecting stats "
	    "(max: %.1f%%)\n", numbuf, portion * 100.0, tooslow * 100.0);

	return ((portion < tooslow) ? B_FALSE : B_TRUE);
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

static intrd_walk_ret_t
stats_delta_cb(stats_t *stp, cpustat_t *cs, void *arg)
{
	const stats_t *stprev = arg;
	const cpustat_t *csprev = stprev->sts_cpu[cs->cs_cpuid];

#define	CS_SUB(field, d, c)						\
	if ((d)->cs_ ## field < (c)->cs_ ## field) {			\
		syslog(LOG_WARNING, "%s kstat is decreasing", #field);	\
		return (INTRD_WALK_ERROR);				\
	}								\
	(d)->cs_ ## field -= (c)->cs_ ## field

	CS_SUB(cpu_nsec_idle, cs, csprev);
	CS_SUB(cpu_nsec_user, cs, csprev);
	CS_SUB(cpu_nsec_kernel, cs, csprev);
	CS_SUB(cpu_nsec_dtrace, cs, csprev);
	CS_SUB(cpu_nsec_intr, cs, csprev);

#undef CS_SUB

	ivec_t *iv = list_head(&cs->cs_ivecs);
	ivec_t *ivprev = list_head((list_t *)&csprev->cs_ivecs);
	while (iv != NULL && ivprev != NULL) {
		VERIFY3S(iv->ivec_instance, ==, ivprev->ivec_instance);

		if (iv->ivec_snaptime < ivprev->ivec_snaptime) {
			syslog(LOG_WARNING,
			    "kstat pci_intrs %d snaptime is decreasing",
			    iv->ivec_instance);
			return (INTRD_WALK_ERROR);
		}

		if (iv->ivec_time < ivprev->ivec_time) {
			syslog(LOG_WARNING,
			    "kstat pci_intrs %d value is decreasing",
			    iv->ivec_instance);
			return (INTRD_WALK_ERROR);
		}
		iv->ivec_time -= ivprev->ivec_time;

		iv = list_next(&cs->cs_ivecs, iv);
		ivprev = list_next((list_t *)&csprev->cs_ivecs, ivprev);
	}

	return (INTRD_WALK_NEXT);
}

static boolean_t
stats_differ(const stats_t *s1, const stats_t *s2)
{
	for (size_t i = 0; i < max_cpu; i++) {
		const cpustat_t *c1 = s1->sts_cpu[i];
		const cpustat_t *c2 = s2->sts_cpu[i];

		if (c1 == NULL && c2 == NULL)
			continue;

		if (c1 == NULL || c2 == NULL)
			return (B_TRUE);

		if (c1->cs_nivecs != c2->cs_nivecs)
			return (B_TRUE);

		if (c1->cs_nivecs == 0)
			continue;

		const ivec_t *iv1 = list_head((list_t *)&c1->cs_ivecs);
		const ivec_t *iv2 = list_head((list_t *)&c2->cs_ivecs);

		while (iv1 != NULL && iv2 != NULL) {
			if (iv1->ivec_instance != iv2->ivec_instance)
				return (B_TRUE);

			if (iv1->ivec_ino != iv2->ivec_ino)
				return (B_TRUE);

			if (strcmp(iv1->ivec_buspath, iv2->ivec_buspath) != 0)
				return (B_TRUE);

			iv1 = list_next((list_t *)&c1->cs_ivecs, (void *)iv1);
			iv2 = list_next((list_t *)&c2->cs_ivecs, (void *)iv2);
		}

		if (iv1 != NULL || iv2 != NULL)
			return (B_TRUE);
	}

	return (B_FALSE);
}

stats_t *
stats_delta(const stats_t *restrict st, const stats_t *restrict prev)
{
	if (st == NULL || prev == NULL)
		return (NULL);

	/*
	 * If the kid's match, we should have the same instances, otherwise
	 * we have to check and see if any of the our instances have changed.
	 */
	if (st->sts_kid != prev->sts_kid && stats_differ(st, prev)) {
		printf("new kid\n");
		return (NULL);
	}

	stats_t *delta = stats_dup(st);

	if (cpu_iter(delta, stats_delta_cb, (void *)prev) != INTRD_WALK_DONE) {
		stats_free(delta);
		return (NULL);
	}

	delta->sts_mintime = prev->sts_mintime;
	delta->sts_maxtime = st->sts_maxtime;
	return (delta);
}

static intrd_walk_ret_t
stats_sum_cb(stats_t *sum, cpustat_t *cs, void *arg)
{
	const stats_t *toadd = arg;
	const cpustat_t *toaddcs = toadd->sts_cpu[cs->cs_cpuid];
	boolean_t overflow = B_FALSE;

#define	CS_ADD(_field, _sum, _toadd)					\
	uint64_add((_sum)->cs_ ## _field, (_toadd)->cs_ ## _field,	\
	&(_sum)->cs_ ## _field)

	overflow |= CS_ADD(cpu_nsec_idle, cs, toaddcs);
	overflow |= CS_ADD(cpu_nsec_user, cs, toaddcs);
	overflow |= CS_ADD(cpu_nsec_kernel, cs, toaddcs);
	overflow |= CS_ADD(cpu_nsec_dtrace, cs, toaddcs);
	overflow |= CS_ADD(cpu_nsec_intr, cs, toaddcs);
#undef	CS_ADD

	/*  XXX: write a message? */
	if (overflow)
		return (INTRD_WALK_ERROR);

	list_t *cs_ivecs = &cs->cs_ivecs;
	list_t *toadd_ivecs = (list_t *)&toaddcs->cs_ivecs;
	ivec_t *iv = list_head(cs_ivecs);
	ivec_t *iv_toadd = list_head(toadd_ivecs);
	while (iv != NULL && iv_toadd != NULL) {
		if (uint64_add(iv->ivec_time, iv_toadd->ivec_time,
		    &iv->ivec_time))
			return (INTRD_WALK_ERROR);

		iv = list_next(cs_ivecs, iv);
		iv_toadd = list_next(toadd_ivecs, iv_toadd);
	}
	VERIFY3P(iv, ==, NULL);
	VERIFY3P(iv_toadd, ==, NULL);

	return (INTRD_WALK_NEXT);
}

stats_t *
stats_sum(stats_t * const *restrict deltas, size_t n, size_t *restrict total)
{
	VERIFY3U(n, >, 0);
	VERIFY3P(deltas[0], !=, NULL);

	stats_t *sum = stats_dup(deltas[0]);

	*total = 0;
	for (size_t i = 1; i < n; i++) {
		const stats_t *d = deltas[i];

		if (d == NULL || sum->sts_kid != d->sts_kid)
			continue;

		VERIFY3S(sum->sts_mintime, >, d->sts_mintime);
		VERIFY3S(sum->sts_maxtime, >, d->sts_maxtime);

		sum->sts_mintime = d->sts_mintime;

		if (cpu_iter(sum, stats_sum_cb, (void *)d) != INTRD_WALK_DONE) {
			stats_free(sum);
			return (NULL);
		}
		*total++;
	}

	return (sum);
}

static intrd_walk_ret_t
stats_dup_cb(stats_t *src __unused, cpustat_t *src_cs, void *arg)
{
	stats_t *new_st = arg;
	new_st->sts_cpu[src_cs->cs_cpuid] = cpustat_dup(src_cs);
	return (INTRD_WALK_NEXT);
}

static void
stlgrp_copy(const cpugrp_t *src, cpugrp_t *dst)
{
	dst->cg_id = src->cg_id;
	dst->cg_parent = src->cg_parent;
	dst->cg_children = xcalloc(src->cg_nchildren, sizeof (lgrp_id_t));
	bcopy(src->cg_children, dst->cg_children,
	    src->cg_nchildren * sizeof (lgrp_id_t));
	dst->cg_nchildren = src->cg_nchildren;
}

stats_t *
stats_dup(const stats_t *src)
{
	stats_t *stp;

	stp = stats_new();
	stp->sts_kid = src->sts_kid;
	stp->sts_mintime = src->sts_mintime;
	stp->sts_maxtime = src->sts_maxtime;

	VERIFY3S(cpu_iter((stats_t *)src, stats_dup_cb, stp), ==,
	    INTRD_WALK_DONE);
	sts->sts_ncpu = src->sts_ncpu;

	stp->sts_lgrp = xcalloc(src->sts_nlgrp, sizeof (cpugrp_t));
	for (size_t i = 0; i < src->sts_nlgrp; i++)
		stlgrp_copy(&src->sts_lgrp[i], &stp->sts_lgrp[i]);
	stp->sts_nlgrp = src->sts_nlgrp;

	return (stp);
}

/*
 * Like nicenum, but assumes the value is * 10^(-9) units
 */
void
nanonicenum(uint64_t val, char *buf, size_t buflen)
{
	static const char units[] = "num KMGTPE";
	static const size_t index_max = 9;
	uint64_t divisor = 1;
	int index = 0;
	char u;

	while (index < index_max) {
		uint64_t newdiv = divisor * 1024;

		if (val < newdiv)
			break;
		divisor = newdiv;
		index++;
	}
	u = units[index];

	if (val % divisor == 0) {
		(void) snprintf(buf, buflen, "%llu%c", val / divisor, u);
	} else {
		for (int i = 2; i >= 0; i--) {
			if (snprintf(buf, buflen, "%.*f%c", i,
			    (double)val / divisor, u) <= 5)
				return;
		}
	}
}

static intrd_walk_ret_t
stats_dump_cb(stats_t *stp, cpustat_t *cs, void *dummy __unused)
{
	ivec_t *iv;
	uint64_t total;

	total = cs->cs_cpu_nsec_idle + cs->cs_cpu_nsec_user +
		cs->cs_cpu_nsec_kernel + cs->cs_cpu_nsec_dtrace +
		cs->cs_cpu_nsec_intr;

#define	PCT(_v, _t) ((_t) == 0 ? 0.0 : ((((double)(_v) * 100)) / (_t)))

	(void) printf("  CPU %3d idle: %3.1f%% user: %3.1f%% kern: %3.1f%%"
	    " dtrace: %3.1f%% intr: %3.1f%%\n",
	    cs->cs_cpuid,
	    PCT(cs->cs_cpu_nsec_idle, total),
	    PCT(cs->cs_cpu_nsec_user, total),
	    PCT(cs->cs_cpu_nsec_kernel, total),
	    PCT(cs->cs_cpu_nsec_dtrace, total),
	    PCT(cs->cs_cpu_nsec_intr, total));

	for (iv = list_head(&cs->cs_ivecs); iv != NULL;
	    iv = list_next(&cs->cs_ivecs, iv)) {
		char timebuf[NN_NUMBUF_SZ];

		nanonicenum(iv->ivec_time, timebuf, sizeof (timebuf));
		(void) printf("    %-16s int#%llu pil %llu %6ss (%3.1f%%)\n",
		    custr_cstr(iv->ivec_name), iv->ivec_ino, iv->ivec_pil,
		    timebuf, PCT(iv->ivec_time, total));
	}

	return (INTRD_WALK_NEXT);
}

void
stats_dump(const stats_t *stp)
{
	char timebuf[NN_NUMBUF_SZ] = { 0 };

	VERIFY3S(stp->sts_maxtime, >=, stp->sts_mintime);

	nanonicenum(stp->sts_maxtime - stp->sts_mintime, timebuf,
	    sizeof (timebuf));
	(void) printf("Interval: %ss\n", timebuf);
	cpu_iter((stats_t *)stp, stats_dump_cb, NULL);
	(void) fputc('\n', stdout);
}

static intrd_walk_ret_t
kstat_iter(kstat_ctl_t *restrict kcp, kstat_itercb_t cb, void *restrict arg)
{
	intrd_walk_ret_t ret = INTRD_WALK_DONE;

	for (kstat_t *ksp = kcp->kc_chain; ksp != NULL; ksp = ksp->ks_next) {
		if ((ret = cb(kcp, ksp, arg)) != INTRD_WALK_NEXT)
			return (ret);
	}

	return ((ret == INTRD_WALK_NEXT) ? INTRD_WALK_DONE : ret);
}

intrd_walk_ret_t
cpu_iter(stats_t *stp, cpu_itercb_t cb, void *arg)
{
	intrd_walk_ret_t ret = INTRD_WALK_DONE;

	for (size_t i = 0; i < max_cpu; i++) {
		if (stp->sts_cpu[i] == NULL)
			continue;

		if ((ret = cb(stp, stp->sts_cpu[i], arg)) != INTRD_WALK_NEXT)
			return (ret);
	}
	return ((ret == INTRD_WALK_NEXT) ? INTRD_WALK_DONE : ret);
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

	stp->sts_kid = 0;
	stp->sts_mintime = INT64_MAX;
	stp->sts_maxtime = INT64_MIN;

	for (i = 0; i < max_cpu; i++) {
		cpustat_free(stp->sts_cpu[i]);
		stp->sts_cpu[i] = NULL;
	}
	stp->sts_ncpu = 0;

	for (i = 0; i < stp->sts_nlgrp; i++)
		free(stp->sts_lgrp[i].cg_children);
	free(stp->sts_lgrp);
	stp->sts_lgrp = NULL;
	stp->sts_nlgrp = 0;
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
	VERIFY3U(cs->cs_nivecs, ==, 0);

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
	cs->cs_lgrp = src->cs_lgrp;
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
	stats_t *stp = buf;
	size_t len = max_cpu * sizeof (cpustat_t *);

	bzero(stp, sizeof (*stp));
	stp->sts_cpu = umem_zalloc(len, UMEM_NOFAIL);
	stp->sts_mintime = INT64_MAX;
	stp->sts_maxtime = INT64_MIN;
	return (0);
}

static void
stats_dtor(void *buf, void *dummy __unused)
{
	stats_t *stp = buf;
	size_t len = max_cpu * sizeof (cpustat_t *);
	umem_free(stp->sts_cpu, len);
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
	    sizeof (stats_t), 8, stats_ctor, stats_dtor, NULL, NULL, NULL,
	    0)) == NULL) {
		err(EXIT_FAILURE, "unable to create stats cache");
	}
}
