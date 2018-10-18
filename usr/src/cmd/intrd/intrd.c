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

static int intrd_daemonize(void);
static void intrd_dfatal(int, const char *, ...);
static void setup(kstat_ctl_t **restrict, config_t *restrict);
static void loop(const config_t *restrict, kstat_ctl_t *restrict);
static void delta_save(stats_t **, size_t, stats_t *, uint_t);

uint_t max_cpu;

#ifdef DEBUG
const char *
_umem_debug_init(void)
{
	return ("default,verbose");
}

const char *
_umem_logging_init(void)
{
	return ("fail,contents");
}
#endif

static int
nomem(void)
{
	(void) fprintf(stderr, "Out of memory\n");
	return (UMEM_CALLBACK_EXIT(255));
}

int
main(int argc, char **argv)
{
	kstat_ctl_t *kcp;
	config_t cfg = {
		.cfg_interval = 10,
		.cfg_idle_interval = 45,
		.cfg_retry_interval = 1,
		.cfg_avginterval = 60,
		.cfg_statslen = 120,
		.cfg_tooslow = 0.05
	};
	int dfd, status;

	umem_nofail_callback(nomem);

#if 0
	dfd = intrd_daemonize();
#endif

	setup(&kcp, &cfg);

#if 0
	status = 0;
	(void) write(dfd, &status, sizeof (status));
	(void) close(dfd);
#endif

	loop(&cfg, kcp);

	kstat_close(kcp);
	return (0);
}

static int
intrd_daemonize(void)
{
	sigset_t set, oset;
	int estatus, pfds[2];
	pid_t child;
	priv_set_t *pset;

	if (chdir("/") != 0)
		err(EXIT_FAILURE, "failed to chdir /");

	/*
	 * At this point, block all signals going in so we don't have the parent
	 * mistakingly exit when the child is running, but never block SIGABRT.
	 */
	if (sigfillset(&set) != 0)
		abort();
	if (sigdelset(&set, SIGABRT) != 0)
		abort();
	if (sigprocmask(SIG_BLOCK, &set, &oset) != 0)
		abort();

	/*
	 * Do the fork+setsid dance.
	 */
	if (pipe(pfds) != 0)
		err(EXIT_FAILURE, "failed to create pipe for daemonizing");

	if ((child = fork()) == -1)
		err(EXIT_FAILURE, "failed to fork for daemonizing");

	if (child != 0) {
		/* We'll be exiting shortly, so allow for silent failure */
		(void) close(pfds[1]);
		if (read(pfds[0], &estatus, sizeof (estatus)) ==
		    sizeof (estatus))
			_exit(estatus);

		if (waitpid(child, &estatus, 0) == child && WIFEXITED(estatus))
			_exit(WEXITSTATUS(estatus));

		_exit(EXIT_FAILURE);
	}

	/*
	 * Drop privileges.
	 * XXX: Should we run as nobody and maybe have SMF give us
	 * basic + PRIV_SYS_RES_CONFIG
	 */
	if (setgroups(0, NULL) != 0)
		abort();
	if ((pset = priv_allocset()) == NULL)
		abort();

	priv_basicset(pset);
	if (priv_delset(pset, PRIV_PROC_EXEC) == -1 ||
	    priv_delset(pset, PRIV_PROC_INFO) == -1 ||
	    priv_delset(pset, PRIV_PROC_FORK) == -1 ||
	    priv_delset(pset, PRIV_PROC_SESSION) == -1 ||
	    priv_delset(pset, PRIV_FILE_LINK_ANY) == -1 ||
	    priv_addset(pset, PRIV_SYS_RES_CONFIG) == -1) {
		abort();
	}

	if (setppriv(PRIV_SET, PRIV_PERMITTED, pset) == -1)
		abort();
	if (setppriv(PRIV_SET, PRIV_EFFECTIVE, pset) == -1)
		abort();

	priv_freeset(pset);

	if (close(pfds[0]) != 0)
		abort();
	if (setsid() == -1)
		abort();
	if (sigprocmask(SIG_SETMASK, &oset, NULL) != 0)
		abort();
	(void) umask(0022);

	return (pfds[1]);
}

static void
setup(kstat_ctl_t **restrict kcpp, config_t *restrict cfg)
{
	kstat_ctl_t *kcp;
	long val;

	intrd_kstat_init();

	if ((kcp = kstat_open()) == NULL)
		err(EXIT_FAILURE, "could not open /dev/kstat");
	*kcpp = kcp;

	if ((val = sysconf(_SC_NPROCESSORS_MAX)) == -1)
		err(EXIT_FAILURE, "sysconf(_SC_NPROCESSORS_MAX) failed");

	if (val > UINT32_MAX || val <= 0) {
		errx(EXIT_FAILURE, "max # of processors (%ld) of range "
		    "[1, %u]", val, UINT32_MAX);
	}
	max_cpu = (uint_t)val;

	// XXX: Initialize cfg
}

static void
loop(const config_t *restrict cfg, kstat_ctl_t *restrict kcp)
{
	printf("avg int: %u interval: %u\n", cfg->cfg_avginterval, cfg->cfg_interval); fflush(stdout);

	const size_t deltas_sz = cfg->cfg_avginterval / cfg->cfg_interval + 1;

	stats_t *stats[2] = { 0 };
	stats_t **deltas = NULL;
	stats_t *delta = NULL, *sum = NULL;
	size_t ndeltas = 0;
	uint_t interval = cfg->cfg_interval;
	int gen = 0;

	deltas = xcalloc(deltas_sz, sizeof (stats_t *));

	for (;; sleep(interval)) {
		stats_free(stats[gen]);
		if ((stats[gen] = stats_get(cfg, kcp, interval)) == NULL)
			continue;

		delta = stats_delta(stats[gen], stats[gen ^ 1]);
		gen ^= 1;

		if (delta == NULL) {
			/*
			 * Something changed between the current and previous
			 * stat collection.  Try again later.
			 */
			(void) printf("NULL delta\n");
			continue;
		}
		delta_save(deltas, deltas_sz, delta, cfg->cfg_statslen);
		sum = stats_sum(deltas, deltas_sz, &ndeltas);

		printf("Delta\n");
		stats_dump(delta);
	}
}

static void
delta_save(stats_t **deltas, size_t n, stats_t *newdelta, uint_t statslen)
{
	hrtime_t cutoff, prevtime = INT64_MAX;
	size_t i, j;

	VERIFY3U(n, >, 1);

	cutoff = newdelta->sts_maxtime - (hrtime_t)statslen * NANOSEC;

	for (i = 0; i < n; i++) {
		if (deltas[i] == NULL)
			continue;

		/* These should be in order from newest to oldest */
		VERIFY3S(prevtime, >, deltas[i]->sts_mintime);
		prevtime = deltas[i]->sts_mintime;

		if (deltas[i]->sts_mintime >= cutoff)
			continue;

		for (j = i; i < n; i++) {
			stats_free(deltas[j]);
			deltas[j] = NULL;
		}
		break;
	}

	/* If all the slots are full, drop the last entry */
	if (i == n) {
		i = n - 1;
		stats_free(deltas[i]);
	}

	/* Move everything over one slot */
	(void) memmove(deltas + 1, deltas, i * sizeof (stats_t *));
	deltas[0] = newdelta;
}

static void
calc_lgrp_load(cpugrp_t *grp, load_t *ld, lgrp_id_t id)
{
	cpugrp_t *cg = grp + id;
	load_t *lgrp = LOAD_LGRP(ld, id);

	for (size_t i = 0; i < cg->cg_nchildren; i++) {
		calc_lgrp_load(grp, ld, cg->cg_children[i]);

		load_t *lchild = LOAD_LGRP(ld, cg->cg_children[i]);

		lgrp->ld_total += lchild->ld_total;
		lgrp->ld_intrtotal += lchild->ld_intrtotal;
		lgrp->ld_bigint = LOAD_MAXINT(lgrp, lchild);
	}

}

static load_t *
calc_load(stats_t *stp)
{
	load_t *ld = xcalloc(max_cpu + stp->sts_nlgrp, sizeof (load_t));
	uint64_t sum, intrsum;
	ivec_t *bigint;

	for (size_t i = 0; i < stp->sts_ncpu; i++) {
		cpustat_t *cs = stp->sts_cpu[i];
		load_t *lcpu = LOAD_CPU(ld, cs->cs_cpuid);
		load_t *llgrp = LOAD_LGRP(ld, cs->cs_lgrp);
		ivec_t *iv;

		lcpu->ld_total = cs->cs_cpu_nsec_idle + cs->cs_cpu_nsec_user +
		    cs->cs_cpu_nsec_kernel + cs->cs_cpu_nsec_dtrace +
		    cs->cs_cpu_nsec_intr;

		for (iv = list_head(&cs->cs_ivecs); iv != NULL;
		    iv = list_next(&cs->cs_ivecs, iv)) {
			lcpu->ld_intrtotal += iv->ivec_time;
			if (lcpu->ld_bigint == NULL ||
			    lcpu->ld_bigint->ivec_time < iv->ivec_time)
				lcpu->ld_bigint = iv;
		}

		llgrp->ld_total += lcpu->ld_total;
		llgrp->ld_intrtotal += lcpu->ld_intrtotal;
		llgrp->ld_bigint = LOAD_MAXINT(llgrp, lcpu);
	}

	calc_lgrp_load(stp->sts_lgrp, ld, 0);

	return (ld);
}

static void *
filter(void *arr, size_t n, void *(*cb)(void *, void *), void *arg)
{
	char **pp = arr;
	char **new = xcalloc(n, sizeof (char *));
	size_t len = 0;

	for (size_t i = 0; i < n; i++) {
		void *p = cb(pp[i], arg);

		if (p != NULL) {
			new[len++] = p;
		}
	}

	if (len == 0) {
		free(new);
		return (NULL);
	}

	return (xreallocarray(new, len, sizeof (char *)));
}

int
cpustat_cmp_id(const void *a, const void *b)
{
	const cpustat_t *l = *((cpustat_t **)a);
	const cpustat_t *r = *((cpustat_t **)b);

	if (l->cs_cpuid < r->cs_cpuid)
		return (-1);
	if (l->cs_cpuid > r->cs_cpuid)
		return (1);

	return (0);
}

int
ivec_cmp_id(const void *a, const void *b)
{
	const ivec_t *l = *((ivec_t **)a);
	const ivec_t *r = *((ivec_t **)b);

	if (l->ivec_instance < r->ivec_instance)
		return (-1);
	if (l->ivec_instance > r->ivec_instance)
		return (1);

	return (0);
}

int
ivec_cmp_cpu(const void *a, const void *b)
{
	const ivec_t *l = *((ivec_t **)a);
	const ivec_t *r = *((ivec_t **)b);
	int ret;

	if (l->ivec_cpuid < r->ivec_cpuid)
		return (-1);
	if (l->ivec_cpuid > r->ivec_cpuid)
		return (1);

	if ((ret = strcmp(l->ivec_buspath, r->ivec_buspath)) != 0)
		return ((ret != 1) ? -1 : 1);

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

char *
xstrdup(const char *s)
{
	char *p = strdup(s);

	if (p == NULL)
		err(EXIT_FAILURE, "strdup failed");
	return (p);
}

void *
xcalloc(size_t nelem, size_t eltsize)
{
	void *p = calloc(nelem, eltsize);

	if (p == NULL && nelem > 0)
		err(EXIT_FAILURE, "calloc failed");
	return (p);
}

void *
xreallocarray(void *p, size_t n, size_t elsize)
{
	void *newp = reallocarray(p, n, elsize);

	if (newp == NULL && n > 0)
		err(EXIT_FAILURE, "reallocarray failed");
	return (newp);
}

static void
intrd_dfatal(int dfd, const char *fmt, ...)
{
	int status = EXIT_FAILURE;
	va_list ap;

	va_start(ap, fmt);
	(void) vfprintf(stderr, fmt, ap);
	va_end(ap);

	(void) write(dfd, &status, sizeof (status));
	exit(status);
}
