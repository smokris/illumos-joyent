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
#include <string.h>
#include <strings.h>
#include <syslog.h>
#include <unistd.h>
#include <umem.h>
#include <sys/debug.h>
#include <sys/errno.h>
#include <sys/kstat.h>

typedef struct config {
	uint_t	cfg_interval;
	uint_t	cfg_idle_interval;
	uint_t	cfg_retry_interval;
	// idle_load
	uint_t	cfg_avginterval;
	double	cfg_tooslow;
	double	cfg_unsafe_load;
	double	cfg_mindelta;
} config_t;

typedef struct ivec {
	hrtime_t	ivec_crtime;
	int		ivec_instance;
	int		ivec_cpuid;
	uint64_t	ivec_cookie;
	uint64_t	ivec_pil;
	uint64_t	ivec_ino;
	uint64_t	ivec_time;
	char		*ivec_buspath;
	char		ivec_name[16]; /* sizeof kstat_named_t.value.c */
	char		ivec_type[16];	/* sizeof kstat_named_t.value.c */
} ivec_t;

typedef struct cpustat {
	hrtime_t	cs_crtime;
	int		cs_cpuid;
	boolean_t	cs_online;
	uint64_t	cs_cpu_nsec_idle;
	uint64_t	cs_cpu_nsec_user;
	uint64_t	cs_cpu_nsec_kernel;
	uint64_t	cs_cpu_nsec_dtrace;
	uint64_t	cs_cpu_nsec_intr;
} cpustat_t;

typedef struct stats {
	cpustat_t	*sts_cpu;
	size_t		sts_ncpu;
	ivec_t		*sts_ivec;
	size_t		sts_nivec;
	boolean_t	sts_changed;
	hrtime_t	sts_mintime;
	hrtime_t	sts_maxtime;
} stats_t;

enum {
	KITER_NEXT = 0,
	KITER_DONE,
	KITER_STOP
};

typedef int (*kstat_itercb_t)(kstat_ctl_t *restrict, kstat_t *restrict,
    void *restrict);
static int kstat_iter(kstat_ctl_t *restrict, kstat_itercb_t, void *restrict);

static int cpustat_cmp(const void *, const void *);
static int ivec_cmp(const void *, const void *);
static char *xstrdup(const char *);
static stats_t *stats_dup(const stats_t *);
static void stats_free(stats_t *);

static stats_t *calc_delta(const stats_t *restrict, const stats_t *restrict);
static stats_t *get_stats(const config_t *restrict, kstat_ctl_t *restrict,
    uint_t);
static void loop(const config_t *restrict, kstat_ctl_t *restrict);

static volatile boolean_t quit;

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
	config_t cfg = { 0 };

	umem_nofail_callback(nomem);

	if ((kcp = kstat_open()) == NULL)
		err(EXIT_FAILURE, "could not open /dev/kstat");

	loop(&cfg, kcp);
	kstat_close(kcp);

	return (0);
}

static void
loop(const config_t *restrict cfg, kstat_ctl_t *restrict kcp)
{
	const size_t deltas_sz = cfg->cfg_avginterval / cfg->cfg_interval + 1;

	stats_t *stats[2] = { 0 };
	stats_t *stp = NULL;
	stats_t *delta = NULL;
	stats_t **deltas = NULL;
	size_t ndeltas = 0;
	int gen = 0;

	if ((deltas = calloc(deltas_sz, sizeof (stats_t *))) == NULL)
		err(EXIT_FAILURE, "calloc failed");

	while (!quit) {
		uint_t interval = cfg->cfg_interval;

		if ((stp = get_stats(cfg, kcp, interval)) == NULL) {
			/*
			 * Something (cpu, new device, etc) was added while
			 * we were reading our stats, or we took too long to
			 * read our stats.   Reset and try again.
			 */
			sleep(cfg->cfg_retry_interval);
			continue;
		}

		stats_free(stats[gen]);
		stats[gen] = stp;
		delta = calc_delta(stats[gen], stats[gen ^ 1]);
		gen ^= 1;

		if (delta == NULL || delta->sts_changed)
			continue;

		sleep(interval);
	}

	stats_free(stats[0]);
	stats_free(stats[1]);
}

static stats_t *
calc_delta(const stats_t *restrict st, const stats_t *restrict stprev)
{
	stats_t *delta = NULL;
	cpustat_t *cs, *csd;
	ivec_t *iv, *ivd;
	size_t i;

	if (st->sts_ncpu != stprev->sts_ncpu)
		return (NULL);
	if (st->sts_nivec != stprev->sts_nivec)
		return (NULL);

	delta = stats_dup(st);

	cs = stprev->sts_cpu;
	csd = delta->sts_cpu;

#define	CS_SUB(field, d, c) \
	if ((d)->cs_ ## field < (c)->cs_ ## field) { \
		syslog(LOG_WARNING, "%s kstat is decreasing", #field); \
		goto fail; \
	} \
	(d)->cs_ ## field -= (c)->cs_ ## field;

	for (i = 0; i < st->sts_ncpu; i++, cs++, csd++) {
		VERIFY(cs->cs_online);
		VERIFY(csd->cs_online);

		if (csd->cs_cpuid != cs->cs_cpuid)
			goto fail;

		if (csd->cs_crtime < cs->cs_crtime) {
			syslog(LOG_WARNING, "kstat time is not increasing");
			goto fail;
		}

		csd->cs_crtime -= cs->cs_crtime;
		CS_SUB(cpu_nsec_idle, csd, cs);
		CS_SUB(cpu_nsec_user, csd, cs);
		CS_SUB(cpu_nsec_kernel, csd, cs);
		CS_SUB(cpu_nsec_dtrace, csd, cs);
		CS_SUB(cpu_nsec_intr, csd, cs);
	}
#undef CS_SUB

	iv = stprev->sts_ivec;
	ivd = delta->sts_ivec;
	for (i = 0; i < st->sts_nivec; i++, iv++, ivd++) {
		if (ivd->ivec_instance != iv->ivec_instance ||
		    ivd->ivec_cpuid != iv->ivec_cpuid ||
		    ivd->ivec_ino != iv->ivec_ino ||
		    strcmp(ivd->ivec_buspath, iv->ivec_buspath) != 0)
			goto fail;

		if (ivd->ivec_crtime < iv->ivec_crtime) {
			goto fail;
		}
		if (ivd->ivec_time < iv->ivec_time) {
			goto fail;
		}
		ivd->ivec_time -= iv->ivec_time;
	}

	return (delta);

fail:
	stats_free(delta);
	return (NULL);
}

static stats_t *
sum_deltas(const stats_t **deltas, size_t n)
{
	return (NULL);
}

static void
consolidate_ivecs(stats_t *stp)
{}

struct count_info {
	size_t	ci_ncpuinfo;
	size_t	ci_ncpu;
	size_t	ci_nivec;
};

static int
count_kstats(kstat_ctl_t *restrict kcp, kstat_t *restrict ksp, void *arg)
{
	struct count_info *count = arg;

	if (strcmp(ksp->ks_module, "cpu_info") == 0)
		count->ci_ncpuinfo++;
	else if (strcmp(ksp->ks_module, "cpu") == 0 &&
	    strcmp(ksp->ks_name, "sys") == 0)
		count->ci_ncpu++;
	else if (strcmp(ksp->ks_module, "ivec") == 0 &&
	    strcmp(ksp->ks_name, "npe") == 0)
		count->ci_nivec++;

	return (KITER_NEXT);
}

struct read_info {
	stats_t *ri_statsp;
	size_t	ri_count;
};

static int
do_cpu_info(kstat_ctl_t *restrict kcp, kstat_t *restrict ksp, void *arg)
{
	/*
	 * Cache the index of the cpu state field in the cpu_info kstat.
	 */
	static uint_t hint = -1;

	struct read_info *rip = arg;

	if (strcmp(ksp->ks_module, "cpu_info") != 0)
		return (KITER_NEXT);

	cpustat_t *cs = rip->ri_statsp->sts_cpu + rip->ri_count++;

	if (kstat_read(kcp, ksp, NULL) == -1) {
		if (errno == ENXIO) {
			/*
			 * Our kstat has been removed since the update;
			 * just ignore and continue.
			 */
			return (KITER_NEXT);
		}
		err(EXIT_FAILURE, "unable to read kstat %s:%d",
		    ksp->ks_name, ksp->ks_instance);
	}

	VERIFY3S(ksp->ks_type, ==, KSTAT_TYPE_NAMED);
	cs->cs_cpuid = ksp->ks_instance;

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
	if (strcmp(KSTAT_NAMED_STR_PTR(&nm[hint]), "on-line") == 0)
		cs->cs_online = B_TRUE;

	return (KITER_NEXT);
}

static int
do_cpu(kstat_ctl_t *restrict kcp, kstat_t *restrict ksp, void *restrict arg)
{
	static int idle = -1;
	static int kernel = -1;
	static int user = -1;
	static int dtrace = -1;
	static int intr = -1;

	stats_t *stp = arg;
	cpustat_t *cs = NULL;

	if (strcmp(ksp->ks_module, "cpu") != 0)
		return (KITER_NEXT);
	if (strcmp(ksp->ks_name, "sys") != 0)
		return (KITER_NEXT);

	for (uint_t i = 0; i < stp->sts_ncpu; i++) {
		if (stp->sts_cpu[i].cs_cpuid == ksp->ks_instance) {
			cs = &stp->sts_cpu[i];
			break;
		}
	}

	if (cs == NULL) {
		stp->sts_changed = B_TRUE;
		return (KITER_DONE);
	}

	if (kstat_read(kcp, ksp, NULL) == -1) {
		if (errno == ENXIO) {
			stp->sts_changed = B_TRUE;
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

	cs->cs_crtime = ksp->ks_crtime;
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

	ivec_t *ivp = rip->ri_statsp->sts_ivec + rip->ri_count++;

	if (kstat_read(kcp, ksp, NULL) == -1) {
		if (errno = ENXIO) {
			rip->ri_statsp->sts_changed = B_TRUE;
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

	ivp->ivec_instance = ksp->ks_instance;
	ivp->ivec_crtime = ksp->ks_snaptime;
	ivp->ivec_cookie = nm[cookie].value.ui64;
	ivp->ivec_pil = nm[pil].value.ui64;
	ivp->ivec_ino = nm[ino].value.ui64;
	VERIFY3U(nm[ino].value.ui64, <=, INT_MAX);
	ivp->ivec_cpuid = (int)nm[cpu].value.ui64;
	ivp->ivec_time = nm[f_time].value.ui64;
	ivp->ivec_buspath = xstrdup(KSTAT_NAMED_STR_PTR(&nm[buspath]));
	(void) strlcpy(ivp->ivec_name, nm[name].value.c,
	    sizeof (ivp->ivec_name));
	(void) strlcpy(ivp->ivec_type, nm[type].value.c,
	    sizeof (ivp->ivec_type));

	return (KITER_NEXT);
}

static stats_t *
get_stats(const config_t *restrict cfg, kstat_ctl_t *restrict kcp,
    uint_t interval)
{
	stats_t *sts;
	kstat_t *ksp;
	kid_t kid;

	if ((kid = kstat_chain_update(kcp)) == 0)
		return (NULL);

	if (kid == -1)
		err(EXIT_FAILURE, "failed to update kstat chain");

	struct count_info count = { 0 };

	(void) kstat_iter(kcp, count_kstats, &count);
	if (count.ci_ncpuinfo != count.ci_ncpu) {
		return (NULL);
	}

	if ((sts = calloc(1, sizeof (*sts))) == NULL)
		err(EXIT_FAILURE, "calloc failed");

	if ((sts->sts_cpu = calloc(count.ci_ncpu, sizeof (cpustat_t))) == NULL)
		err(EXIT_FAILURE, "calloc failed");
	sts->sts_ncpu = count.ci_ncpu;

	if ((sts->sts_ivec = calloc(count.ci_nivec, sizeof (ivec_t))) == NULL)
		err(EXIT_FAILURE, "calloc failed");
	sts->sts_nivec = count.ci_nivec;

	sts->sts_mintime = INT64_MAX;
	sts->sts_maxtime = INT64_MIN;

	struct read_info read_info = {
		.ri_statsp = sts,
		.ri_count = 0,
	};
	(void) kstat_iter(kcp, do_cpu_info, &read_info);
	(void) kstat_iter(kcp, do_cpu, &read_info);

	read_info.ri_count = 0;
	(void) kstat_iter(kcp, get_ivecs, &read_info);

	if (sts->sts_changed) {
		stats_free(sts);
		return (NULL);
	}

	qsort(sts->sts_cpu, sts->sts_ncpu, sizeof (cpustat_t), cpustat_cmp);
	qsort(sts->sts_ivec, sts->sts_nivec, sizeof (ivec_t), ivec_cmp);

	size_t i;

	/*
	 * Offline CPUs should be sorted to the end of the list.  If we
	 * encounter an offline CPU, truncate the list at that point and
	 * stop.
	 */
	for (i = 0; i < sts->sts_ncpu; i++) {
		if (sts->sts_cpu[i].cs_online)
			continue;

		if (i == 0) {
			syslog(LOG_WARNING, "all cpus are reporting offline");
			stats_free(sts);
			return (NULL);
		}

		sts->sts_cpu = realloc_array(sts->sts_cpu, i,
		    sizeof (cpustat_t));
		VERIFY3P(sts->sts_cpu, !=, NULL);
		sts->sts_ncpu = i;
		break;
	}

	/*
	 * Similarly for ivecs, disabled ones are sorted last.  If we
	 * encounter a disabled ivec, truncate the list at that point.
	 */
	for (i = 0; i < sts->sts_nivec; i++) {
		if (strcmp(sts->sts_ivec[i].ivec_type, "disabled") != 0)
			continue;

		if (i == 0) {
			syslog(LOG_WARNING, "all interrupts are reporting "
			    "disabled");
			stats_free(sts);
			return (NULL);
		}

		sts->sts_nivec = realloc_array(sts->sts_ivec, i,
		    sizeof (ivec_t));
		VERIFY3P(sts->sts_ivec, !=, NULL);
		sts->sts_nivec = i;
		break;
	}

	for (i = 0; i < sts->sts_ncpu; i++) {
		if (sts->sts_cpu[i].cs_crtime < sts->sts_mintime)
			sts->sts_mintime = sts->sts_cpu[i].cs_crtime;
		if (sts->sts_cpu[i].cs_crtime > sts->sts_maxtime)
			sts->sts_maxtime = sts->sts_cpu[i].cs_crtime;
	}
	for (i = 0; i < sts->sts_nivec; i++) {
		if (sts->sts_ivec[i].ivec_crtime < sts->sts_mintime)
			sts->sts_mintime = sts->sts_ivec[i].ivec_crtime;
		if (sts->sts_ivec[i].ivec_crtime > sts->sts_maxtime)
			sts->sts_maxtime = sts->sts_ivec[i].ivec_crtime;
	}

	hrtime_t timediff = sts->sts_maxtime - sts->sts_mintime;
	if ((double)timediff / interval > cfg->cfg_tooslow) {
		stats_free(sts);
		return (NULL);
	}

	return (sts);
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

static char *
xstrdup(const char *s)
{
	char *p = strdup(s);

	if (p == NULL)
		err(EXIT_FAILURE, "strdup failed");
	return (p);
}

static stats_t *
stats_dup(const stats_t *src)
{
	stats_t *stp;

	if ((stp = calloc(1, sizeof (*stp))) == NULL)
		err(EXIT_FAILURE, "calloc failed");

	stp->sts_ncpu = src->sts_ncpu;
	stp->sts_nivec = src->sts_nivec;
	stp->sts_cpu = calloc(stp->sts_ncpu, sizeof (cpustat_t));
	stp->sts_ivec = calloc(stp->sts_nivec, sizeof (ivec_t));
	if (stp->sts_cpu == NULL || stp->sts_ivec == NULL)
		err(EXIT_FAILURE, "calloc failed");

	bcopy(src->sts_cpu, stp->sts_cpu, src->sts_ncpu * sizeof (cpustat_t));
	bcopy(src->sts_ivec, stp->sts_ivec, src->sts_nivec * sizeof (ivec_t));

	ivec_t *iv;
	size_t i;
	for (i = 0, iv = stp->sts_ivec; i < stp->sts_nivec; i++, iv++) {
		iv->ivec_buspath = strdup(src->sts_ivec[i].ivec_buspath);
		if (iv->ivec_buspath == NULL)
			err(EXIT_FAILURE, "strdup failed");
	}

	return (stp);
}

static void
stats_free(stats_t *stp)
{
	if (stp == NULL)
		return;
	free(stp->sts_cpu);
	free(stp->sts_ivec);
	free(stp);
}

/*
 * sort by: online/!online, cpuid
 */
static int
cpustat_cmp(const void *a, const void *b)
{
	const cpustat_t *l = a;
	const cpustat_t *r = b;

	if (l->cs_online != r->cs_online) {
		if (!l->cs_online)
			return (1);
		if (!r->cs_online)
			return (-1);
	}

	if (l->cs_cpuid < r->cs_cpuid)
		return (-1);
	if (l->cs_cpuid > r->cs_cpuid)
		return (1);

	return (0);
}

/*
 * sort by: !disabled/disabled, instance
 */
static int
ivec_cmp(const void *a, const void *b)
{
	const ivec_t *l = a;
	const ivec_t *r = b;

	if (strcmp(l->ivec_type, r->ivec_type) != 0) {
		if (strcmp(l->ivec_type, "disabled") == 0)
			return (1);
		if (strcmp(r->ivec_type, "disabled") == 0)
			return (-1);
	}

	if (l->ivec_instance < r->ivec_instance)
		return (-1);
	if (l->ivec_instance > r->ivec_instance)
		return (1);

	return (0);
}

/*
 * sort by cpu, buspath, interrupt number (ino)
 */
static int
ivec_cmp2(const void *a, const void *b)
{
	const ivec_t *l = a;
	const ivec_t *r = b;
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

	return (0);
}
