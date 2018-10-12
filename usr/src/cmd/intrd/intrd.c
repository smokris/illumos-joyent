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

#include <sys/kstat.h>
#include <kstat.h>
#include <inttypes.h>
#include <sys/debug.h>
#include <sys/list.h>
#include <string.h>
#include <stdlib.h>
#include <stddef.h>
#include <err.h>

typedef struct ivec {
	list_node_t	ivec_node;
	hrtime_t	ivec_time;
	hrtime_t	ivec_crtime;
	uint64_t	ivec_cookie;
	uint64_t	ivec_pil;
	uint64_t	ivec_ino;
	uint64_t	ivec_num_ino;
	char		*ivec_buspath;
	char		*ivec_name;
} ivec_t;

typedef struct cpustat {
	list_node_t	cs_node;
	uint64_t	cs_cpuid;
	hrtime_t	cs_crtime;
	uint64_t	cs_total;
	list_t		cs_ivecs;
} cpustat_t;

typedef struct istat {
	list_t	is_cpu;
	size_t	is_ncpu;
	hrtime_t is_snaptime;
} istat_t;

typedef struct delta_cpu {
	list_node_t	dc_node;
	uint64_t	dc_intrs;
	uint64_t	dc_total;
	hrtime_t	dc_bigintr;
	double		dc_intrload;
} delta_cpu_t;

typedef struct delta {
	boolean_t	d_missing;
	hrtime_t	d_minsnap;
	hrtime_t	d_maxsnap;
	double		d_avg_intrload;
	uint64_t	d_avg_intrnsec;
	list_t		d_cpus;
	size_t		d_ncpus;
} delta_t;

static istat_t *istat_new(void);
static cpustat_t *cpustat_new(void);
static ivec_t *ivec_new(void);
static char *xstrdup(const char *);

cpustat_t *get_cpustat(istat_t *, uint64_t);

static delta_t *generate_delta(istat_t *restrict, istat_t *restrict);
static istat_t *get_stat(kstat_ctl_t *);

int
main(int argc, char **argv)
{
	kstat_ctl_t *kcp;

	if ((kcp = kstat_open()) == NULL)
		err(EXIT_FAILURE, "could not open /dev/kstat");


	return (0);
}

static delta_t *
generate_delta(istat_t *restrict is, istat_t *restrict isnew)
{
	delta_t *d = calloc(1, sizeof (*d));
	cpustat_t *cs, *csnew;

	if (d == NULL)
		err(EXIT_FAILURE, "calloc failed");

	d->d_minsnap = is->is_snaptime;
	d->d_maxsnap = isnew->is_snaptime;
	if (d->d_minsnap > d->d_maxsnap) {
		syslog(LOG_WARNING, "stats aren't ascending");
		free(d);
		return (NULL);
	}

	if (is->is_ncpu != isnew->is_ncpu) {
		syslog(LOG_DEBUG, "number of CPUs has changed");
		free(d);
		return (NULL);
	}

	for (cs = list_head(&is->is_cpu); cs != NULL;
	    cs = list_next(&is->is_cpu, cs)) {
		csnew = get_cpustat(isnew, cs->cs_cpuid);
		if (csnew == NULL) {
			free(d);
			return (NULL);
		}

		if (csnew->cs_total < cs->cs_total) {
			syslog(LOG_WARNING, "deltas are not ascending");
			free(d);
			return (NULL);
		}

		if ((d->d_total = csnew->cs_total - cs->cs_total) == 0)
			d->d_total = 1;

	}
}

enum {
	KSM_UNKNOWN,
	KSM_CPUINFO,
	KSM_PCIINTR
};

static istat_t *
get_stat(kstat_ctl_t *kcp)
{
	istat_t *is;
	kstat_t *ksp;
	kid_t kid;

	if ((kid = kstat_chain_update(kcp)) == 0)
		return (NULL);

	if (kid == -1)
		err(EXIT_FAILURE, "failed to update kstat chain");

	is = istat_new();

	for (ksp = kcp->kc_chain; ksp != NULL; ksp = ksp->ks_next) {
		int which = KSM_UNKNOWN;

		if (strcmp(ksp->ks_module, "cpu_info") == 0)
			which = KSM_CPUINFO;
		else if (strcmp(ksp->ks_module, "pci_intrs") == 0)
			which = KSM_PCIINTR;

		if (which == KSM_UNKNOWN)
			continue;


	}
}

cpustat_t *
get_cpustat(istat_t *is, uint64_t id)
{
	cpustat_t *cs;

	for (cs = list_head(&is->is_cpu); cs != NULL;
	    cs = list_next(&is->is_cpu, cs)) {
		if (cs->cs_cpuid == id)
			return (cs);
	}

	return (NULL);
}

static istat_t *
istat_new(void)
{
	istat_t *is = calloc(1, sizeof (*is));

	if (is == NULL)
		err(EXIT_FAILURE, "calloc failed");

	list_create(&is->is_cpu, sizeof (cpustat_t),
	    offsetof (cpustat_t, cs_node));

	return (is);
}

static cpustat_t *
cpustat_new(void)
{
	cpustat_t *cs = calloc(1, sizeof (*cs));

	if (cs == NULL)
		err(EXIT_FAILURE, "calloc failed");

	list_create(&cs->cs_ivecs, sizeof (ivec_t),
	    offsetof(ivec_t, ivec_node));

	return (cs);
}

static ivec_t *
ivec_new(void)
{
	ivec_t *iv = calloc(1, sizeof (*iv));

	if (iv == NULL)
		err(EXIT_FAILURE, "calloc failed");

	return (iv);
}

static char *
xstrdup(const char *s)
{
	char *p = strdup(s);

	if (p == NULL)
		err(EXIT_FAILURE, "strdup failed");
	return (p);
}
