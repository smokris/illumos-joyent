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

typedef struct cpuload {
	int		cl_cpuid;
	uint64_t	cl_intrmax;
	uint64_t	cl_intrsum;
	double		dl_avgintload;
	double		dl_avgitnsec;
} cpuload_t;

static int ivec_ctor(void *, void *, int);
static void ivec_dtor(void *, void *);

static void loop(const config_t *restrict, kstat_ctl_t *restrict);
static void delta_save(stats_t **, size_t, stats_t *, uint_t);

static umem_cache_t *ivec_cache;

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

	if ((ivec_cache = umem_cache_create("ivec cache", sizeof (ivec_t), 8,
	    ivec_ctor, ivec_dtor, NULL, NULL, NULL, 0)) == NULL)
		err(EXIT_FAILURE, "unable to create ivec_cache");

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
			continue;
		}
		delta_save(deltas, delta_sz, delta, statslen);

		sum = stats_sum(deltas, deltas_sz, &ndeltas);

	}

}

static void
delta_save(stats_t **deltas, size_t n, stats_t *newdelta, uint_t statslen)
{
	hrtime_t cutoff;
	size_t i,j;

	VERIFY3U(n, >, 1);

	cutoff = newdelta->sts_maxtime - (hrtime_t)statslen * NANOSEC;

	for (i = 0; i < n; i++) {
		if (i + 1 < n) {
			VERIFY3S(deltas[i]->sts_mintime, >=,
			    deltas[i + 1]->sts_mintime);
		}

		if (deltas[i]->sts_mintime >= cutoff)
			continue;

		for (j = i; i < n; i++) {
			stats_free(deltas[j]);
			deltas[j] = NULL;
		}
		break;
	}

	if (i == n) {
		i = n - 1;
		stats_free(deltas[i]);
	}

	(void) memmove(deltas + 1, deltas, i * sizeof (stats_t *));
	deltas[0] = delta;
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

	if (p == NULL)
		err(EXIT_FAILURE, "calloc failed");
	return (p);
}

void *
xreallocarray(void *p, size_t n, size_t elsize)
{
	void *newp = reallocarray(p, n, elsize);

	if (newp == NULL)
		err(EXIT_FAILURE, "reallocarray failed");
	return (newp);
}

ivec_t *
ivec_dup(const ivec_t *iv)
{
	ivec_t *newiv = ivec_new();
	custr_t *newcu = newiv->ivec_name;

	bcopy(iv, newiv, sizeof (*iv));
	newiv->ivec_buspath = xstrdup(iv->ivec_buspath);
	newiv->ivec_name = newcu;
	custr_append(newcu, custr_cstr(iv->ivec_name));

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

	bzero(iv, sizeof (*iv));
	iv->ivec_num_ino = 1;
	iv->ivec_nshared = 1;
	iv->ivec_name = cu;
	custr_reset(cu);
}

static int
ivec_ctor(void *buf, void *dummy __unused, int flags __unused)
{
	ivec_t *iv = buf;

	bzero(iv, sizeof (*iv));
	VERIFY0(custr_alloc(&iv->ivec_name));
	iv->iv_num_ino = 1;
	iv->iv_nshared = 1;

	return (0);
}

static void
ivec_dtor(void *buf, void *dummy __unused)
{
	ivec_t *iv = buf;
	custr_free(iv->iv_name);
}
