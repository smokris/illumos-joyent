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

#ifndef _INTRD_H
#define	_INTRD_H

#include <kstat.h>
#include <sys/kstat.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

struct custr;

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
	size_t		ivec_num_ino;
	size_t		ivec_nshared;
	char		*ivec_buspath;
	struct custr *ivec_name;
	char		ivec_type[16];	/* sizeof kstat_named_t.value.c */
} ivec_t;

typedef struct cpustat {
	hrtime_t	cs_crtime;
	int	        cs_cpuid;
	uint64_t	cs_cpu_nsec_idle;
	uint64_t	cs_cpu_nsec_user;
	uint64_t	cs_cpu_nsec_kernel;
	uint64_t	cs_cpu_nsec_dtrace;
	uint64_t	cs_cpu_nsec_intr;
	ivec_t		**cs_ivecs;
	size_t		cs_nivecs;
} cpustat_t;

typedef struct stats {
	hrtime_t	sts_mintime;
	hrtime_t	sts_maxtime;
	cpustat_t	**sts_cpu;
	size_t		sts_ncpu;
} stats_t;

stats_t *stats_get(const config_t *restrict, kstat_ctl_t *restrict, uint_t);
stats_t *stats_delta(const stats_t *, const stats_t *);
stats_t *stats_sum(const stats_t **, size_t, size_t *);
stats_t *stats_dup(const stats_t *);
void stats_free(stats_t *);

int cpustat_cmp_id(const void *, const void *);
int ivec_cmp_id(const void *, const void *);
int ivec_cmp_cpu(const void *, const void *);
int ivec_cmp_time(const void *, const void *);

ivec_t *ivec_new(void);
ivec_t *ivec_dup(const ivec_t *);
void ivec_free(ivec_t *);
int ivec_cmp_id(const void *, const void *);

char *xstrdup(const char *);
void *xcalloc(size_t, size_t);
void *xreallocarray(void *, size_t, size_t);

int intrmove(const char *, int, int, int, int);

#ifdef __cplusplus
}
#endif

#endif /* _INTRD_H */
