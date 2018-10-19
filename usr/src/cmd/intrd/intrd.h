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
#include <sys/lgrp_user.h>
#include <sys/list.h>
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
	uint_t	cfg_statslen;
	double	cfg_tooslow;
	double	cfg_unsafe_load;
	double	cfg_mindelta;
} config_t;

typedef struct ivec {
	list_node_t	ivec_node;
	hrtime_t	ivec_snaptime;
	int		ivec_instance;
	int		ivec_cpuid;
	int		ivec_oldcpuid;
	uint64_t	ivec_cookie;
	uint64_t	ivec_pil;
	uint64_t	ivec_ino;
	uint64_t	ivec_time;
	size_t		ivec_num_ino;
	size_t		ivec_nshared;
	char		*ivec_buspath;
	struct custr	*ivec_name;
	char		ivec_type[16];	/* sizeof kstat_named_t.value.c */
} ivec_t;

typedef struct cpustat {
	hrtime_t	cs_snaptime;
	int		cs_cpuid;
	lgrp_id_t	cs_lgrp;
	uint64_t	cs_cpu_nsec_idle;
	uint64_t	cs_cpu_nsec_user;
	uint64_t	cs_cpu_nsec_kernel;
	uint64_t	cs_cpu_nsec_dtrace;
	uint64_t	cs_cpu_nsec_intr;
	list_t		cs_ivecs;
	size_t		cs_nivecs;
} cpustat_t;

typedef struct cpugrp {
	lgrp_id_t	cg_id;
	lgrp_id_t	cg_parent;
	lgrp_id_t	*cg_children;
	size_t		cg_nchildren;
} cpugrp_t;

/*
 * A snapshot of the interrupt statistics on the system.  This is assembled
 * from multiple individual kstats, so the kstat times will not be identical.
 * sts_{min,max}time represent the smallest and largest values of
 * kstat_t.ks_crtime of all the individual kstats used to create this snapshot.
 *
 * cpustat_t's are indexed by CPU id.  That is, the cpustat_t for CPU 5 is
 * sts_cpu[5] -- i.e. there may be gaps in this.  It is sized to hold
 * max_cpu (i.e. _SC_N_PROCESSORS_MAX) cpustat_t *'s.
 */
typedef struct stats {
	kid_t		sts_kid;

	hrtime_t	sts_mintime;
	hrtime_t	sts_maxtime;

	cpustat_t	**sts_cpu;
	size_t		sts_ncpu;

	cpugrp_t	*sts_lgrp;
	size_t		sts_nlgrp;
} stats_t;
#define STATS_CPU(_st, _id) (_st)->sts_cpu[(_id)]

typedef struct load {
	uint64_t	ld_total;
	uint64_t	ld_intrtotal;
	ivec_t		*ld_bigint;
} load_t;
#define LOAD_LGRP(_load, _id) ((_load) + max_cpu + (_id))
#define LOAD_CPU(_load, _id) ((_load) + (_id))
#define LOAD_BIGINT_LOAD(_load) \
    (((_load)->ld_bigint != NULL) ? (_load)->ld_bigint->ivec_time : 0)
#define LOAD_MAXINT(_l1, _l2) \
    ((LOAD_BIGINT_LOAD(_l1) > LOAD_BIGINT_LOAD(_l2)) ? \
     (_l1)->ld_bigint : (_l2)->ld_bigint)

extern uint_t max_cpu;

typedef enum intrd_walk_ret {
    INTRD_WALK_ERROR = -1,
    INTRD_WALK_NEXT = 0,
    INTRD_WALK_DONE = 1
} intrd_walk_ret_t;

typedef intrd_walk_ret_t (*cpu_itercb_t)(stats_t *, cpustat_t *, void *);
intrd_walk_ret_t cpu_iter(stats_t *, cpu_itercb_t, void *);

stats_t *stats_get(const config_t *restrict, kstat_ctl_t *restrict, uint_t);
stats_t *stats_delta(const stats_t *, const stats_t *);
stats_t *stats_sum(stats_t * const*, size_t, size_t *);
stats_t *stats_dup(const stats_t *);
void stats_free(stats_t *);
void stats_dump(const stats_t *);

cpustat_t *cpustat_new(void);
cpustat_t *cpustat_dup(const cpustat_t *);
void cpustat_free(cpustat_t *);

ivec_t *ivec_new(void);
ivec_t *ivec_dup(const ivec_t *);
void ivec_free(ivec_t *);

char *xstrdup(const char *);
void *xcalloc(size_t, size_t);
void *xreallocarray(void *, size_t, size_t);

void nanonicenum(uint64_t, char *, size_t);

int intrmove(const char *, int, int, int, int);

void intrd_kstat_init(void);

#ifdef __cplusplus
}
#endif

#endif /* _INTRD_H */
