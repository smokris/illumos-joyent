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
 * Copyright 2017 Nexenta Inc.  All rights reserved.
 * Copyright 2020 Joyent, Inc.
 */

#ifndef _SYS_DKIOC_FREE_UTIL_H
#define	_SYS_DKIOC_FREE_UTIL_H

#include <sys/dkio.h>

#ifdef	__cplusplus
extern "C" {
#endif

#define	DFL_COPYIN_MAX_EXTS	(1024 * 1024)

typedef struct dkioc_free_align {
	/* Device block size in bytes. Must be > 0, and must be a power of 2 */
	size_t	dfa_bsize;

	/* Maximum number of extents in a single request. 0 == no limit */
	size_t	dfa_max_ext;

	/*
	 * Maximum number of blocks (in units of dfa_bsize) in a single request.
	 * 0 == no limit.
	 */
	size_t	dfa_max_blocks;

	/*
	 * Minimum alignment for extent offsets in units of blocks (dfa_bsize).
	 * etc). Must be > 0, and a power of two.
	 */
	size_t	dfa_align;

	/*
	 * Minimum granularity for length in units of blocks (dfa_bsize).
	 * Must be > 0, and a power of two.
	 */
	size_t dfa_gran;
} dkioc_free_align_t;

typedef enum dkioc_iter_flags {
	DIF_NONE	= 0,
	DIF_NOSPLIT	= (1 << 1)
} dkioc_iter_flags_t;

typedef int (*dfl_iter_fn_t)(const dkioc_free_list_ext_t *exts, size_t n_ext,
    boolean_t last, void *arg);

int dfl_copyin(void *arg, dkioc_free_list_t **out, int ddi_flags, int kmflags);
void dfl_free(dkioc_free_list_t *dfl);
int dfl_iter(const dkioc_free_list_t *dfl, const dkioc_free_align_t *align,
    dfl_iter_fn_t fn, void *arg, int kmflag, dkioc_iter_flags_t);

#ifdef	__cplusplus
}
#endif

#endif /* _SYS_DKIOC_FREE_UTIL_H */
