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
 * Copyright 2019 Joyent, Inc.
 */

/* needed when building libzpool */
#ifndef	_KERNEL
#include <sys/zfs_context.h>
#endif

#include <sys/sunddi.h>
#include <sys/dkio.h>
#include <sys/dkioc_free_util.h>
#include <sys/sysmacros.h>
#include <sys/file.h>
#include <sys/sdt.h>

struct ext_arg {
	uint64_t	ea_ext_cnt;
	dfl_iter_fn_t	ea_fn;
	void		*ea_arg;
	dkioc_free_list_ext_t *ea_exts;
};

typedef int (*ext_iter_fn_t)(const dkioc_free_list_ext_t *,
    boolean_t, void *);

static int ext_iter(const dkioc_free_list_t *, const dkioc_free_align_t *,
    uint_t, ext_iter_fn_t, void *);
static int ext_xlate(const dkioc_free_list_t *, const dkioc_free_list_ext_t *,
    const dkioc_free_align_t *, uint_t, uint64_t *, uint64_t *);
static int count_exts(const dkioc_free_list_ext_t *, boolean_t, void *);
static int process_exts(const dkioc_free_list_ext_t *, boolean_t, void *);

/*
 * Copy-in convenience function for variable-length dkioc_free_list_t
 * structures. The pointer to be copied from is in `arg' (may be a pointer
 * to userspace). A new buffer is allocated and a pointer to it is placed
 * in `out'. `ddi_flags' indicates whether the pointer is from user-
 * or kernelspace (FKIOCTL) and `kmflags' are the flags passed to
 * kmem_zalloc when allocating the new structure.
 * Returns 0 on success, or an errno on failure.
 */
int
dfl_copyin(void *arg, dkioc_free_list_t **out, int ddi_flags, int kmflags)
{
	dkioc_free_list_t *dfl;

	if (ddi_flags & FKIOCTL) {
		dkioc_free_list_t *dfl_in = arg;

		if (dfl_in->dfl_num_exts == 0 ||
		    dfl_in->dfl_num_exts > DFL_COPYIN_MAX_EXTS)
			return (SET_ERROR(EINVAL));
		dfl = kmem_alloc(DFL_SZ(dfl_in->dfl_num_exts), kmflags);
		if (dfl == NULL)
			return (SET_ERROR(ENOMEM));
		bcopy(dfl_in, dfl, DFL_SZ(dfl_in->dfl_num_exts));
	} else {
		uint64_t num_exts;

		if (ddi_copyin(((uint8_t *)arg) + offsetof(dkioc_free_list_t,
		    dfl_num_exts), &num_exts, sizeof (num_exts),
		    ddi_flags) != 0)
			return (SET_ERROR(EFAULT));
		if (num_exts == 0 || num_exts > DFL_COPYIN_MAX_EXTS)
			return (SET_ERROR(EINVAL));
		dfl = kmem_alloc(DFL_SZ(num_exts), kmflags);
		if (dfl == NULL)
			return (SET_ERROR(ENOMEM));
		if (ddi_copyin(arg, dfl, DFL_SZ(num_exts), ddi_flags) != 0 ||
		    dfl->dfl_num_exts != num_exts) {
			kmem_free(dfl, DFL_SZ(num_exts));
			return (SET_ERROR(EFAULT));
		}
	}

	*out = dfl;
	return (0);
}

/* Frees a variable-length dkioc_free_list_t structure. */
void
dfl_free(dkioc_free_list_t *dfl)
{
	kmem_free(dfl, DFL_SZ(dfl->dfl_num_exts));
}

/*
 * Convenience function to iterate through the array of extents in dfl while
 * respecting segmentation and alignment of the extents.
 *
 * Some devices that implement DKIOCFREE (e.g. nvme and vioblk) have limits
 * on either the number of extents that can be submitted in a single request,
 * or the total number of blocks that can be submitted in a single request.
 * In addition, devices may have alignment requirements on the starting
 * address stricter than the device block size.
 *
 * Since there is currently no way for callers of DKIOCFREE to discover
 * any alignment or segmentation requirements, the driver itself may choose
 * to adjust the actual extent start and length that is freed (never freeing
 * outside the original unmodified extent boundaries), split extents into
 * multiple smaller extents, or split a single request into multiple requests
 * to the underlying hardware. dfl_iter() frees the driver from having to
 * deal with such complexity/tedium.
 *
 * The original request is passed in dfl and the alignment requirements are
 * given in dkfa. dfl_iter() will do the necessary adjustments and then
 * call func with an array of extents, number of extents, as well as a flag
 * that is set upon the last invocation of func for the original request, as
 * well as the void * arg passed to dfl_iter().
 *
 * func should return 0 on success or an error value. An error may result
 * in partial completion of the request, sorry.
 *
 * Currently no flags are defined, and should always be zero.
 */
int
dfl_iter(const dkioc_free_list_t *dfl, const dkioc_free_align_t *dfa,
    dfl_iter_fn_t func, void *arg, int kmflag, uint32_t dfl_flag)
{
	dkioc_free_list_ext_t *exts;
	uint64_t n_exts = 0;
	struct ext_arg earg = { 0 };
	uint_t bshift;
	int r = 0;

	if (dfl_flag != 0)
		return (SET_ERROR(EINVAL));

	/* Block size must be at least 1 and a power of two */
	if (dfa->dfa_bsize == 0 || !ISP2(dfa->dba_bsize))
		return (SET_ERROR(EINVAL));

	/* Offset alignment must also be at least 1 and a power of two */
	if (dfa->dfa_align == 0 || !ISP2(dfa->dfa_align))
		return (SET_ERROR(EINVAL));

	/* The offset alignment must be at least as large as the block size */	
	if (dfa->dfa_align < dfa->dfa_bsize)
		return (SET_ERROR(EINVAL));

	/* Since dfa_bsize != 0, ddi_ffsll() _must_ return a value > 1 */
	bshift = ddi_ffsll((long long)dfa->dfa_bsize) - 1;

	/*
	 * If a limit on the total number of blocks is given, it must be
	 * greater than the offset alignment. E.g. if the block size is 512
	 * bytes, the offset alignment is 4096 (8 blocks), the device must
	 * allow extent sizes at least 8 blocks long (otherwise it is not
	 * possible to free the entire device).
	 */
	if (dfa->dfa_max_blocks > 0 &&
	    (dfa->dfa_max_blocks >> bshift) < dfa->dfa_align)
		return (SET_ERROR(EINVAL));

	/*
	 * Determine the total number of extents needed. Due to alignment
	 * and segmentation requirements, this may be different than
	 * the initial number of segments.
	 */
	r = ext_iter(dfl, dfa, bshift, count_exts, &n_exts);
	if (r != 0)
		return (r);

	/*
	 * It's possible that some extents do not conform to the alignment
	 * requirements, nor do they have a conforming subset. For example,
	 * with a minimum alignment of 8 blocks, an extent starting at
	 * offset 2 and a length of 5 is such a case. Since there is no way
	 * to report partial results, such extents are silently skipped.
	 * It is then possible that a request could consist of nothing but
	 * ineligible extents, and so such a request is also silently
	 * ignored.
	 */
	if (n_exts == 0)
		return (0);

	n_exts = earg.ea_ext_cnt;
	exts = kmem_zalloc(n_exts * sizeof (*exts), kmflag);
	if (exts == NULL)	
		return (SET_ERROR(EOVERFLOW));

	earg.ea_ext_cnt = n_exts;
	earg.ea_fn = func;
	earg.ea_arg = arg;
	earg.ea_exts = exts;

	/*
	 * Run through all the extents, calling func as the limits for
	 * each request are reached. The final request remains queued
	 * when ext_iter() returns.
	 */
	r = ext_iter(dfl, dfa, bshift, process_exts, &earg);
	if (r != 0)
		goto done;

	/* Process the final request */
	r = process_exts(NULL, B_TRUE, &earg);

done:
	kmem_free(exts, n_exts * sizeof (*exts));
	return (r);
}

static int
count_exts(const dkioc_free_list_ext_t *ext, boolean_t newreq __unused,
    void *arg)
{
	size_t *np = arg;

	(*np)++;
	return (0);
}

static int
process_exts(const dkioc_free_list_ext_t *ext, boolean_t newreq, void *arg)
{
	struct ext_arg *args = arg;

	if (newreq && args->ea_ext_cnt > 0) {
		/*
		 * A new request, and are extents from the previous request
		 * ready to dispatch.
		 */
		int r;
		boolean_t last = (ext == NULL) ? B_TRUE : B_FALSE;

		r = args->ea_fn(args->ea_exts, args->ea_ext_cnt, last,
		    args->ea_arg);

		if (r != 0)
			return (r);

		args->ea_exts += args->ea_ext_cnt;
		args->ea_ext_cnt = 0;

		/*
		 * After the last request, we are called with a NULL ext
		 * and a new request to process the final request.
		 */
		if (ext == NULL)
			return (0);
	}

	args->ea_exts[args->ea_ext_cnt++] = *ext;
	return (0);
}

/*
 * Translate the byte offset and lengths in ext into block offsets and
 * lengths, with the offset aligned per dfla.
 */
static int
ext_xlate(const dkioc_free_list_t *dfl, const dkioc_free_list_ext_t *ext,
    const dkioc_free_align_t *dfa, uint_t bshift, uint64_t *startp,
    uint64_t *lengthp)
{
	uint64_t start = dfl->dfl_offset + ext->dfle_start;
	uint64_t end = start + ext->dfle_length;

	if (start < dfl->dfl_offset || start < ext->dfle_start)
		return (SET_ERROR(EOVERFLOW));
	if (end < start || end < ext->dfle_length)
		return (SET_ERROR(EOVERFLOW));

	start = P2ROUNDUP(start, dfa->dfa_align) >> bshift;
	end = P2ALIGN(end, dfa->dfa_bsize) >> bshift;

	*startp = start;
	*lengthp = (end > start) ? end - start : 0;
	return (0);
}

/*
 * Iterate through the extents in dfl. fn is called for each adjusted extent
 * (adjusting offsets and lengths to conform to the alignment requirements)
 * and one input extent may result in 0, 1, or multiple calls to fn as a 
 * result.
 */
static int
ext_iter(const dkioc_free_list_t *dfl, const dkioc_free_align_t *dfa,
    uint_t bshift, ext_iter_fn_t fn, void *arg)
{
	const dkioc_free_list_ext_t *ext;
	uint64_t n_exts = 0;
	uint64_t n_blk = 0;
	size_t i;
	boolean_t newreq = B_TRUE;

	for (i = 0, ext = dfl->dfl_exts; i < dfl->dfl_num_exts; i++, ext++) {
		uint64_t start, length;
		int r;

		r = ext_xlate(dfl, ext, dfa, bshift, &start, &length);
		if (r != 0)
			return (r);

		while (length > 0) {
			dkioc_free_list_ext_t blk_ext = {
				.dfle_start = start,
				.dfle_length = length
			};

			if (dfa->dfa_max_ext > 0 &&
			    n_exts + 1 > dfa->dfa_max_ext) {
				/*
				 * Reached the max # of extents, start a new
				 * request.
				 */
				newreq = B_TRUE;
				n_exts = 0;
				n_blk = 0;
				continue;
			}

			if (dfa->dfa_max_blocks > 0 &&
			    n_blk + length > dfa->dfa_max_blocks) {
				/*
				 * This extent puts us over the max # of
				 * blocks in a request. If this isn't a
				 * new request, start a new request,
				 */
				if (!newreq) {
					newreq = B_TRUE;
					n_exts = 0;
					n_blk = 0;
					continue;
				}

				/*
				 * A new request, and the extent length is
				 * larger than our max. Reduce the length to
				 * the largest multiple of dfa_align
				 * equal to or less than dfa_max_blocks
				 * so the next starting address has the
				 * correct alignment.
				 */
				blk_ext.dfle_length =
				    P2ALIGN(dfa->dfa_max_blocks,
				    dfa->dfa_align >> bshift);
			}

			r = fn(&blk_ext, newreq, arg);
			if (r != 0)
				return (r);

			newreq = B_FALSE;

			n_exts++;
			n_blk += blk_ext.dfle_length;

			length -= blk_ext.dfle_length;
			start += blk_ext.dfle_length;
		}
	}

	return (0);
}
