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
	uint64_t		ea_ext_cnt;
	dfl_iter_fn_t		ea_fn;
	void			*ea_arg;
	dkioc_free_list_ext_t	*ea_exts;
	size_t			ea_nreq;
	dkioc_iter_flags_t	ea_flags;
};

typedef int (*ext_iter_fn_t)(const dkioc_free_list_ext_t *,
    boolean_t, void *);

static int ext_iter(const dkioc_free_list_t *, const dkioc_free_align_t *,
    uint_t, ext_iter_fn_t, void *);
static int ext_xlate(dkioc_free_list_ext_t *, uint64_t, uint64_t, uint64_t,
    uint_t);
static int count_exts(const dkioc_free_list_ext_t *, boolean_t, void *);
static int process_exts(const dkioc_free_list_ext_t *, boolean_t, void *);

#if __GNUC__ > 4 || __GNU_C_MINOR__ >= 8
#define	uadd64_overflow(a, b, c) __builtin_uaddl_overflow(a, b, c)
#else
static bool
uadd64_overflow(uint64_t a, uint64_t b, uint64_t *res)
{
	*res = a + b;
	return ((*res < a || *res < b) ? true : false);
}
#endif
	
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
 * Convenience function to resize and segment the array of extents in
 * a DKIOCFREE request as required by a driver.
 *
 * Some devices that implement DKIOCFREE (e.g. vioblk) have limits
 * on either the number of extents that can be submitted in a single request,
 * or the total number of blocks that can be submitted in a single request.
 * In addition, devices may have alignment requirements on the starting
 * address stricter than the device block size.
 *
 * Since there is currently no mechanism for callers of DKIOCFREE to discover
 * any alignment, segmentation, or size requirements for DKIOCFREE requests
 * for a particular driver (or instance of a particular driver), dfl_iter()
 * allows drivers to tranform the dkioc_free_list_t from a DKIOCFREE request
 * into groups of dkioc_free_ext_ts that conform to the driver's alignment,
 * segmentation, or size requirements. The transformation done by dfl_iter()
 * may involve modifications such as splitting a list of extents into smaller
 * groups, splitting extents into multiple smaller extents, increasing the
 * start address of an extent to conform to alignments, or reducing the size
 * of an extent so that the resulting size is a multiple of the device block
 * size. In all instances, the resultant set is either identical to the
 * original set of extents, or a subset -- that is we _never_ transform a
 * a range into a range that exceeds the original boundaries of the original
 * extents.
 *
 * The transformed extents are grouped per the driver's requirements described
 * by the constraints contained in the 'dfa' parameter, and the 'func'
 * callback is invoked for each group of transformed extents. An optional
 * opaque (to dfl_iter()) 'arg' parameter is passed through to 'func' as well.
 * In addition, on the final group, the 'last' argument of 'func' is set
 * to B_TRUE (for all other groups of extents passed to 'func', 'func' is
 * called with 'last' set to B_FALSE). Indicating the final group of extents
 * allows a driver to mark a request as complete or implement synchronous
 * semantics as required.
 *
 * Unfortunately, the DKIOCFREE ioctl provides no method for communicating
 * any sort of partial completion -- either it returns success (0) or
 * an error. As such, there's little benefit to providing more detailed
 * error semantics beyond what DKIOCFREE can handle (if that ever changes, it
 * would be worth revisiting this). As a result, we take a somewhat simplistic
 * approach -- we stop processing the request on the first error encountered
 * and return the error.  Otherwise dfl_iter() returns 0.
 *
 * Note that transformed extents that result in a range too small to be
 * processed by the driver (e.g. a 4k block size with a request to free
 * starting at offset 512 and a length of 1024) aren't considered an error and
 * are silently ignored. This means it is possible (though hopefully unlikely)
 * a request to a driver may result in no freed extents. When this happens,
 * 'func' is still called, but with a NULL list of extents, an extent count
 * of 0, and with last set to B_TRUE to allow for cleanup (calling done
 * routines, etc.).
 *
 * Currently no flags are defined, and should always be zero.
 */
int
dfl_iter(const dkioc_free_list_t *dfl, const dkioc_free_align_t *dfa,
    dfl_iter_fn_t func, void *arg, int kmflag, dkioc_iter_flags_t flags)
{
	dkioc_free_list_ext_t *exts;
	uint64_t n_exts = 0;
	struct ext_arg earg = { 0 };
	uint_t bshift;
	int r = 0;

	if ((flags & ~(DIF_NONE|DIF_NOSPLIT)) != 0)
		return (SET_ERROR(EINVAL));

	/* Block size must be at least 1 and a power of two */
	if (dfa->dfa_bsize == 0 || !ISP2(dfa->dfa_bsize))
		return (SET_ERROR(EINVAL));

	/* Offset alignment must also be at least 1 and a power of two */
	if (dfa->dfa_align == 0 || !ISP2(dfa->dfa_align))
		return (SET_ERROR(EINVAL));

	/* Length granularity must be at least 1 and a power of two */
	if (dfa->dfa_gran == 0 || !ISP2(dfa->dfa_gran))
		return (SET_ERROR(EINVAL));

	/*
	 * Since dfa_bsize != 0 (see above), ddi_ffsll() _must_ return a
	 * value > 1
	 */
	bshift = ddi_ffsll((long long)dfa->dfa_bsize) - 1;

	/*
	 * If a limit on the total number of blocks is given, it must be
	 * greater than the offset alignment. E.g. if the block size is 512
	 * bytes and the offset alignment is 4096 (8 blocks), the device must
	 * allow extent sizes at least 8 blocks long (otherwise there will be
	 * device addresses that cannot be contained within an extent).
	 */
	if (dfa->dfa_max_blocks > 0 && dfa->dfa_max_blocks < dfa->dfa_align)
		return (SET_ERROR(EINVAL));

	/*
	 * The general approach is that we walk the array of extents twice
	 * using ext_iter(). For each extent, ext_iter() will invoke the
	 * given callback function 0 or more times (based on the requirements
	 * in dfa), and then invoke the callback function with a NULL extent.
	 *
	 * This first walk is used to count the total number of extents
	 * after applying the driver requirements in 'dfa'. This may be
	 * different from the initial number of extents due to splitting
	 * extents or discarding extents that do not conform to alignment
	 * requirements (and may even be 0).
	 */
	r = ext_iter(dfl, dfa, bshift, count_exts, &n_exts);
	if (r != 0)
		return (r);

	/*
	 * It's possible that some extents do not conform to the alignment
	 * requirements, nor do they have a conforming subset. For example,
	 * a device with a block size of 512 bytes, and a starting alignment
	 * of 4096 bytes would not be able to free extent with a starting
	 * offset of 512 and a length of 1024. Such extents are ignored
	 * (we have no good way to report back partial results). While unlikely,
	 * it is possible a request consists of nothing but non-conforming
	 * extents. In this case, we invoke the callback with a NULL list
	 * of extents and with last set so it can perform any necessary
	 * cleanup, completion tasks.
	 */
	if (n_exts == 0)
		return (func(NULL, 0, B_TRUE, arg));

	exts = kmem_zalloc(n_exts * sizeof (*exts), kmflag);
	if (exts == NULL)	
		return (SET_ERROR(ENOMEM));

	earg.ea_ext_cnt = 0;
	earg.ea_fn = func;
	earg.ea_arg = arg;
	earg.ea_exts = exts;
	earg.ea_nreq = 0;
	earg.ea_flags = flags;

	/*
	 * We've allocated enough space to hold all the transformed extents
	 * in 'exts'. Now walk the original list of extents a second time
	 * and do the work.  process_exts() will accumulate the transformed
	 * extents and invoke 'func' (the callback passed into dfl_iter()) to
	 * perform the free request with the accumulated extents, repeating
	 * as necessary.
	 */
	r = ext_iter(dfl, dfa, bshift, process_exts, &earg);
	kmem_free(exts, n_exts * sizeof (*exts));
	return (r);
}

static int
count_exts(const dkioc_free_list_ext_t *ext, boolean_t newreq __unused,
    void *arg)
{
	size_t *np = arg;

	if (ext != NULL && ext->dfle_length > 0)
		(*np)++;

	return (0);
}

static int
process_exts(const dkioc_free_list_ext_t *ext, boolean_t newreq, void *arg)
{
	struct ext_arg *args = arg;
	dkioc_free_list_ext_t *ext_list = args->ea_exts;

	if (ext == NULL) {
		/*
		 * The very last call should be with ext set to NULL to
		 * flush any accumulated extents since the last start of
		 * a new group.
		 */
		VERIFY(newreq);

		/*
		 * A corner case -- we never had any extents that could
		 * be passed to the callback. Do a final call with the
		 * extent list as NULL (and a count of 0).
		 */
		if (args->ea_ext_cnt == 0)
			ext_list = NULL;

		args->ea_nreq++;

		return (args->ea_fn(ext_list, args->ea_ext_cnt, B_TRUE,
		    args->ea_arg));
	}

	/*
	 * Starting a new request, and we have accumulated extents to
	 * flush.
	 */
	if (newreq && args->ea_ext_cnt > 0) {
		int r;

		args->ea_nreq++;

		r = args->ea_fn(ext_list, args->ea_ext_cnt, B_FALSE,
		    args->ea_arg);
		if (r != 0)
			return (r);

		/*
		 * A bit simplistic, but we just keep appending to the
		 * original array allocated by dfl_iter(), but just update
		 * our starting position (args->ex_exts) for the next group.
		 */
		args->ea_exts += args->ea_ext_cnt;
		args->ea_ext_cnt = 0;
	}

	/* Skip any extents that end up with zero length after aligning. */
	if (ext->dfle_length > 0)
		args->ea_exts[args->ea_ext_cnt++] = *ext;

	return (0);
}

/*
 * Translate the ext from byte-based units to units of
 * (1 << bshift) sized blocks, with the start and length values adjusted to
 * the align and gran values (align and gran are in units of bytes).
 *
 * Returns 0 on success, or an error value.
 */
static int
ext_xlate(dkioc_free_list_ext_t *ext, uint64_t offset, uint64_t align,
    uint64_t gran, uint_t bshift)
{
	uint64_t start, end;

	if (uadd64_overflow(offset, ext->dfle_start, &start))
		return (SET_ERROR(EOVERFLOW));

	if (uadd64_overflow(start, ext->dfle_length, &end))
		return (SET_ERROR(EOVERFLOW));
	
	start = P2ROUNDUP(start, align);
	end = P2ALIGN(end, gran);

	ext->dfle_start = start >> bshift;
	ext->dfle_length = (end > start) ? (end - start) >> bshift : 0;
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
	const dkioc_free_list_ext_t *src = dfl->dfl_exts;
	uint64_t n_exts = 0;
	uint64_t n_blks = 0;
	uint64_t align = dfa->dfa_align << bshift;
	uint64_t gran = dfa->dfa_gran << bshift;
	size_t i;
	boolean_t newreq = B_TRUE;

	for (i = 0; i < dfl->dfl_num_exts; i++, src++) {
		dkioc_free_list_ext_t ext = *src;
		int r;

		r = ext_xlate(&ext, dfl->dfl_offset, align, gran, bshift);
		if (r != 0)
			return (r);

		while (ext.dfle_length > 0) {
			dkioc_free_list_ext_t seg = ext;

			if (dfa->dfa_max_ext > 0 &&
			    n_exts + 1 > dfa->dfa_max_ext) {
				/*
				 * Reached the max # of extents, start a new
				 * request, and retry.
				 */
				newreq = B_TRUE;
				n_exts = 0;
				n_blks = 0;
				continue;
			}

			if (dfa->dfa_max_blocks > 0 &&
			    n_blks + seg.dfle_length > dfa->dfa_max_blocks) {
				/*
				 * This extent puts us over the max # of
				 * blocks in a request.
				 */
				if (!newreq) {
					/*
					 * If we haven't started a new request,
					 * start one, and retry as a new
					 * request in case it can fit on
					 * its own. If not, we'll skip
					 * this block and split it in the
					 * code below.
					 */
					newreq = B_TRUE;
					n_exts = 0;
					n_blks = 0;
					continue;
				}

				/*
				 * A new request, and the extent length is
				 * larger than our max. Reduce the length to
				 * the largest multiple of dfa_align
				 * equal to or less than dfa_max_blocks
				 * so the next starting address has the
				 * correct alignment, splitting the request.
				 */
				seg.dfle_length = P2ALIGN(dfa->dfa_max_blocks,
				    align);

				/*
				 * Our sanity checks on the alignment
				 * requirements mean we should be able to
				 * free at least part of the extent.
				 */
				ASSERT3U(seg.dfle_length, >, 0);
			}

			r = fn(&seg, newreq, arg);
			if (r != 0)
				return (r);

			n_exts++;
			n_blks += seg.dfle_length;

			ASSERT3U(ext.dfle_length, >=, seg.dfle_length);

			ext.dfle_length -= seg.dfle_length;
			ext.dfle_start += seg.dfle_length;
			newreq = B_FALSE;
		}
	}

	/*
	 * Invoke the callback one last time w/ a NULL array of extents and
	 * newreq == B_TRUE to signal completion (and flush any accumulated
	 * extents).
	 */
	return (fn(NULL, B_TRUE, arg));
}
