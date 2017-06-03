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
 * Copyright 2014 Jason King.
 */
#include <sys/debug.h>
#include <string.h>
#include <umem.h>
#include "buf.h"

size_t
buf_copy(buf_t * restrict dest, const buf_t * restrict src, size_t n)
{
	uchar_t *p = dest->ptr;
	size_t total = 0;

	for (size_t i = 0; i < n; i++) {
		size_t amt = src[i].len;

		if (total + amt > dest->len)
			amt = dest->len - total;
		if (amt == 0)
			break;

		(void) memcpy(p, src[i].ptr, amt);
		total += amt;
		p += amt;
	}

	return (total);
}

void
buf_clear(buf_t *buf)
{
	if (buf == NULL || buf->ptr == NULL || buf->len == 0)
		return;
	(void) memset(buf->ptr, 0, buf->len);
}

void
buf_range(buf_t * restrict dest, buf_t * restrict src, size_t off, size_t len)
{
	ASSERT(off + len <= src->len);
	dest->ptr = src->ptr + off;
	dest->len = src->len - off;
}

boolean_t
buf_alloc(buf_t *buf, size_t len)
{
	if ((buf->ptr = umem_zalloc(len, UMEM_DEFAULT)) == NULL)
		return (B_FALSE);
	buf->len = len;
	return (B_TRUE);
}

void
buf_free(buf_t *buf)
{
	if (buf == NULL)
		return;
	buf_clear(buf);
	umem_free(buf->ptr, buf->len);
}

