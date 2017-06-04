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

int
buf_cmp(const buf_t *restrict l, const buf_t *restrict r)
{
	size_t minlen;
	int cmp;

	/* !NULL > NULL, NULL == NULL */
	if (r == NULL || r->len == 0 || r->ptr == NULL) {
		if (l != NULL && l->len > 0 && l->ptr != NULL)
			return (1);
		else
			return (0);
	}

	/* NULL < !NULL */
	if (l == NULL || l->len == 0 || l->ptr == NULL)
		return (1);

	minlen = l->len;
	if (r->len < minlen)
		minlen = r->len;

	cmp = memcmp(l->ptr, r->ptr, minlen);
	if (cmp != 0)
		return ((cmp > 0) ? 1 : - 1);

	if (l->len > r->len)
		return (1);
	if (l->len < r->len)
		return (-1);
	return (0);
}

boolean_t
buf_put8(buf_t *buf, uint8_t val)
{
	if (buf->len < sizeof (uint8_t))
		return (B_FALSE);

	*(buf->ptr++) = val;
	buf->len -= sizeof (uint8_t);
	return (B_TRUE);
}

boolean_t
buf_put64(buf_t *buf, uint64_t val)
{
	if (buf->len < sizeof (uint64_t))
		return (B_FALSE);

	ASSERT3U(buf->len, >=, sizeof (uint64_t));
	*(buf->ptr++) = (uchar_t)((val >> 56) & 0xffLL);
	*(buf->ptr++) = (uchar_t)((val >> 48) & 0xffLL);
	*(buf->ptr++) = (uchar_t)((val >> 40) & 0xffLL);
	*(buf->ptr++) = (uchar_t)((val >> 32) & 0xffLL);
	*(buf->ptr++) = (uchar_t)((val >> 24) & 0xffLL);
	*(buf->ptr++) = (uchar_t)((val >> 16) & 0xffLL);
	*(buf->ptr++) = (uchar_t)((val >> 8) & 0xffLL);
	*(buf->ptr++) = (uchar_t)(val & 0xffLL);
	buf->len -= sizeof (uint64_t);
	return (B_TRUE);
}

boolean_t
buf_put32(buf_t *buf, uint32_t val)
{
	if (buf->len < sizeof (uint32_t))
		return (B_FALSE);
	*(buf->ptr++) = (uchar_t)((val >> 24) & (uint32_t)0xff);
	*(buf->ptr++) = (uchar_t)((val >> 16) & (uint32_t)0xff);
	*(buf->ptr++) = (uchar_t)((val >> 8) & (uint32_t)0xff);
	*(buf->ptr++) = (uchar_t)(val & (uint32_t)0xffLL);
	buf->len -= sizeof (uint32_t);
	return (B_TRUE);
}

extern void buf_dup(buf_t * restrict dest, buf_t * restrict src);
extern void buf_advance(buf_t *buf, size_t amt);

