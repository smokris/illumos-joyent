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
 * Copyright 2017 Jason King.
 * Copyright 2017 Joyent, Inc.
 */
#include <sys/debug.h>
#include <string.h>
#include <umem.h>
#include "buf.h"

static inline boolean_t
eof_check(buf_t *buf, size_t len)
{
	if (buf_eof(buf))
		return (B_TRUE);
	if (buf->b_ptr + len > buf->b_buf + buf->b_len) {
		buf->b_flags |= BUF_EOF;
		return (B_TRUE);
	}
	return (B_FALSE);
}

size_t
buf_cat(buf_t *restrict dest, const buf_t *restrict src, size_t n)
{
	size_t total = 0;

	BUF_IS_WRITE(dest);

	for (size_t i = 0; i < n; i++, src++) {
		size_t amt = buf_left(src);

		BUF_IS_READ(src);
		if (eof_check(dest, amt))
			return (total);

		(void) memcpy(dest->b_ptr, src->b_ptr, amt);
		dest->b_ptr += amt;
		total += amt;
	}

	return (total);
}

size_t
buf_copy(buf_t *restrict dest, const buf_t *restrict src, size_t n)
{
	uchar_t *p = dest->b_buf;
	size_t total = 0;

	BUF_IS_WRITE(dest);

	dest->b_ptr = dest->b_buf;
	return (buf_cat(dest, src, n));
	for (size_t i = 0; i < n; i++) {
		size_t amt = src[i].b_len;

		if (total + amt > dest->b_len)
			amt = dest->b_len - total;
		if (amt == 0)
			break;

		(void) memcpy(p, src[i].b_buf, amt);
		total += amt;
		p += amt;
	}

	
	/* XXX: what to do about b_ptr? */
	return (total);
}

void
buf_clear(buf_t *buf)
{
	if (buf == NULL || buf->b_buf == NULL || buf->b_len == 0)
		return;

	(void) memset(buf->b_buf, 0, buf->b_len);
	buf->b_ptr = NULL;
	buf->b_flags &= ~(BUF_EOF);
}

void
buf_range(buf_t * restrict dest, buf_t * restrict src, size_t off, size_t len)
{
	ASSERT(off + len <= src->len);
	dest->b_ptr = dest->b_buf = src->b_ptr + off;
	dest->b_len = src->b_len - off;
	dest->b_flags = src->b_flags & ~(BUF_ALLOCED);
}

boolean_t
buf_alloc(buf_t *buf, size_t len)
{
	if ((buf->b_buf = umem_zalloc(len, UMEM_DEFAULT)) == NULL)
		return (B_FALSE);
	buf->b_ptr = buf->b_buf;
	buf->b_len = len;
	buf->b_flags = BUF_ALLOCED;
	return (B_TRUE);
}

void
buf_free(buf_t *buf)
{
	if (buf == NULL)
		return;

	VERIFY(buf->b_flags & BUF_ALLOCED);
	buf_clear(buf);
	umem_free(buf->b_buf, buf->b_len);
}

int
buf_cmp(const buf_t *restrict l, const buf_t *restrict r)
{
	size_t minlen;
	int cmp;

	/* !NULL > NULL, NULL == NULL */
	if (r == NULL || r->b_len == 0 || r->b_ptr == NULL) {
		if (l != NULL && l->b_len > 0 && l->b_ptr != NULL)
			return (1);
		else
			return (0);
	}

	/* NULL < !NULL */
	if (l == NULL || l->b_len == 0 || l->b_ptr == NULL)
		return (1);

	minlen = l->b_len;
	if (r->b_len < minlen)
		minlen = r->b_len;

	cmp = memcmp(l->b_buf, r->b_buf, minlen);
	if (cmp != 0)
		return ((cmp > 0) ? 1 : - 1);

	if (l->b_len > r->b_len)
		return (1);
	if (l->b_len < r->b_len)
		return (-1);
	return (0);
}

void
buf_put8(buf_t *buf, uint8_t val)
{
	BUF_IS_WRITE(buf);
	if (eof_check(buf, sizeof (uint8_t)))
		return;

	*(buf->b_ptr++) = val;
}

void
buf_put64(buf_t *buf, uint64_t val)
{
	BUF_IS_WRITE(buf);
	if (eof_check(buf, sizeof (uint64_t)))
		return;

	*(buf->b_ptr++) = (uchar_t)((val >> 56) & 0xffLL);
	*(buf->b_ptr++) = (uchar_t)((val >> 48) & 0xffLL);
	*(buf->b_ptr++) = (uchar_t)((val >> 40) & 0xffLL);
	*(buf->b_ptr++) = (uchar_t)((val >> 32) & 0xffLL);
	*(buf->b_ptr++) = (uchar_t)((val >> 24) & 0xffLL);
	*(buf->b_ptr++) = (uchar_t)((val >> 16) & 0xffLL);
	*(buf->b_ptr++) = (uchar_t)((val >> 8) & 0xffLL);
	*(buf->b_ptr++) = (uchar_t)(val & 0xffLL);
}

void
buf_put32(buf_t *buf, uint32_t val)
{
	BUF_IS_WRITE(buf);
	if (eof_check(buf, sizeof (uint32_t)))
		return;

	*(buf->b_ptr++) = (uchar_t)((val >> 24) & (uint32_t)0xff);
	*(buf->b_ptr++) = (uchar_t)((val >> 16) & (uint32_t)0xff);
	*(buf->b_ptr++) = (uchar_t)((val >> 8) & (uint32_t)0xff);
	*(buf->b_ptr++) = (uchar_t)(val & (uint32_t)0xffLL);
}

extern boolean_t buf_eof(const buf_t *);
extern size_t buf_left(const buf_t *);
extern void buf_reset(buf_t *);
extern void buf_skip(buf_t *, size_t);
extern void buf_set_read(buf_t *);
extern void buf_set_write(buf_t *);
