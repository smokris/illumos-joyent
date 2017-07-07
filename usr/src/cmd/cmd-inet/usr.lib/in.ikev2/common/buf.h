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
 * Copyright 2017 Joyent, Inc.
 */

#ifndef _BUF_H
#define	_BUF_H

#include <sys/types.h>
#include <sys/debug.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct buf {
	uchar_t	*b_buf;
	uchar_t *b_ptr;
	size_t	b_len;
	ulong_t	b_flags;
} buf_t;
#define	BUF_READ	(1UL << 0)
#define	BUF_WRITE	(1UL << 1)
#define	BUF_EOF		(1UL << 2)
#define	BUF_ALLOCED	(1UL << 3)

#define	STRUCT_TO_BUF(st) { 		\
	.b_buf = (uchar_t *)&(st),	\
	.b_ptr = (uchar_t *)&(st),	\
	.b_len = sizeof ((st)),		\
	.b_flags = 0			\
}

#define	BUF_IS_WRITE(b) \
	VERIFY(((b)->b_flags & BUF_WRITE) && !((b)->b_flags & BUF_READ))
#define	BUF_IS_READ(b) \
	VERIFY(((b)->b_flags & BUF_READ) && !((b)->b_flags & BUF_WRITE))

inline boolean_t
buf_eof(const buf_t *b)
{
	return (!!(b->b_flags & BUF_EOF));
}

inline void
buf_skip(buf_t *buf, size_t amt)
{
	if (buf_eof(buf))
		return;

	uchar_t *end = buf->b_buf + buf->b_len;
	buf->b_ptr += amt;

	if (buf->b_ptr > end) {
		buf->b_ptr = end;
		buf->b_flags |= BUF_EOF;
	}
}

inline void
buf_reset(buf_t *buf)
{
	buf->b_ptr = buf->b_buf;
	buf->b_flags &= ~(BUF_EOF);
}

inline size_t
buf_left(const buf_t *buf)
{
	if (buf->b_flags & BUF_EOF)
		return (0);
	return (buf->b_len - (size_t)(buf->b_ptr - buf->b_buf));
}

inline void
buf_set_read(buf_t *buf)
{
	buf->b_flags &= ~(BUF_READ|BUF_WRITE);
	buf->b_flags |= BUF_READ;
}

inline void
buf_set_write(buf_t *buf)
{
	buf->b_flags &= ~(BUF_READ|BUF_WRITE);
	buf->b_flags |= BUF_WRITE;
}

size_t		buf_cat(buf_t *restrict, const buf_t *restrict, size_t);
size_t		buf_copy(buf_t *restrict, const buf_t *restrict, size_t);
void		buf_clear(buf_t *);
void		buf_range(buf_t *restrict, buf_t *restrict, size_t, size_t);

boolean_t	buf_alloc(buf_t *, size_t);
void		buf_free(buf_t *);

int		buf_cmp(const buf_t *restrict, const buf_t *restrict);

void		buf_put8(buf_t *, uint8_t);
void		buf_put32(buf_t *, uint32_t);
void		buf_put64(buf_t *, uint64_t);

#if 0
void		buf_init(buf_t *, char *, size_t, size_t, boolean_t);
void		buf_range(buf_t *, size_t, buf_t *);

uint8_t		buf_get8(buf_t *);
uint16_t	buf_get16(buf_t *);
uint32_t	buf_get32(buf_t *);
uint64_t	buf_get64(buf_t *);
size_t		buf_copyfrom(buf_t *, char *, size_t);

void		buf_put16(buf_t *, uint16_t);
size_t		buf_append(char *, size_t, buf_t *);
#endif

#ifdef __cplusplus
}
#endif

#endif /* _BUF_H */
