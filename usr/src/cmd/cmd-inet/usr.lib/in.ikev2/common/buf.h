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

#ifndef _BUF_H
#define	_BUF_H

#include <sys/types.h>
#include <sys/debug.h>

#ifdef __cplusplus
extern "C" {
#endif

struct buf;

#ifndef _BUF_T
#define	_BUF_T
typedef struct buf buf_t;
#endif

struct buf {
	uchar_t	*ptr;
	ulong_t	len;	/* equiv. to size_t, but this makes pkcs11 happy */
};

inline void
buf_dup(buf_t * restrict dest, buf_t * restrict src)
{
	dest->ptr = src->ptr;
	dest->len = src->len;
}

inline void
buf_advance(buf_t *buf, size_t amt)
{
	VERIFY(buf->len >= amt);
	buf->ptr += amt;
	buf->len -= amt;
}

#define	STRUCT_TO_BUF(st) \
	{ .ptr = (uchar_t *)&(st), .len = sizeof ((st)) }

#define	BUF_INIT_BUF(b) \
	{ .ptr = (b)->ptr, .len = (b)->len }

size_t		buf_copy(buf_t * restrict, const buf_t * restrict, size_t);
void		buf_clear(buf_t *);
void		buf_range(buf_t * restrict, buf_t * restrict, size_t, size_t);

boolean_t	buf_alloc(buf_t *, size_t);
void		buf_free(buf_t *);

int		buf_cmp(const buf_t *restrict, const buf_t *restrict);

boolean_t	buf_put8(buf_t *, uint8_t);
boolean_t	buf_put32(buf_t *, uint32_t);
boolean_t	buf_put64(buf_t *, uint64_t);

#if 0
void		buf_init(buf_t *, char *, size_t, size_t, boolean_t);
void		buf_range(buf_t *, size_t, buf_t *);
boolean_t	buf_eof(buf_t *);

uint8_t		buf_get8(buf_t *);
uint16_t	buf_get16(buf_t *);
uint32_t	buf_get32(buf_t *);
uint64_t	buf_get64(buf_t *);
size_t		buf_copyfrom(buf_t *, char *, size_t);

void		buf_put8(buf_t *, uint8_t);
void		buf_put16(buf_t *, uint16_t);
void		buf_put32(buf_t *, uint32_t);
void		buf_put64(buf_t *, uint64_t);
size_t		buf_append(char *, size_t, buf_t *);
#endif

#ifdef __cplusplus
}
#endif

#endif /* _BUF_H */
