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

#ifndef _IKEV2_BUF_H
#define	_IKEV2_BUF_H

#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifndef _BUF_T
#define	_BUF_T
struct buf_s;
typedef struct buf_s buf_t;

#if 0
struct buf_s {
	buf_t		*parent;
	char		*ptr;
	size_t		len;
	size_t		alloc;
	boolean_t	grow;
	boolean_t	eof;
};
#endif

struct buf_s {
	uchar_t	*ptr;
	ulong_t	len;	/* equiv. to size_t, but this makes pkcs11 happy */
};
#define	BUF_DUP(_dest, _src)			\
	do {					\
		(_dest)->ptr = (_src)->ptr;	\
		(_dest)->len = (_src)->len;	\
	} while (0)

#define	BUF_ADVANCE(_buf, _n)			\
	do {					\
		VERIFY((_buf)->len >= (_n));	\
		(_buf)->ptr += (_n);		\
		(_buf)->len -= (_n);		\
	} while (0)

#endif /* _BUF_T */

size_t		buf_copy(buf_t * restrict, const buf_t * restrict, size_t);
void		buf_clear(buf_t *);
void		buf_range(buf_t * restrict, buf_t * restrict, size_t, size_t);

boolean_t	buf_alloc(buf_t *, size_t);
void		buf_free(buf_t *);

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

#endif /* _IKEV2_BUF_H */
