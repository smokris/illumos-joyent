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

struct buf_s {
	buf_t		*parent;
	char		*ptr;
	size_t		len;
	size_t		alloc;
	boolean_t	grow;
	boolean_t	eof;
};
#endif /* _BUF_T */

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

#ifdef __cplusplus
}
#endif

#endif /* _IKEV2_BUF_H */
