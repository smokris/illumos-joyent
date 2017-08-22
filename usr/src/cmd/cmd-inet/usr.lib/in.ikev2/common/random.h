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
 * Copyright 2014 Jason King.  All rights reserved.
 */

#ifndef _RANDOM_H
#define	_RANDOM_H

#ifdef __cplusplus
extern "C" {
#endif

#include <inttypes.h>

extern void random_init(void);
extern void random_high(void *, size_t);
extern void random_low(void *, size_t);
extern uint64_t random_high_64(void);
extern uint64_t random_low_64(void);

inline uint32_t
random_high_32(void)
{
	return ((uint32_t)random_high_64() & (uint64_t)0xffffffff);
}

inline uint16_t
random_high_16(void)
{
	return ((uint16_t)random_high_64() & (uint64_t)0xffff);
}

inline uint8_t
random_high_8(void)
{
	return ((uint8_t)random_high_8() & (uint64_t)0xff);
}

inline uint32_t
random_low_32(void)
{
	return ((uint32_t)random_low_64() & (uint64_t)0xffffffff);
}

inline uint16_t
random_low_16(void)
{
	return ((uint16_t)random_low_64() & (uint64_t)0xffff);
}

inline uint8_t
random_low_8(void)
{
	return ((uint8_t)random_low_8() & (uint64_t)0xff);
}

#ifdef __cplusplus
}
#endif

#endif /* _RANDOM_H */
