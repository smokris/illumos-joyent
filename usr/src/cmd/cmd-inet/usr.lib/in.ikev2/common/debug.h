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
#ifndef _DEBUG_H
#define	_DEBUG_H

#include <inttypes.h>

#ifdef __cplusplus
extern "C" {
#endif

#define	DBG_SHOW_TID	(1U << 0)	/* output TID in debug messages */

extern uint32_t debug_evt;
extern uint32_t debug_opts;

extern void dbg_printf(const char *, ...);
extern void dbg_vprintf(const char *, va_list);

inline void
DBG(int level, const char *msg, ...)
{
	if (!(debug_opts & level))
		return;

	va_list ap;

	va_start(ap, msg);
	dbg_vprintf(msg, ap);
	va_end(ap);
}

#ifdef __cplusplus
}
#endif

#endif /* _DEBUG_H */
