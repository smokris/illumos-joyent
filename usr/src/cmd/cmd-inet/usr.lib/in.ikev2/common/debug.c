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

#include <sys/types.h>
#include <sys/socket.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <sys/debug.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <alloca.h>

#include "defs.h"
#include "debug.h"

FILE		*dbg_file = stderr;
uint32_t	debug_evt = 0;
uint32_t	debug_opts = 0;

/*
 * Output a debug message.  To make useful debugging messages easier,
 * while this is printf-esque, the conversion specifications ARE DIFFERENT:
 * The general format is:
 *
 * %[(str)]c
 *
 * Where width and precision have the equivalent meanings as printf.
 * base allows an integral parameter to specify the output base (1-36).
 * Values of c are:
 *
 *  a	Argument is a sockaddr_u_t.  Print address only
 *  A	Argument is a sockaddr_u_t.  Print address:port.
 *  e	Argument is an enumerated value specified by 'str'.
 *  i	Argument is an integral value.
 *  m	The current value of errno (no argument).
 *  p	Argument is a pointer.  Display in hex with leading 0x.
 *  s	Argument is a string.
 *  z	Argument is size_t
 */

typedef struct fmt_s {
	const char	*fmt_str;
	va_list		args;
	int		opt;
	const char	*opt_str;
	size_t		opt_len;
} fmt_t;

static int process_option(fmt_t *);
static void write_addr(sockaddr_u_t *, boolean_t);

void
dbg_printf(const char *fmt_str, ...)
{
	va_list ap;

	va_start(ap, fmt_str);
	dbg_vprintf(fmt_str, ap);
	va_end(ap);
}

void
dbg_vprintf(const char *fmt_str, va_list ap)
{
	const char	*p;
	const char	*s_end;
	fmt_t		fmt = { 0 };

	fmt.fmt_str = fmt_str;

	flockfile(dbg_file);

	p = fmt_str;
	while (*p != '\0') {
		const char *span = strchr(p, '%');

		if (span == NULL)
			span = p + strlen(p); /* point to \0 */

		if (span > p)
			(void) fwrite(p, (size_t)(span - p), 1, dbg_file);

		p = span;
		if (*p == '\0')
			goto done;

		ASSERT(*p == '%');

		(void) memset(&fmt, 0, sizeof (fmt));
		fmt.fmt_str = fmt_str;
		va_copy(fmt.args, ap);

restart:
		fmt.opt_str = NULL;
		fmt.opt_len = 0;

		switch (p[1]) {
		case '\0':
			/* % at end of string */
			(void) putc_unlocked('%', dbg_file);
			goto done;
		case '%':
			/* %% */
			(void) putc_unlocked('%', dbg_file);
			p += 2;
			continue;
		case '(':
			VERIFY((s_end = strchr(p, ')')) != NULL);
			fmt.opt_str = p + 2;
			fmt.opt_len = (size_t)(s_end - p - 1);
			p = s_end + 1;
			goto restart;
		case 'a':
		case 'A':
		case 'e':
		case 'i':
		case 'm':
		case 'p':
		case 's':
		case 'z':
			fmt.opt = p[1];
			p += 2;
			break;
		default:
			/* invalid format string */
			INVALID(p[1]);
		}

		if (process_option(&fmt) != 0)
			goto done;
	}

done:
	/* always terminate a message with a newline */
	(void) putc_unlocked('\n', dbg_file);
	funlockfile(dbg_file);
}

static int
process_option(fmt_t *fmt)
{
	char *opt_str = NULL;

	union {
		sockaddr_u_t *su;
		const char *str;
		const void *p;
		size_t sz;
	} u;

	if (fmt->opt_str != NULL) {
		opt_str = alloca(fmt->opt_len + 1);
		(void) memset(opt_str, 0, fmt->opt_len + 1);
		(void) strncpy(opt_str, fmt->opt_str, fmt->opt_len);
	}
		
	switch (fmt->opt) {
	case 'a':
	case 'A':
		u.su = va_arg(fmt->args, sockaddr_u_t *);
		write_addr(u.su, (fmt->opt == 'A') ? B_TRUE : B_FALSE);
		break;

	case 'm':
		(void) fprintf(dbg_file, "%s", strerror(errno));
		break;

	case 's':
		u.str = va_arg(fmt->args, const char *);
		(void) fprintf(dbg_file, "%s", u.str);
		break;

	case 'p':
		u.p = va_arg(fmt->args, const void *);
		(void) fprintf(dbg_file, "0x%p", u.p);
		break;

	case 'z':
		u.sz = va_arg(fmt->args, size_t);
		(void) fprintf(dbg_file, "%zu", u.sz);
		break;

	default:
		  INVALID(fmt->opt);
	}

	return (0);
}

static void
write_addr(sockaddr_u_t *sa, boolean_t port)
{
	char buf[INET6_ADDRSTRLEN] = { 0 };
	const void *addr = NULL;
	boolean_t ip6 = B_FALSE;

	switch (sa->sau_ss->ss_family) {
	case AF_INET:
		addr = &sa->sau_sin->sin_addr;
		break;
	case AF_INET6:
		addr = &sa->sau_sin6->sin6_addr;
		ip6 = B_TRUE;
		break;
	default:
		VERIFY(0);
	}

	VERIFY(inet_ntop(sa->sau_ss->ss_family, addr, buf,
	    sizeof (buf)) != NULL);

	if (port & ip6)
		(void) putc_unlocked('[', dbg_file);

	(void) fwrite(buf, strlen(buf), 1, dbg_file);

	if (port & ip6)
		(void) putc_unlocked(']', dbg_file);

	/*
	 * sockaddr_sin and sockaddr_sin6 both keep the port in the
	 * same location
	 */
	if (port)
		(void) fprintf(dbg_file, ":%" PRIu16, sa->sau_sin->sin_port);
}

extern void DBG(int, const char *, ...);
