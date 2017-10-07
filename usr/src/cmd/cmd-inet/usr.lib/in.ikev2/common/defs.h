
/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */

/*
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright 2017 Jason King.
 * Copyright (c) 2017, Joyent, Inc.
 */

#ifndef _DEFS_H
#define	_DEFS_H

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/debug.h>
#include <ikedoor.h>
#include <cryptoutil.h>
#include <security/cryptoki.h>
#include <stdio.h>
#include <assert.h>
#include <umem.h>
#include <bunyan.h>
#include <libintl.h>

#ifdef  __cplusplus
extern "C" {
#endif

#ifndef SOCKADDR_U_T
#define	SOCKADDR_U_T
typedef union sockaddr_u_s {
	struct sockaddr_storage *sau_ss;
	struct sockaddr_in	*sau_sin;
	struct sockaddr_in6	*sau_sin6;
} sockaddr_u_t;
#endif /* SOCKADDR_U_T */

/* Parsed-out PF_KEY message. */
typedef struct parsedmsg_s {
	struct parsedmsg_s *pmsg_next;
	sadb_msg_t *pmsg_samsg;
	sadb_ext_t *pmsg_exts[SADB_EXT_MAX + 2]; /* 2 for alignment */
	sockaddr_u_t pmsg_sau;
	sockaddr_u_t pmsg_dau;
	sockaddr_u_t pmsg_isau;
	sockaddr_u_t pmsg_idau;
	sockaddr_u_t pmsg_nlau;
	sockaddr_u_t pmsg_nrau;
} parsedmsg_t;

#define	pmsg_sss pmsg_sau.sau_ss
#define	pmsg_ssin pmsg_sau.sau_sin
#define	pmsg_ssin6 pmsg_sau.sau_sin6
#define	pmsg_dss pmsg_dau.sau_ss
#define	pmsg_dsin pmsg_dau.sau_sin
#define	pmsg_dsin6 pmsg_dau.sau_sin6
#define	pmsg_isss pmsg_isau.sau_ss
#define	pmsg_issin pmsg_isau.sau_sin
#define	pmsg_issin6 pmsg_isau.sau_sin6
#define	pmsg_idss pmsg_idau.sau_ss
#define	pmsg_idsin pmsg_idau.sau_sin
#define	pmsg_idsin6 pmsg_idau.sau_sin6
#define	pmsg_nlss pmsg_nlau.sau_ss
#define	pmsg_nlsin pmsg_nlau.sau_sin
#define	pmsg_nlsin6 pmsg_nlau.sau_sin6
#define	pmsg_nrss pmsg_nrau.sau_ss
#define	pmsg_nrsin pmsg_rnau.sau_sin
#define	pmsg_nrsin6 pmsg_nrau.sau_sin6

typedef struct algindex {
	const char *desc;
	int doi_num;
} algindex_t;

/*
 * Compare two AF_INET{,6} sockaddrs (no port).  Assume sockaddr_storage
 * pointers are passed, and also verifies the address families match and
 * are either AF_INET or AF_INET6.
 */
#define	SA_ADDR_EQ(sa1, sa2)						\
	(((sa1)->ss_family == (sa2)->ss_family) &&			\
	    ((((sa1)->ss_family == AF_INET) &&				\
		((struct sockaddr_in *)(sa1))->sin_addr.s_addr ==	\
		((struct sockaddr_in *)(sa2))->sin_addr.s_addr) ||	\
		(((sa1)->ss_family == AF_INET6) &&			\
		IN6_ARE_ADDR_EQUAL(&((struct sockaddr_in6 *)(sa1))->sin6_addr,\
		    &((struct sockaddr_in6 *)(sa2))->sin6_addr))))

/*
 * Compare two AF_INET{,6} sockaddr ports.  Exploit the identical offsets for
 * sin_port/sin6_port.  (Does not check sockaddr families a priori.)
 */
#define	SA_PORT_EQ(sa1, sa2) (((struct sockaddr_in *)(sa1))->sin_port == \
	    ((struct sockaddr_in *)(sa2))->sin_port)

/*
 * Compare two AF_INET{,6} sockaddrs (including ports).  Exploit the
 * identical offsets for sin_port/sin6_port.
 */
#define	SA_FULL_EQ(sa1, sa2) (SA_ADDR_EQ(sa1, sa2) && SA_PORT_EQ(sa1, sa2))

#define	NOMEM assfail("Out of memory", __FILE__, __LINE__)
#define	INVALID(var) assfail("Invalid value of " # var, __FILE__, __LINE__)

#ifndef ARRAY_SIZE
#define	ARRAY_SIZE(x) (sizeof (x) / sizeof (x[0]))
#endif

/* cstyle cannot handle ## __VA_ARGS */
/* BEGIN CSTYLED */
#define	STDERR(_lvl, _log, _msg, ...)			\
	(void) bunyan_##_lvl((_log), (_msg),		\
	BUNYAN_T_STRING, "err", strerror(errno),	\
	BUNYAN_T_INT32, "errno", (int32_t)(errno),	\
	BUNYAN_T_STRING, "func", __func__,		\
	BUNYAN_T_STRING, "file", __FILE__,		\
	BUNYAN_T_INT32, "line", __LINE__,		\
	## __VA_ARGS__,					\
	BUNYAN_T_END)
/* END CSTYLED */

/* A few simple functions to simplify using struct sockaddr's w/ bunyan */
inline uint32_t
ss_port(const struct sockaddr_storage *ss)
{
	sockaddr_u_t sau;
	sau.sau_ss = (struct sockaddr_storage *)ss;
	switch (ss->ss_family) {
	case AF_INET:
		return ((uint32_t)ntohs(sau.sau_sin->sin_port));
	case AF_INET6:
		return ((uint32_t)ntohs(sau.sau_sin6->sin6_port));
	default:
		INVALID("ss->ss_family");
		/*NOTREACHED*/
		return (0);
	}
}

inline const void *
ss_addr(const struct sockaddr_storage *ss)
{
	sockaddr_u_t sau;
	sau.sau_ss = (struct sockaddr_storage *)ss;
	switch (ss->ss_family) {
	case AF_INET:
		return (&sau.sau_sin->sin_addr);
	case AF_INET6:
		return (&sau.sau_sin6->sin6_addr);
	default:
		INVALID("ss->ss_family");
		/*NOTREACHED*/
		return (NULL);
	}
}

inline int
ss_bunyan(const struct sockaddr_storage *ss)
{
	switch (ss->ss_family) {
	case AF_INET:
		return (BUNYAN_T_IP);
	case AF_INET6:
		return (BUNYAN_T_IP6);
	default:
		INVALID("ss->ss_family");
		/*NOTREACHED*/
		return (BUNYAN_T_END);
	}
}

/* BEGIN CSTYLED */
#define	NETLOG(_level, _log, _msg, _src, _dest, ...)	\
	(void) bunyan_##_level((_log), (_msg),		\
	BUNYAN_T_STRING, "func", __func__,		\
	BUNYAN_T_STRING, "file", __FILE__,		\
	BUNYAN_T_INT32, "line", __LINE__,		\
	ss_bunyan(_src), "srcaddr", ss_addr(_src),	\
	BUNYAN_T_UINT32, "srcport", ss_port(_src),	\
	ss_bunyan(_dest), "destaddr", ss_addr(_dest),	\
	BUNYAN_T_UINT32, "destport", ss_port(_dest),	\
	## __VA_ARGS__,					\
	BUNYAN_T_END)
/* END CSTYLED */

typedef enum event {
	EVENT_NONE,
	EVENT_SIGNAL
} event_t;

extern char *my_fmri;
extern bunyan_logger_t *log;
extern int main_port;

typedef int (*bunyan_logfn_t)(bunyan_logger_t *, const char *, ...);
bunyan_logfn_t getlog(bunyan_level_t);

const char *afstr(sa_family_t);
const char *symstr(void *);
const char *event_str(event_t);
const char *port_source_str(ushort_t);

#ifdef  __cplusplus
}
#endif

#endif  /* _DEFS_H */
