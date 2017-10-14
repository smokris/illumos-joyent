
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

#include <bunyan.h>
#include <cryptoutil.h>
#include <libintl.h>
#include <security/cryptoki.h>
#include <sys/debug.h>
#include <sys/list.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <ikedoor.h>
#include <stdio.h>
#include <umem.h>

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
	list_node_t pmsg_node;
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
void parsedmsg_free(parsedmsg_t *);

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

/* A few simple functions to simplify using struct sockaddr's w/ bunyan */
int ss_bunyan(const struct sockaddr_storage *);
uint32_t ss_port(const struct sockaddr_storage *);
const void *ss_addr(const struct sockaddr_storage *);

#define	BLOG_KEY_SRC		"src"
#define	BLOG_KEY_SRCPORT	"srcport"
#define	BLOG_KEY_DEST		"dest"
#define	BLOG_KEY_DESTPORT	"destport"

#define	BLOG_KEY_ERRMSG		"err"
#define	BLOG_KEY_ERRNO		"errno"
#define	BLOG_KEY_FILE		"file"
#define	BLOG_KEY_FUNC		"func"
#define	BLOG_KEY_LINE		"line"

/* cstyle cannot handle ## __VA_ARGS */
/* BEGIN CSTYLED */
#define	TSTDERR(_e, _lvl, _log, _msg, ...)			\
	(void) bunyan_##_lvl((_log), (_msg),			\
	BUNYAN_T_STRING, BLOG_KEY_ERRMSG, strerror(_e),		\
	BUNYAN_T_INT32, BLOG_KEY_ERRNO, (int32_t)(_e),		\
	BUNYAN_T_STRING, BLOG_KEY_FUNC, __func__,		\
	BUNYAN_T_STRING, BLOG_KEY_FILE, __FILE__,		\
	BUNYAN_T_INT32, BLOG_KEY_LINE, __LINE__,		\
	## __VA_ARGS__,						\
	BUNYAN_T_END)

#define	STDERR(_lvl, _log, _msg, ...) \
	TSTDERR(errno, _lvl, _log, _msg, ## __VA_ARGS__)

/* END CSTYLED */

/* BEGIN CSTYLED */
#define	NETLOG(_level, _log, _msg, _src, _dest, ...)		\
	(void) bunyan_##_level((_log), (_msg),			\
	BUNYAN_T_STRING, BLOG_KEY_FUNC, __func__,		\
	BUNYAN_T_STRING, BLOG_KEY_FILE, __FILE__,		\
	BUNYAN_T_INT32, BLOG_KEY_LINE, __LINE__,		\
	ss_bunyan(_src), BLOG_KEY_SRC, ss_addr(_src),		\
	BUNYAN_T_UINT32, BLOG_KEY_SRCPORT, ss_port(_src),	\
	ss_bunyan(_dest), BLOG_KEY_DEST, ss_addr(_dest),	\
	BUNYAN_T_UINT32, BLOG_KEY_DESTPORT, ss_port(_dest),	\
	## __VA_ARGS__,						\
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
const char *symstr(void *, char *, size_t);
const char *event_str(event_t);

/* Size of largest possible port source string + NUL */
#define	PORT_SOURCE_STR_LEN	20
char *port_source_str(ushort_t, char *, size_t);

void pfkey_msg_init(sadb_msg_t *, uint8_t, uint8_t);
size_t pfkey_add_address(sadb_address_t *, sockaddr_u_t, void *);
void pfkey_send_error(const sadb_msg_t *, uint8_t);
boolean_t pfkey_getspi(sockaddr_u_t, sockaddr_u_t, uint8_t, uint32_t *);
boolean_t pfkey_inverse_acquire(sockaddr_u_t, sockaddr_u_t, sockaddr_u_t,
    sockaddr_u_t, parsedmsg_t **);

void sadb_log(bunyan_logger_t *restrict, bunyan_level_t, const char *restrict,
    sadb_msg_t *restrict);

#ifdef  __cplusplus
}
#endif

#endif  /* _DEFS_H */
