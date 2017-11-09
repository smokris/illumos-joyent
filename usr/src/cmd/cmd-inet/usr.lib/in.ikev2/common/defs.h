
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

#define	PMSG_FROM_KERNEL(pmsg) ((pmsg)->pmsg_samsg->sadb_msg_pid == 0)

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

#define	INVALID(var) assfail("Invalid value of " # var, __FILE__, __LINE__)

#ifndef ARRAY_SIZE
#define	ARRAY_SIZE(x) (sizeof (x) / sizeof (x[0]))
#endif

/* A few simple functions to simplify using struct sockaddr's w/ bunyan */
int ss_bunyan(const struct sockaddr_storage *);
uint32_t ss_port(const struct sockaddr_storage *);
const void *ss_addr(const struct sockaddr_storage *);

#define	LOG_KEY_ERRMSG	"err"
#define	LOG_KEY_ERRNO	"errno"
#define	LOG_KEY_FILE	"file"
#define	LOG_KEY_FUNC	"func"
#define	LOG_KEY_LINE	"line"

#define	LOG_KEY_I2SA		"i2sa"
#define	LOG_KEY_LADDR		"local_addr"
#define	LOG_KEY_RADDR		"remote_addr"
#define	LOG_KEY_LSPI		"local_spi"
#define	LOG_KEY_RSPI		"remote_spi"
#define	LOG_KEY_INITIATOR	"initiator"
#define	LOG_KEY_LOCAL_ID	"local_id"
#define	LOG_KEY_LOCAL_ID_TYPE	LOG_KEY_LOCAL_ID "_type"
#define	LOG_KEY_REMOTE_ID	"remote_id"
#define	LOG_KEY_REMOTE_ID_TYPE	LOG_KEY_REMOTE_ID "_type"

#define	LOG_KEY_REQ	"req_pkt"
#define	LOG_KEY_RESP	"resp_pkt"
#define	LOG_KEY_VERSION	"ike_version"
#define	LOG_KEY_MSGID	"msgid"
#define	LOG_KEY_EXCHTYPE "exch_type"

/* cstyle cannot handle ## __VA_ARGS */
/* BEGIN CSTYLED */
#define	TSTDERR(_e, _lvl, _msg, ...)			\
	(void) bunyan_##_lvl(log, (_msg),			\
	BUNYAN_T_STRING, LOG_KEY_ERRMSG, strerror(_e),		\
	BUNYAN_T_INT32, LOG_KEY_ERRNO, (int32_t)(_e),		\
	BUNYAN_T_STRING, LOG_KEY_FUNC, __func__,		\
	BUNYAN_T_STRING, LOG_KEY_FILE, __FILE__,		\
	BUNYAN_T_INT32, LOG_KEY_LINE, __LINE__,		\
	## __VA_ARGS__,						\
	BUNYAN_T_END)

#define	STDERR(_lvl, _msg, ...) \
	TSTDERR(errno, _lvl, _msg, ## __VA_ARGS__)

/* END CSTYLED */

typedef enum event {
	EVENT_NONE,
	EVENT_SIGNAL
} event_t;

extern char *my_fmri;
extern int main_port;
/*
 * While bunyan itself is multithreaded, since every thread runs some sort
 * of event loop, by guaranteeing every thread it's own instance, we can
 * build up keys as the event goes through processing, and then reset the keys
 * before we loop around again.
 */
extern __thread bunyan_logger_t *log;

typedef int (*bunyan_logfn_t)(bunyan_logger_t *, const char *, ...);
bunyan_logfn_t getlog(bunyan_level_t);

const char *afstr(sa_family_t);
const char *symstr(void *, char *, size_t);
const char *event_str(event_t);

/* Size of largest possible port source string + NUL */
#define	PORT_SOURCE_STRLEN	20
char *port_source_str(ushort_t, char *, size_t);

void log_reset_keys(void);
void key_add_ike_version(const char *, uint8_t);
void key_add_ike_spi(const char *, uint64_t);
void key_add_addr(const char *, struct sockaddr_storage *);
struct config_id_s;
void key_add_id(const char *, const char *, struct config_id_s *);
char *writehex(uint8_t *, size_t, char *, char *, size_t);

void sockaddr_copy(const struct sockaddr_storage *, struct sockaddr_storage *,
    boolean_t);
void net_to_range(const struct sockaddr_storage *, uint8_t,
    struct sockaddr_storage *, struct sockaddr_storage *);
void range_intersection(struct sockaddr_storage *restrict,
    struct sockaddr_storage *restrict,
    const struct sockaddr_storage *restrict,
    const struct sockaddr_storage *restrict,
    const struct sockaddr_storage *restrict,
    const struct sockaddr_storage *restrict);
int range_cmp_size(const struct sockaddr_storage *,
    const struct sockaddr_storage *restrict,
    const struct sockaddr_storage *restrict,
    const struct sockaddr_storage *restrict);
void range_clamp(struct sockaddr_storage *restrict,
    struct sockaddr_storage *restrict);
boolean_t range_is_zero(const struct sockaddr_storage *,
    const struct sockaddr_storage *);

#ifdef  __cplusplus
}
#endif

#endif  /* _DEFS_H */
