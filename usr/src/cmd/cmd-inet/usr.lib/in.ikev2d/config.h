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
 * Copyright 2018, Joyent, Inc.
 */
#ifndef _CONFIG_H
#define	_CONFIG_H

#include <atomic.h>
#include <bunyan.h>
#include <netinet/in.h>
#include <synch.h>
#include <sys/types.h>
#include <sys/time.h>
#include "ikev2.h"

#ifdef __cplusplus
extern "C" {
#endif

#define	CONFIG_FILE "/etc/inet/ike/config"

/* Default values if not specified in the configuration file */
#define	CONFIG_LOCAL_ID_TYPE	CFG_AUTH_ID_IPV4
#define	CONFIG_EXPIRE_TIMER	SEC2NSEC(300)		/* 5m / 300s */
#define	CONFIG_RETRY_INIT	MSEC2NSEC(500)		/* 0.5s / 500ms */
#define	CONFIG_RETRY_MAX	SEC2NSEC(30)		/* 30s */
#define	CONFIG_RETRY_LIMIT	5U
#define	CONFIG_P2_LIFETIME_SECS	3600U
#define	CONFIG_P2_SOFTLIFE_SECS	3240U
#define	CONFIG_P2_LIFETIME_KB	(100 * 1024)
#define	CONFIG_P2_SOFTLIFE_KB	(90 * 1024)
#define	CONFIG_P2_IDLETIME_SECS 600U

typedef enum config_auth_id {
	CFG_AUTH_ID_DN,
	CFG_AUTH_ID_DNS,
	CFG_AUTH_ID_GN,
	CFG_AUTH_ID_IPV4,
	CFG_AUTH_ID_IPV4_PREFIX,
	CFG_AUTH_ID_IPV4_RANGE,
	CFG_AUTH_ID_IPV6,
	CFG_AUTH_ID_IPV6_PREFIX,
	CFG_AUTH_ID_IPV6_RANGE,
	CFG_AUTH_ID_EMAIL
} config_auth_id_t;

typedef enum config_addr_type {
	CFG_ADDR_IPV4,
	CFG_ADDR_IPV4_PREFIX,
	CFG_ADDR_IPV4_RANGE,
	CFG_ADDR_IPV6,
	CFG_ADDR_IPV6_PREFIX,
	CFG_ADDR_IPV6_RANGE
} config_addr_type_t;

typedef struct config_addr {
	config_addr_type_t	cfa_type;
	union {
		in_addr_t	cfa_ip4;
		in6_addr_t	cfa_ip6;
	} cfa_startu;
	union {
		in_addr_t	cfa_ip4;
		in6_addr_t	cfa_ip6;
		uint8_t		cfa_num;
	} cfa_endu;
#define	cfa_start4	cfa_startu.cfa_ip4
#define	cfa_start6	cfa_startu.cfa_ip6
#define	cfa_end4	cfa_endu.cfa_ip4
#define	cfa_end6	cfa_endu.cfa_ip6
} config_addr_t;

typedef struct config_id {
	config_auth_id_t	cid_type;
				/*
				 * size of cid_data, for string types, includes
				 * trailing NUL.
				 */
	size_t			cid_len;
	uint8_t			cid_data[];
} config_id_t;

typedef struct config_xf {
	char			*xf_str;
	ikev2_xf_encr_t		xf_encr;
	size_t			xf_minbits;
	size_t			xf_maxbits;
	ikev2_xf_auth_t		xf_auth;
	ikev2_dh_t		xf_dh;
	ikev2_auth_type_t	xf_authtype;
} config_xf_t;

typedef struct config_rule {
	volatile uint32_t	rule_refcnt;
	char			*rule_label;
	config_addr_t		*rule_local_addr;
	size_t			rule_nlocal_addr;
	config_addr_t		*rule_remote_addr;
	size_t			rule_nremote_addr;
	config_xf_t		**rule_xf;
	ikev2_dh_t		rule_p2_dh;
	config_id_t		*rule_local_id;
	config_id_t		**rule_remote_id;
	size_t			rule_remote_id_alloc;
	size_t			rule_p1_softlife_secs;
	size_t			rule_p1_hardlife_secs;
	size_t			rule_p2_lifetime_secs;
	size_t			rule_p2_softlife_secs;
	size_t			rule_p2_idletime_secs;
	size_t			rule_p2_lifetime_kb;
	size_t			rule_p2_softlife_kb;
	boolean_t		rule_immediate;
} config_rule_t;
#define	RULE_REFHOLD(cf) atomic_inc_32(&(cf)->rule_refcnt)
#define	RULE_REFRELE(cf)					\
	(void) ((atomic_dec_32_nv(&(cf)->rule_refcnt) != 0) ||	\
	    (config_rule_free(cf), 0))

typedef struct config {
	config_rule_t		**cfg_rules;
	config_xf_t		**cfg_default_xf;
	char			*cfg_proxy;
	char			*cfg_socks;
	config_auth_id_t	cfg_local_id_type;
	char			**cfg_cert_root;
	size_t			cfg_cert_root_alloc;
	char			**cfg_cert_trust;
	size_t			cfg_cert_trust_alloc;
	hrtime_t		cfg_expire_timer;	/* ns */
	hrtime_t		cfg_lifetime_secs;	/* ns */
	hrtime_t		cfg_retry_max;		/* ns */
	hrtime_t		cfg_retry_init;		/* ns */
	size_t			cfg_retry_limit;
	size_t			cfg_p1_softlife_secs;
	size_t			cfg_p1_hardlife_secs;
	size_t			cfg_p2_lifetime_secs;
	size_t			cfg_p2_softlife_secs;
	size_t			cfg_p2_idletime_secs;
	size_t			cfg_p2_lifetime_kb;
	size_t			cfg_p2_softlife_kb;
	ikev2_dh_t		cfg_p2_dh;
	boolean_t		cfg_ignore_crls;
	boolean_t		cfg_use_http;
} config_t;

union sockaddr_u_s;

extern config_t *config;
extern rwlock_t config_rule_lock;

config_t	*config_read(const char *);
void		config_free(config_t *);
void		config_rule_free(config_rule_t *);

config_rule_t	*config_get_rule(union sockaddr_u_s,
    union sockaddr_u_s);
boolean_t config_addr_to_ss(const config_addr_t *restrict,
    struct sockaddr_storage *restrict);

config_auth_id_t ikev2_id_to_cfg(ikev2_id_type_t);
config_id_t	*config_id_new(config_auth_id_t, const void *, size_t);
config_id_t	*config_id_copy(const config_id_t *);
int		config_id_cmp(const config_id_t *, const config_id_t *);
const char	*config_id_type_str(config_auth_id_t);
char		*config_id_str(const config_id_t *, char *, size_t);
size_t		config_id_strlen(const config_id_t *);
void		config_id_free(config_id_t *);

#ifdef __cplusplus
}
#endif

#endif /* _CONFIG_H */
