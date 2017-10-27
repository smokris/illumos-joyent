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
 * Copyright (c) 2017, Joyent, Inc.
 */
#ifndef _CONFIG_H
#define	_CONFIG_H

#include <sys/types.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <stdio.h>
#include <bunyan.h>
#include <pthread.h>
#include <atomic.h>
#include "ikev2.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum config_auth_id_e {
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

typedef enum config_addr_e {
	CFG_ADDR_IPV4,
	CFG_ADDR_IPV4_PREFIX,
	CFG_ADDR_IPV4_RANGE,
	CFG_ADDR_IPV6,
	CFG_ADDR_IPV6_PREFIX,
	CFG_ADDR_IPV6_RANGE
} config_addr_type_t;

typedef struct config_addr_s {
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

typedef struct config_id_s {
	config_auth_id_t	cid_type;
				/*
				 * size of cid_data, for string types, includes
				 * trailing NUL.
				 */
	size_t			cid_len;
	uint8_t			cid_data[];
} config_id_t;

typedef struct config_xf_s {
	char			*xf_str;
	ikev2_xf_encr_t		xf_encr;
	size_t			xf_minbits;
	size_t			xf_maxbits;
	ikev2_xf_auth_t		xf_auth;
	ikev2_dh_t		xf_dh;
	ikev2_auth_type_t	xf_authtype;
	size_t			xf_lifetime_secs;
	size_t			xf_nonce_len;
} config_xf_t;

struct config_s;
typedef struct config_rule_s {
	struct config_s		*rule_config;
	char			*rule_label;
	config_addr_t		*rule_local_addr;
	size_t			rule_nlocal_addr;
	config_addr_t		*rule_remote_addr;
	size_t			rule_nremote_addr;
	config_xf_t		**rule_xf;
	size_t			rule_nxf;
	ikev2_dh_t		rule_p2_dh;
	config_id_t		*rule_local_id;
	config_id_t		**rule_remote_id;
	size_t			rule_remote_id_alloc;
	boolean_t		rule_immediate;
} config_rule_t;

struct config_s {
	volatile uint32_t	cfg_refcnt;
	config_rule_t		cfg_default;
	config_rule_t		**cfg_rules;
	size_t			cfg_rules_alloc;
	size_t			cfg_xforms_alloc;
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
	boolean_t		cfg_ignore_crls;
	boolean_t		cfg_use_http;
	size_t			cfg_p1_softlife_secs;
	size_t			cfg_p1_hardlife_secs;
	size_t			cfg_p1_nonce_len;
	size_t			cfg_p2_lifetime_secs;
	size_t			cfg_p2_softlife_secs;
	size_t			cfg_p2_idletime_secs;
	size_t			cfg_p2_lifetime_kb;
	size_t			cfg_p2_softlife_kb;
	size_t			cfg_p2_nonce_len;
};
typedef struct config_s config_t;
#define	CONFIG_REFHOLD(cp) (void)atomic_inc_32(&(cp)->cfg_refcnt)
#define	CONFIG_REFRELE(cp) \
	(void) ((atomic_dec_32_nv(&(cp)->cfg_refcnt) != 0) || \
	    (cfg_free(cp), 0))
#define	RULE_IS_DEFAULT(r) (!!(&(r)->rule_config->cfg_default == (r)))

union sockaddr_u_s;
extern pthread_rwlock_t cfg_lock;
extern config_t *config;

void process_config(FILE *, boolean_t);
config_t *config_get(void);
config_rule_t *config_get_rule(union sockaddr_u_s,
    union sockaddr_u_s);
void cfg_rule_free(config_rule_t *);
void cfg_free(config_t *);

boolean_t config_addr_to_ss(config_addr_t *, union sockaddr_u_s);

config_auth_id_t ikev2_id_to_cfg(ikev2_id_type_t);
config_id_t *config_id_new(config_auth_id_t, const void *, size_t);
config_id_t *config_id_copy(const config_id_t *);
int config_id_cmp(const config_id_t *, const config_id_t *);
const char *config_id_type_str(config_auth_id_t);
char *config_id_str(const config_id_t *, char *, size_t);
void config_id_free(config_id_t *);

#ifdef __cplusplus
}
#endif

#endif /* _CONFIG_H */
