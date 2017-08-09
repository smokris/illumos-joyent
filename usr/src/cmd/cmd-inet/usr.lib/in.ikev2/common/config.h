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
} config_addr_t;

typedef struct config_id_s {
	config_auth_id_t	id_type;
	union {
		char *id_str;
		struct {
			uint8_t	*id_buf;
			size_t	id_len;
		} id_buf;
		in_addr_t	id_ipv4;
		in6_addr_t	id_ipv6;
	} val;
} config_id_t;

typedef struct config_xf_s {
	ikev2_xf_encr_t		xf_encr;
	size_t			xf_minbits;
	size_t			xf_maxbits;
	ikev2_xf_auth_t		xf_auth;
	ikev2_dh_t		xf_dh;
	ikev2_auth_type_t	xf_authtype;
} config_xf_t;

typedef struct config_rule_s {
	char			*cfg_label;
	config_auth_id_t	cfg_local_id_type;
	config_addr_t		*cfg_local_addr;
	size_t			cfg_nlocal_addr;
	config_addr_t		*cfg_remote_addr;
	size_t			cfg_nremote_addr;
	config_id_t		*cfg_id;
	config_xf_t		*cfg_xf;
	size_t			cfg_nxf;
	ikev2_dh_t		cfg_p2_dh;
} config_rule_t;

extern pthread_rwlock_t cfg_lock;
extern char **cfg_cert_root;
extern char **cfg_cert_trust;
extern boolean_t cfg_ignore_crls;
extern hrtime_t cfg_expire_timer;
extern hrtime_t cfg_lifetime_secs;
extern hrtime_t cfg_retry_max;
extern hrtime_t cfg_retry_init;
extern size_t cfg_retry_limit;

void process_config(FILE *, boolean_t, bunyan_logger_t *);

#ifdef __cplusplus
}
#endif

#endif /* _CONFIG_H */
