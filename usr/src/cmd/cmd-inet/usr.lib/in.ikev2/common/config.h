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

typedef struct config_id_s {
	ikev2_id_type_t		id_type;
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

typedef struct config_s {
	char	*cfg_label;
} config_t;

extern hrtime_t cfg_lifetime_secs;
extern volatile hrtime_t cfg_retry_max;
extern volatile hrtime_t cfg_retry_init;

void process_config(FILE *, boolean_t, bunyan_logger_t *);

#ifdef __cplusplus
}
#endif

#endif /* _CONFIG_H */
