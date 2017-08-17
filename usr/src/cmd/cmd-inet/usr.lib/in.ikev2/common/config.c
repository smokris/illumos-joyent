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
 * Copyright (c) 2017, Joyent, Inc.
 */
#include <sys/types.h>
#include <sys/debug.h>
#include <pthread.h>
#include "config.h"

pthread_rwlock_t cfg_lock = PTHREAD_RWLOCK_INITIALIZER;

char **cfg_cert_root;
char **cfg_cert_trust;
hrtime_t cfg_retry_max = SEC2NSEC(60);
hrtime_t cfg_retry_init = SEC2NSEC(1);
hrtime_t cfg_expire_timer;
hrtime_t cfg_lifetime_secs;
size_t cfg_retry_limit;
boolean_t cfg_ignore_crls;
boolean_t cfg_use_http;

config_xf_t **cfg_def_xforms;
size_t cfg_def_nxforms;

config_rule_t **cfg_rules;
size_t cfg_nrules;
ikev2_dh_t cfg_def_p2_pfs;

void
cfg_rule_free(config_rule_t *rule)
{
	if (rule == NULL)
		return;

	VERIFY3U(rule->cfg_refcnt, ==, 0);
	VERIFY(rule->cfg_condemn);

	for (size_t i = 0; i < rule->cfg_nxf; i++)
		free(rule->cfg_xf[i]);
	free(rule->cfg_xf);
	free(rule->cfg_local_addr);
	free(rule->cfg_remote_addr);
	free(rule->cfg_label);
	free(rule);
}

