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
#include "defs.h"
#include "config.h"
#include "ikev2_enum.h"

pthread_rwlock_t cfg_lock = PTHREAD_RWLOCK_INITIALIZER;
config_t *config;

config_t *
config_get(void)
{
	config_t *cfg = NULL;

	PTH(pthread_rwlock_rdlock(&cfg_lock));
	cfg = config;
	atomic_inc_32(&cfg->cfg_refcnt);
	PTH(pthread_rwlock_unlock(&cfg_lock));
	return (cfg);
}

void
config_xf_log(bunyan_logger_t *b, bunyan_level_t level, const char *msg,
    const config_xf_t *xf)
{
	getlog(level)(b, msg,
	    BUNYAN_T_STRING, "xf_encralg", ikev2_xf_encr_str(xf->xf_encr),
	    BUNYAN_T_UINT32, "xf_minbits", (uint32_t)xf->xf_minbits,
	    BUNYAN_T_UINT32, "xf_maxbits", (uint32_t)xf->xf_maxbits,
	    BUNYAN_T_STRING, "xf_authalg", ikev2_xf_auth_str(xf->xf_auth),
	    BUNYAN_T_STRING, "xf_authtype",
	    ikev2_auth_type_str(xf->xf_authtype),
	    BUNYAN_T_STRING, "xf_dh", ikev2_dh_str(xf->xf_dh),
	    BUNYAN_T_END);
}

void
cfg_rule_free(config_rule_t *rule)
{
	if (rule == NULL)
		return;

	if (rule->rule_xf != NULL) {
		for (size_t i = 0; rule->rule_xf[i] != NULL; i++)
			free(rule->rule_xf[i]);
	}

	free(rule->rule_xf);
	free(rule->rule_local_addr);
	free(rule->rule_remote_addr);
	free(rule->rule_label);
	free(rule);
}

void
cfg_free(config_t *cfg)
{
	if (cfg == NULL)
		return;

	size_t i;

	VERIFY3U(cfg->cfg_refcnt, ==, 0);
	
	for (i = 0;
	    cfg->cfg_cert_root != NULL && cfg->cfg_cert_root[i] != NULL;
	    i++)
		free(cfg->cfg_cert_root[i]);

	if (cfg->cfg_cert_trust != NULL) {
		for (i = 0; cfg->cfg_cert_trust[i] != NULL; i++)
			free(cfg->cfg_cert_trust[i]);
	}

	if (cfg->cfg_xforms != NULL) {
		for (i = 0; cfg->cfg_xforms[i] != NULL; i++)
			free(cfg->cfg_xforms[i]);
	}

	if (cfg->cfg_rules != NULL) {
		for (i = 0; cfg->cfg_rules[i] != NULL; i++)
			cfg_rule_free(cfg->cfg_rules[i]);
	}

	free(cfg->cfg_rules);
	free(cfg->cfg_xforms);
	free(cfg->cfg_proxy);
	free(cfg->cfg_socks);
	free(cfg->cfg_cert_root);
	free(cfg->cfg_cert_trust);
	free(cfg);
}
