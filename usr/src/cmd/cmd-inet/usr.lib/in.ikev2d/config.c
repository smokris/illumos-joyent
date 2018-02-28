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
 * Copyright 2018, Joyent, Inc.
 */

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/debug.h>
#include <string.h>
#include <strings.h>
#include <synch.h>
#include <umem.h>

#include "defs.h"
#include "config.h"
#include "config_impl.h"
#include "ikev2_enum.h"
#include "util.h"

config_t *config;
rwlock_t config_rule_lock = DEFAULTRWLOCK;

static boolean_t cfg_addr_match(const sockaddr_u_t,
    const config_addr_t *restrict);

#ifdef notyet
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
#endif

/*
 * Return the first rule that matches the given local and remote addresses.
 * If no rule matches, return the default rule.  The config is refheld on
 * return.
 */
config_rule_t *
config_get_rule(sockaddr_u_t local, sockaddr_u_t remote)
{

	VERIFY0(rw_rdlock(&config_rule_lock));

	for (size_t i = 0; config->cfg_rules[i] != NULL; i++) {
		config_rule_t *rule = config->cfg_rules[i];
		boolean_t local_match = B_FALSE;
		boolean_t remote_match = B_FALSE;

		for (size_t j = 0; j < rule->rule_nlocal_addr; j++) {
			if (cfg_addr_match(local, &rule->rule_local_addr[j])) {
				local_match = B_TRUE;
				break;
			}
		}
		for (size_t j = 0; j < rule->rule_nremote_addr; j++) {
			if (cfg_addr_match(remote,
			    &rule->rule_remote_addr[j])) {
				remote_match = B_TRUE;
				break;
			}
		}
		if (local_match && remote_match) {
			RULE_REFHOLD(rule);
			VERIFY0(rw_unlock(&config_rule_lock));
			return (rule);
		}
	}
	VERIFY0(rw_unlock(&config_rule_lock));

	return (NULL);
}

boolean_t
config_addr_to_ss(const config_addr_t *restrict caddr,
    struct sockaddr_storage *restrict ss)
{
	switch (caddr->cfa_type) {
	case CFG_ADDR_IPV4_PREFIX:
	case CFG_ADDR_IPV4_RANGE:
	case CFG_ADDR_IPV6_PREFIX:
	case CFG_ADDR_IPV6_RANGE:
		return (B_FALSE);
	case CFG_ADDR_IPV4:
		ss->ss_family = AF_INET;
		((struct sockaddr_in *)ss)->sin_port = htons(IPPORT_IKE);
		bcopy(&caddr->cfa_start4, (void *)ss_addr(SSTOSA(ss)),
		    sizeof (in_addr_t));
		break;
	case CFG_ADDR_IPV6:
		ss->ss_family = AF_INET6;
		((struct sockaddr_in6 *)ss)->sin6_port = htons(IPPORT_IKE);
		bcopy(&caddr->cfa_start6, (void *)ss_addr(SSTOSA(ss)),
		    sizeof (in6_addr_t));
		break;
	}
	return (B_TRUE);
}

static boolean_t
cfg_addr_match(const sockaddr_u_t l, const config_addr_t *restrict r)
{
	uint32_t mask;

	switch (r->cfa_type) {
	case CFG_ADDR_IPV4:
		if (l.sau_ss->ss_family != AF_INET)
			return (B_FALSE);
		if (l.sau_sin->sin_addr.s_addr != r->cfa_start4)
			return (B_FALSE);
		return (B_TRUE);
	case CFG_ADDR_IPV4_PREFIX:
		/* XXX: this needs testing */
		if (l.sau_ss->ss_family != AF_INET)
			return (B_FALSE);
		mask = (0xffffffff << (32 - r->cfa_endu.cfa_num)) &
		    0xffffffff;
		if ((l.sau_sin->sin_addr.s_addr & mask) ==
		    (r->cfa_start4 & mask))
			return (B_TRUE);
		return (B_FALSE);
	case CFG_ADDR_IPV4_RANGE:
		if (l.sau_ss->ss_family != AF_INET)
			return (B_FALSE);
		if (l.sau_sin->sin_addr.s_addr >= r->cfa_start4 &&
		    l.sau_sin->sin_addr.s_addr <= r->cfa_end4)
			return (B_TRUE);
		return (B_FALSE);
	case CFG_ADDR_IPV6:
		if (l.sau_ss->ss_family != AF_INET6)
			return (B_FALSE);
		if (IN6_ARE_ADDR_EQUAL(&l.sau_sin6->sin6_addr,
		    &r->cfa_start6))
			return (B_TRUE);
		return (B_FALSE);
	case CFG_ADDR_IPV6_PREFIX:
		if (l.sau_ss->ss_family != AF_INET6)
			return (B_FALSE);
		/* LINTED E_SUSPICIOUS_COMPARISON */
		if (IN6_ARE_PREFIXEDADDR_EQUAL(&l.sau_sin6->sin6_addr,
		    &r->cfa_start6, r->cfa_endu.cfa_num))
			return (B_TRUE);
		return (B_FALSE);
	case CFG_ADDR_IPV6_RANGE:
		if (l.sau_ss->ss_family != AF_INET6)
			return (B_FALSE);
		for (size_t i = 0; i < 16; i++) {
			if ((l.sau_sin6->sin6_addr.s6_addr[i] <
			    r->cfa_start6.s6_addr[i]) ||
			    (l.sau_sin6->sin6_addr.s6_addr[i] >
			    r->cfa_end6.s6_addr[i]))
				return (B_FALSE);
		}
		return (B_TRUE);
	}
	return (B_FALSE);
}

const char *
config_id_type_str(config_auth_id_t type)
{
	switch (type) {
	case CFG_AUTH_ID_DNS:
		return ("dns");
	case CFG_AUTH_ID_EMAIL:
		return ("email");
	case CFG_AUTH_ID_DN:
		return ("dn");
	case CFG_AUTH_ID_GN:
		return ("gn");
	case CFG_AUTH_ID_IPV4:
		return ("ipv4");
	case CFG_AUTH_ID_IPV4_PREFIX:
		return ("ipv4_prefix");
	case CFG_AUTH_ID_IPV4_RANGE:
		return ("ipv4_range");
	case CFG_AUTH_ID_IPV6:
		return ("ipv6");
	case CFG_AUTH_ID_IPV6_PREFIX:
		return ("ipv6_prefix");
	case CFG_AUTH_ID_IPV6_RANGE:
		return ("ipv6_range");
	}

	INVALID(id->cid_type);
	/*NOTREACHED*/
	return (NULL);
}

char *
config_id_str(const config_id_t *id, char *buf, size_t buflen)
{
	const void *ptr = id->cid_data;
	int af = 0;

	switch (id->cid_type) {
	case CFG_AUTH_ID_DNS:
	case CFG_AUTH_ID_EMAIL:
		(void) strlcpy(buf, (const char *)ptr, buflen);
		break;
	case CFG_AUTH_ID_DN:
	case CFG_AUTH_ID_GN:
		/* TODO! */
		INVALID("dn/gn to str not implemented yet");
		break;
	case CFG_AUTH_ID_IPV4:
	case CFG_AUTH_ID_IPV4_PREFIX:
	case CFG_AUTH_ID_IPV4_RANGE:
		af = AF_INET;
		break;
	case CFG_AUTH_ID_IPV6:
	case CFG_AUTH_ID_IPV6_PREFIX:
	case CFG_AUTH_ID_IPV6_RANGE:
		af = AF_INET6;
		break;
	}

	if (inet_ntop(af, ptr, buf, buflen) == NULL)
		bzero(buf, buflen);

	return (buf);
}

size_t
config_id_strlen(const config_id_t *id)
{
	switch (id->cid_type) {
	case CFG_AUTH_ID_DNS:
	case CFG_AUTH_ID_EMAIL:
		return (id->cid_len + 1);
	case CFG_AUTH_ID_DN:
	case CFG_AUTH_ID_GN:
		/* TODO */
		INVALID(id->cid_type);
		break;
	case CFG_AUTH_ID_IPV4:
		return (INET_ADDRSTRLEN);
	case CFG_AUTH_ID_IPV4_PREFIX:
		return (INET_ADDRSTRLEN + 3);
	case CFG_AUTH_ID_IPV4_RANGE:
		return (2 * INET_ADDRSTRLEN + 1);
	case CFG_AUTH_ID_IPV6:
		return (INET6_ADDRSTRLEN);
	case CFG_AUTH_ID_IPV6_PREFIX:
		return (INET6_ADDRSTRLEN + 4);
	case CFG_AUTH_ID_IPV6_RANGE:
		return (2 * INET6_ADDRSTRLEN + 1);
	}

	/*NOTREACHED*/
	return (0);
}

config_id_t *
config_id_new(config_auth_id_t type, const void *data, size_t len)
{
	config_id_t *cid = NULL;

	if ((cid = umem_zalloc(sizeof (*cid) + len, UMEM_DEFAULT)) == NULL)
		return (NULL);

	cid->cid_type = type;
	cid->cid_len = len;
	bcopy(data, cid->cid_data, len);
	return (cid);
}

int
config_id_cmp(const config_id_t *l, const config_id_t *r)
{
	if (l->cid_type < r->cid_type)
		return (-1);
	if (l->cid_type > r->cid_type)
		return (1);
	return (memcmp(l->cid_data, r->cid_data, MIN(l->cid_len, r->cid_len)));
}

void
config_id_free(config_id_t *id)
{
	if (id == NULL)
		return;
	umem_free(id, id->cid_len + sizeof (config_id_t));
}

config_xf_t *
config_xf_new(void)
{
	return (umem_zalloc(sizeof (config_xf_t), UMEM_DEFAULT));
}

void
config_xf_free(config_xf_t *xf)
{
	if (xf == NULL)
		return;
	ustrfree(xf->xf_str);
	umem_free(xf, sizeof (*xf));
}

void
config_xfs_free(config_xf_t **xfs)
{
	size_t i;

	if (xfs == NULL)
		return;

	for (i = 0; xfs[i] != NULL; i++)
		config_xf_free(xfs[i]);
	umem_cfree(xfs, i + 1, sizeof (config_xf_t *));
}

config_rule_t *
config_rule_new(void)
{
	return (umem_zalloc(sizeof (config_rule_t), UMEM_DEFAULT));
}

void
config_rule_free(config_rule_t *rule)
{
	size_t i;

	if (rule == NULL)
		return;

	VERIFY3U(rule->rule_refcnt, ==, 0);

	if (rule->rule_remote_id != NULL) {
		for (i = 0; rule->rule_remote_id[i] != NULL; i++)
			config_id_free(rule->rule_remote_id[i]);

		umem_cfree(rule->rule_remote_id, i + 1, sizeof (config_id_t *));
	}

	config_xfs_free(rule->rule_xf);
	ustrfree(rule->rule_label);
	umem_cfree(rule->rule_local_addr, rule->rule_nlocal_addr,
	    sizeof (config_addr_t));
	umem_cfree(rule->rule_remote_addr, rule->rule_nremote_addr,
	    sizeof (config_addr_t));
	umem_free(rule, sizeof (*rule));
}

config_t *
config_new(void)
{
	config_t *cfg = umem_zalloc(sizeof (*cfg), UMEM_DEFAULT);

	if (cfg == NULL)
		return (NULL);

	/* Setup defaults */
	cfg->cfg_local_id_type = CONFIG_LOCAL_ID_TYPE;
	cfg->cfg_expire_timer = CONFIG_EXPIRE_TIMER;
	cfg->cfg_retry_init = CONFIG_RETRY_INIT;
	cfg->cfg_retry_max = CONFIG_RETRY_MAX;
	cfg->cfg_retry_limit = CONFIG_RETRY_LIMIT;
	cfg->cfg_p2_lifetime_secs = CONFIG_P2_LIFETIME_SECS;
	cfg->cfg_p2_softlife_secs = CONFIG_P2_SOFTLIFE_SECS;
	cfg->cfg_p2_lifetime_kb = CONFIG_P2_LIFETIME_KB;
	cfg->cfg_p2_softlife_kb = CONFIG_P2_SOFTLIFE_KB;

	return (cfg);
}

void
config_free(config_t *cfg)
{
	if (cfg == NULL)
		return;

	strarray_free(cfg->cfg_cert_root);
	strarray_free(cfg->cfg_cert_trust);
	ustrfree(cfg->cfg_proxy);
	ustrfree(cfg->cfg_socks);
	config_xfs_free(cfg->cfg_default_xf);

	if (cfg->cfg_rules != NULL) {
		size_t i;

		for (i = 0; cfg->cfg_rules[i] != NULL; i++)
			RULE_REFRELE(cfg->cfg_rules[i]);

		umem_cfree(cfg->cfg_rules, i + 1, sizeof (config_rule_t *));
	}

	umem_free(cfg, sizeof (*cfg));
}
