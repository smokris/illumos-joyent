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
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/debug.h>
#include <pthread.h>
#include <string.h>
#include <strings.h>
#include <umem.h>
#include "defs.h"
#include "config.h"
#include "ikev2_enum.h"

pthread_rwlock_t cfg_lock = PTHREAD_RWLOCK_INITIALIZER;
config_t *config;

static boolean_t cfg_addr_match(const sockaddr_u_t,
    const config_addr_t *restrict);

config_t *
config_get(void)
{
	config_t *cfg = NULL;

	VERIFY0(pthread_rwlock_rdlock(&cfg_lock));
	cfg = config;
	CONFIG_REFHOLD(cfg);
	VERIFY0(pthread_rwlock_unlock(&cfg_lock));
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

/*
 * Return the first rule that matches the given local and remote addresses.
 * If no rule matches, return the default rule.  The config is refheld on
 * return.
 */
config_rule_t *
config_get_rule(sockaddr_u_t local, sockaddr_u_t remote)
{
	config_t *cfg = config_get();

	for (size_t i = 0; cfg->cfg_rules[i] != NULL; i++) {
		config_rule_t *rule = cfg->cfg_rules[i];
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
		if (local_match && remote_match)
			return (rule);
	}

	return (&cfg->cfg_default);
}

boolean_t
config_addr_to_ss(config_addr_t *caddr, sockaddr_u_t saddr)
{
	switch (caddr->cfa_type) {
	case CFG_ADDR_IPV4_PREFIX:
	case CFG_ADDR_IPV4_RANGE:
	case CFG_ADDR_IPV6_PREFIX:
	case CFG_ADDR_IPV6_RANGE:
		return (B_FALSE);
	case CFG_ADDR_IPV4:
		saddr.sau_sin->sin_family = AF_INET;
		saddr.sau_sin->sin_port = htons(IPPORT_IKE);
		(void) memcpy(&saddr.sau_sin->sin_addr, &caddr->cfa_start4,
		    sizeof (in_addr_t));
		break;
	case CFG_ADDR_IPV6:
		saddr.sau_sin6->sin6_family = AF_INET6;
		saddr.sau_sin6->sin6_port = htons(IPPORT_IKE);
		(void) memcpy(&saddr.sau_sin6->sin6_addr, &caddr->cfa_start6,
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
		/*TODO*/
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
config_auth_id_t
ikev2_id_to_cfg(ikev2_id_type_t i2id)
{
	switch (i2id) {
	case IKEV2_ID_IPV4_ADDR:
		return (CFG_AUTH_ID_IPV4);
	case IKEV2_ID_FQDN:
		return (CFG_AUTH_ID_DNS);
	case IKEV2_ID_RFC822_ADDR:
		return (CFG_AUTH_ID_EMAIL);
	case IKEV2_ID_IPV6_ADDR:
		return (CFG_AUTH_ID_IPV6);
	case IKEV2_ID_DER_ASN1_DN:
		return (CFG_AUTH_ID_DN);
	case IKEV2_ID_DER_ASN1_GN:
		return (CFG_AUTH_ID_GN);
	case IKEV2_ID_KEY_ID:
		INVALID(i2id);
		/*NOTREACHED*/
		return (0);
	case IKEV2_ID_FC_NAME:
		INVALID(i2id);
		/*NOTREACHED*/
		return (0);
	}
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

config_id_t *
config_id_copy(const config_id_t *src)
{
	return (config_id_new(src->cid_type, src->cid_data, src->cid_len));
}

int
config_id_cmp(const config_id_t *l, const config_id_t *r)
{
	if (l->cid_type != r->cid_type)
		return (l->cid_type - r->cid_type);
	return (memcmp(l->cid_data, r->cid_data, MIN(l->cid_len, r->cid_len)));
}

void
config_id_free(config_id_t *id)
{
	if (id == NULL)
		return;

	size_t len = id->cid_len + sizeof (config_id_t);

	umem_free(id, len);
}

void
cfg_rule_free(config_rule_t *rule)
{
	size_t i;

	if (rule == NULL)
		return;

	if (rule->rule_xf != NULL) {
		for (i = 0; rule->rule_xf[i] != NULL; i++) {
			char *s = rule->rule_xf[i]->xf_str;

			ustrfree(rule->rule_xf[i]->xf_str);
			umem_free(rule->rule_xf[i], sizeof (config_xf_t));
		}
		umem_cfree(rule->rule_xf, i + 1, sizeof (config_xf_t *));
	}

	if (rule->rule_remote_id != NULL) {
		for (i = 0; rule->rule_remote_id[i] != NULL; i++)
			config_id_free(rule->rule_remote_id[i]);

		umem_cfree(rule->rule_remote_id, i + 1, sizeof (config_id_t *));
	}

	free(rule->rule_local_addr);
	free(rule->rule_remote_addr);
	ustrfree(rule->rule_label);
	umem_free(rule, sizeof (*rule));
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
	free(cfg->cfg_cert_root);

	if (cfg->cfg_cert_trust != NULL) {
		for (i = 0; cfg->cfg_cert_trust[i] != NULL; i++)
			free(cfg->cfg_cert_trust[i]);
		free(cfg->cfg_cert_trust);
	}

	if (cfg->cfg_default.rule_xf != NULL) {
		size_t nxf = 0;

		for (i = 0; cfg->cfg_default.rule_xf[i] != NULL; i++, nxf++) {
			umem_free(cfg->cfg_default.rule_xf[i],
			    sizeof (config_xf_t));
		}

		umem_cfree(cfg->cfg_default.rule_xf, nxf,
		    sizeof (config_xf_t *));
	}

	if (cfg->cfg_rules != NULL) {
		size_t amt = 0;

		for (i = 0; cfg->cfg_rules[i] != NULL; i++, amt++)
			cfg_rule_free(cfg->cfg_rules[i]);

		umem_cfree(cfg->cfg_rules, amt + 1, sizeof (config_rule_t *));
	}

	ustrfree(cfg->cfg_proxy);
	ustrfree(cfg->cfg_socks);
	umem_free(cfg, sizeof (*cfg));
}
