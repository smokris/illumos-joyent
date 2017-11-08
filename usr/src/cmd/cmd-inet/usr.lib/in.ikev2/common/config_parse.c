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
#include <sys/time.h>
#include <sys/debug.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/sysmacros.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <umem.h>
#include <netinet/in.h>
#include <errno.h>
#include <bunyan.h>
#include <ctype.h>
#include <stdio.h>
#include <err.h>
#include "defs.h"
#include "config.h"
#include "ikev2.h"
#include "ikev2_enum.h"

#ifndef ARRAY_SIZE
#define	ARRAY_SIZE(x)	(sizeof (x) / sizeof (x[0]))
#endif

#define	CONFIG_MAX	((size_t)(1024*1024))
#define	CONFIG_CHUNK	((size_t)1024)

typedef enum keyword_e {
	KW_NONE = 0,
	KW_CERT_ROOT,
	KW_CERT_TRUST,
	KW_EXPIRE_TIMER,
	KW_IGNORE_CRLS,
	KW_LDAP_SERVER,
	KW_PKCS11_PATH,
	KW_RETRY_LIMIT,
	KW_RETRY_TIMER_INIT,
	KW_RETRY_TIMER_MAX,
	KW_PROXY,
	KW_SOCKS,
	KW_USE_HTTP,
	KW_P1_LIFETIME_SECS,
	KW_P1_NONCE_LEN,
	KW_P2_LIFETIME_SECS,
	KW_P2_SOFTLIFE_SECS,
	KW_P2_IDLETIME_SECS,
	KW_P2_LIFETIME_KB,
	KW_P2_SOFTLIFE_KB,
	KW_P2_NONCE_LEN,
	KW_LOCAL_ID_TYPE,
	KW_P1_XFORM,
	KW_AUTH_METHOD,
	KW_OAKLEY_GROUP,
	KW_AUTH_ALG,
	KW_ENCR_ALG,
	KW_LABEL,
	KW_LOCAL_ADDR,
	KW_REMOTE_ADDR,
	KW_P2_PFS,
	KW_LOCAL_ID,
	KW_REMOTE_ID,
	KW_IMMEDIATE,
	KW_P1_SOFTLIFE_SECS,
	KW_P1_HARDLIFE_SECS,
	KW_MAX
} keyword_t;

#define	KWF_ARG		(1 << 0)	/* keyword has argument */
#define	KWF_MINUS	(1 << 1)	/* minus is a separator for arg */
#define	KWF_MULTI	(1 << 2)	/* keyword can appear multiple times */

#define	KW_HAS_ARG(k)	(!!(keyword_tab[(k)].kw_flags & KWF_ARG))
#define	KW_IS_MULTI(k)	(!!(keyword_tab[(k)].kw_flags & KWF_MULTI))
#define	KW_USE_MINUS(k)	(!!(keyword_tab[(k)].kw_flags & KWF_MINUS))

static struct {
	const char	*kw_str;
	uint_t		kw_flags;
} keyword_tab[] = {
	{ "",			0 },
	{ "cert_root",		KWF_ARG|KWF_MULTI },
	{ "cert_trust",		KWF_ARG|KWF_MULTI },
	{ "expire_timer",	KWF_ARG },
	{ "ignore_crls",	0 },
	{ "ldap_server",	KWF_ARG|KWF_MULTI },
	{ "pkcs11_path",	KWF_ARG|KWF_MULTI },
	{ "retry_limit",	KWF_ARG },
	{ "retry_timer_init",	KWF_ARG },
	{ "retry_timer_max",	KWF_ARG },
	{ "proxy",		KWF_ARG },
	{ "socks",		KWF_ARG },
	{ "use_http",		0 },
	{ "p1_lifetime_secs",	KWF_ARG },
	{ "p1_nonce_len",	KWF_ARG },
	{ "p2_lifetime_secs",	KWF_ARG },
	{ "p2_softlife_secs",	KWF_ARG },
	{ "p2_idletime_secs",	KWF_ARG },
	{ "p2_lifetime_kb",	KWF_ARG },
	{ "p2_softlife_kb",	KWF_ARG },
	{ "p2_nonce_len",	KWF_ARG },
	{ "local_id_type",	KWF_ARG },
	{ "p1_xform",		KWF_MULTI },
	{ "auth_method",	KWF_ARG },
	{ "oakley_group",	KWF_ARG },
	{ "auth_alg",		KWF_ARG },
	{ "encr_alg",		KWF_ARG },
	{ "label",		KWF_ARG },
	{ "local_addr",		KWF_ARG|KWF_MINUS|KWF_MULTI },
	{ "remote_addr",	KWF_ARG|KWF_MINUS|KWF_MULTI },
	{ "p2_pfs",		KWF_ARG },
	/*
	 * XXX: The manpage implies local_id can appear multiple times, but
	 * only the first one is used.  This may just be poor phrasing.
	 */
	{ "local_id",		KWF_ARG },
	{ "remote_id",		KWF_ARG|KWF_MULTI },
	{ "immediate",		0 },
	{ "p1_softlife_secs",	KWF_ARG },
	{ "p1_hardlife_secs",	KWF_ARG },
};

static struct {
	ikev2_auth_type_t	a_id;
	const char		*a_str;
} auth_tab[] = {
	{ IKEV2_AUTH_NONE, "" },
	{ IKEV2_AUTH_RSA_SIG, "rsa_sig" },
	{ IKEV2_AUTH_SHARED_KEY_MIC, "preshared" },
	{ IKEV2_AUTH_DSS_SIG, "dss_sig" }
};

static struct {
	config_auth_id_t	p1_id;
	const char		*p1_str;
} p1_id_tab[] = {
	{ CFG_AUTH_ID_DN, "dn" },
	{ CFG_AUTH_ID_DN, "DN" },
	{ CFG_AUTH_ID_DNS, "dns" },
	{ CFG_AUTH_ID_DNS, "DNS" },
	{ CFG_AUTH_ID_DNS, "fqdn" },
	{ CFG_AUTH_ID_DNS, "FQDN" },
	{ CFG_AUTH_ID_GN, "gn" },
	{ CFG_AUTH_ID_GN, "GN" },
	{ CFG_AUTH_ID_IPV4, "ip" },
	{ CFG_AUTH_ID_IPV4, "IP" },
	{ CFG_AUTH_ID_IPV4, "ipv4" },
	{ CFG_AUTH_ID_IPV4_PREFIX, "ipv4_prefix" },
	{ CFG_AUTH_ID_IPV4_RANGE, "ipv4_range" },
	{ CFG_AUTH_ID_IPV6, "ipv6" },
	{ CFG_AUTH_ID_IPV6_PREFIX, "ipv6_prefix" },
	{ CFG_AUTH_ID_IPV6_RANGE, "ipv6_range" },
	{ CFG_AUTH_ID_EMAIL, "mbox" },
	{ CFG_AUTH_ID_EMAIL, "MBOX" },
	{ CFG_AUTH_ID_EMAIL, "user_fqdn" }
};

static struct {
	ikev2_xf_auth_t xfa_id;
	const char	*xfa_str;
} xf_auth_tab[] = {
	{ IKEV2_XF_AUTH_HMAC_MD5_128, "md5" },	/* XXX: verify this */
	{ IKEV2_XF_AUTH_HMAC_SHA1_160, "sha" },
	{ IKEV2_XF_AUTH_HMAC_SHA1_160, "sha1" },
	{ IKEV2_XF_AUTH_HMAC_SHA2_256_128, "sha256" },
	{ IKEV2_XF_AUTH_HMAC_SHA2_384_192, "sha384" },
	{ IKEV2_XF_AUTH_HMAC_SHA2_512_256, "sha512" }
};

static struct {
	ikev2_xf_encr_t xfe_id;
	const char	*xfe_str;
} xf_encr_tab[] = {
	{ IKEV2_ENCR_DES, "des" },
	{ IKEV2_ENCR_DES, "des-cbc" },
	{ IKEV2_ENCR_3DES, "3des" },
	{ IKEV2_ENCR_3DES, "3des-cbc" },
	{ IKEV2_ENCR_BLOWFISH, "blowfish" },
	{ IKEV2_ENCR_BLOWFISH, "blowfish-cbc" },
	{ IKEV2_ENCR_AES_CBC, "aes" },
	{ IKEV2_ENCR_AES_CBC, "aes-cbc" },
	{ IKEV2_ENCR_AES_CCM_16, "aes-ccm" },
	{ IKEV2_ENCR_AES_GCM_16, "aes-gcm" }
};

static struct {
	ikev2_dh_t xfd_id;
	const char *xfd_str;
} xf_dh_tab[] = {
	{ IKEV2_DH_MODP_768, "modp768" },
	{ IKEV2_DH_MODP_1024, "modp1024" },
	{ IKEV2_DH_EC2N_155, "ec2n155" },
	{ IKEV2_DH_EC2N_185, "ec2n185" },
	{ IKEV2_DH_MODP_1536, "modp1536" },
	{ IKEV2_DH_MODP_2048, "modp2048" },
	{ IKEV2_DH_MODP_3072, "modp3072" },
	{ IKEV2_DH_MODP_4096, "modp4096" },
	{ IKEV2_DH_MODP_6144, "modp6144" },
	{ IKEV2_DH_MODP_8192, "modp8192" },
	{ IKEV2_DH_ECP_256, "ecp256" },
	{ IKEV2_DH_ECP_384, "ecp384" },
	{ IKEV2_DH_ECP_521, "ecp521" },
	{ IKEV2_DH_MODP_1024_160, "modp1024_160" },
	{ IKEV2_DH_MODP_2048_224, "modp2048_224" },
	{ IKEV2_DH_MODP_2048_256, "modp2048_256" },
	{ IKEV2_DH_ECP_192, "ecp192" },
	{ IKEV2_DH_ECP_224, "ecp224" },
	{ IKEV2_DH_BRAINPOOL_P224R1, "brainpoolp224r1" },
	{ IKEV2_DH_BRAINPOOL_P256R1, "brainpoolp256r1" },
	{ IKEV2_DH_BRAINPOOL_P384R1, "brainpoolp384r1" },
	{ IKEV2_DH_BRAINPOOL_P512R1, "brainpoolp512r1" },
};

/*
 * size_t would be a more appropriate type for t_{line,col}, but using
 * uint32_t makes it cleaner for logging with bunyan
 */
typedef struct token {
	char		*t_str;
	const char	*t_linep;
	uint32_t	t_line;
	uint32_t	t_col;
} token_t;

typedef struct input {
	char	*in_buf;
	size_t	in_buflen;
	char	**in_lines;
} input_t;

typedef struct input_cursor {
	input_t		*ic_input;
	char		*ic_p;
	token_t		*ic_peek;
} input_cursor_t;

static void add_str(char ***restrict, size_t *restrict, const char *restrict);
static void add_addr(config_addr_t **restrict, size_t *restrict,
    const config_addr_t *restrict);
static void add_xf(config_rule_t *restrict, config_xf_t *restrict);
static void add_rule(config_t *restrict, config_rule_t *restrict);
static void add_remid(config_rule_t *restrict, config_id_t *restrict);

static token_t *tok_new(const char *, const char *, const char *, size_t,
    size_t);
static void tok_free(token_t *);
static void tok_log(const token_t *restrict, bunyan_level_t,
    const char *restrict, const char *restrict);
static void tok_error(const token_t *restrict, const char *restrict,
    const char *restrict);
static void tok_invalid(token_t *restrict, keyword_t);

static boolean_t parse_rule(input_cursor_t *restrict, const token_t *restrict,
    config_rule_t **restrict);
static boolean_t parse_address(input_cursor_t *restrict, token_t *restrict,
    config_addr_t *restrict);
static boolean_t parse_p1_id(input_cursor_t *restrict, token_t *restrict,
    config_id_t **restrict);
static boolean_t parse_xform(input_cursor_t *restrict, config_xf_t **restrict);
static boolean_t parse_encrbits(input_cursor_t *restrict,
    config_xf_t *restrict);

static boolean_t parse_kw(const char *restrict, keyword_t *restrict);
static boolean_t parse_auth(const char *restrict, ikev2_auth_type_t *restrict);
static boolean_t parse_authalg(const char *restrict, ikev2_xf_auth_t *restrict);
static boolean_t parse_encralg(const char *restrict, ikev2_xf_encr_t *restrict);
static boolean_t parse_p1_id_type(const char *restrict,
    config_auth_id_t *restrict);
static boolean_t parse_dh(const char *restrict, ikev2_dh_t *restrict);
static boolean_t parse_ip(const char *restrict, in_addr_t *restrict);
static boolean_t parse_ip6(const char *restrict, in6_addr_t *restrict);
static boolean_t parse_int(const char *restrict, uint64_t *restrict);
static boolean_t parse_fp(const char *restrict, double *restrict);

static input_t *input_new(FILE *restrict);
static void input_free(input_t *);

static void input_cursor_init(input_cursor_t *, input_t *);
static void input_cursor_fini(input_cursor_t *);
static token_t *input_token(input_cursor_t *, boolean_t);
static const token_t *input_peek(input_cursor_t *, boolean_t);
static token_t *input_next_token(input_cursor_t *, boolean_t);
static void input_cursor_getpos(input_cursor_t *restrict, const char *restrict,
    const char **restrict, uint32_t *restrict, uint32_t *restrict);

static boolean_t issep(char c, boolean_t);

/*
 * When processing a configuration file, we first load the entire contents
 * into memory before doing any parsing.  This is to hopefully allow more
 * contextual error messages (such as being able to output the full line of
 * text where an error occurs, as well as the location where the error occurs).
 * Once successfully parsed, the contents are discarded.
 *
 * The general approach is to then generate a stream of string tokens.  We
 * defer interpretation of the tokens (e.g. 'IP address') since there are
 * some instances where it'd be complicated to do so due to potential
 * ambiguities.  Instead it's simpler to wait until there's more context.
 *
 * For example, once the 'local_addr' keyword has been seen, we know the next
 * token should be either an IPV4 or IPV6 address, an IPV[46] address prefix
 * (address/masklen), or an IPV[46] range (start address-end address).  We can
 * attempt to convert the string accordingly without ambiguity.
 *
 * To assist in that, there is a (currently) limited ability to peek (view
 * without advancing the stream) at the next token.  This has (so far)
 * proven sufficient.
 *
 * To check the configuration, we build a new copy of config_t, and if it
 * succeeds to completion, we know the configuration does not have any
 * errors, and then discard it (instead of replacing the current configuration).
 *
 * TODO: We should probably support the ability to add and remove individual
 * rules.
 */
void
process_config(FILE *f, boolean_t check_only)
{
	input_t *in = input_new(f);
	token_t *t = NULL, *targ = NULL;
	config_t *cfg = NULL;
	config_xf_t *xf = NULL;
	input_cursor_t ic = { 0 };
	union {
		uint64_t	ui;
		double		d;
	} val;
	size_t rule_count = 0;

	(void) bunyan_trace(log, "process_config() enter", BUNYAN_T_END);

	if (in == NULL) {
		STDERR(error, "failure reading input");
		(void) bunyan_trace(log, "process_config() exit", BUNYAN_T_END);
		return;
	}

	cfg = calloc(1, sizeof (*cfg));
	VERIFY3P(cfg, !=, NULL);

	/* Set defaults */
	cfg->cfg_local_id_type = CFG_AUTH_ID_IPV4;
	cfg->cfg_expire_timer = SEC2NSEC(300);
	cfg->cfg_retry_init = MSEC2NSEC(500);
	cfg->cfg_retry_max = SEC2NSEC(30);
	cfg->cfg_retry_limit = 5;

	input_cursor_init(&ic, in);
	while ((t = input_token(&ic, B_TRUE)) != NULL) {
		keyword_t kw;

		if (strcmp(t->t_str, "{") == 0) {
			config_rule_t *rule = NULL;

			if (!parse_rule(&ic, t, &rule))
				goto fail;

			add_rule(cfg, rule);
			tok_free(t);
			rule_count++;
			continue;
		}

		if (!parse_kw(t->t_str, &kw)) {
			tok_error(t, "Unrecognized configuration parameter",
			    "parameter");
			goto fail;
		}

		VERIFY3S(kw, !=, KW_NONE);
		VERIFY3S(kw, !=, KW_MAX);

		if (KW_HAS_ARG(kw)) {
			targ = input_token(&ic, KW_USE_MINUS(kw));
			if (targ == NULL) {
				tok_error(t, "Parameter is missing argument",
				    "parameter");
				goto fail;
			}
		}

		switch (kw) {
		case KW_NONE:
		case KW_MAX:
			INVALID("t->t_val.t_kw");
			break;
		case KW_CERT_ROOT:
			add_str(&cfg->cfg_cert_root, &cfg->cfg_cert_root_alloc,
			    targ->t_str);
			break;
		case KW_CERT_TRUST:
			add_str(&cfg->cfg_cert_trust,
			    &cfg->cfg_cert_trust_alloc, targ->t_str);
			break;
		case KW_EXPIRE_TIMER:
			if (!parse_int(targ->t_str, &val.ui)) {
				tok_invalid(t, KW_EXPIRE_TIMER);
				goto fail;
			}
			cfg->cfg_expire_timer = val.ui * NANOSEC;
			break;
		case KW_IGNORE_CRLS:
			cfg->cfg_ignore_crls = B_TRUE;
			break;
		case KW_LDAP_SERVER:
		case KW_PKCS11_PATH:
			tok_log(t, BUNYAN_L_INFO,
			    "Ignoring deprecated configuration parameter",
			    "parameter");
			break;
		case KW_RETRY_LIMIT:
			if (!parse_int(targ->t_str, &val.ui)) {
				tok_invalid(t, KW_RETRY_LIMIT);
				goto fail;
			}
			cfg->cfg_retry_limit = val.ui;
			break;
		case KW_PROXY:
			cfg->cfg_proxy = strdup(targ->t_str);
			VERIFY3P(cfg->cfg_proxy, !=, NULL);
			break;
		case KW_SOCKS:
			cfg->cfg_socks = strdup(targ->t_str);
			VERIFY3P(cfg->cfg_socks, !=, NULL);
			break;
		case KW_RETRY_TIMER_INIT:
			if (parse_int(targ->t_str, &val.ui)) {
				cfg->cfg_retry_init = val.ui * NANOSEC;
			} else if (parse_fp(targ->t_str, &val.d)) {
				cfg->cfg_retry_init =
				    (hrtime_t)(val.d * NANOSEC);
			} else {
				tok_invalid(targ, kw);
				goto fail;
			}
			break;
		case KW_RETRY_TIMER_MAX:
			if (parse_int(targ->t_str, &val.ui)) {
				cfg->cfg_retry_max = val.ui * NANOSEC;
			} else if (parse_fp(targ->t_str, &val.d)) {
				cfg->cfg_retry_max =
				    (hrtime_t)(val.d * NANOSEC);
			} else {
				tok_invalid(targ, kw);
				goto fail;
			}
			break;
		case KW_P1_SOFTLIFE_SECS:
			if (!parse_int(targ->t_str, &val.ui)) {
				tok_invalid(targ, kw);
				goto fail;
			}
			cfg->cfg_p1_softlife_secs = val.ui;
			break;
		case KW_P1_HARDLIFE_SECS:
		case KW_P1_LIFETIME_SECS:
			if (!parse_int(targ->t_str, &val.ui)) {
				tok_invalid(targ, kw);
				goto fail;
			}
			cfg->cfg_p1_hardlife_secs = val.ui;
			break;
		case KW_P1_NONCE_LEN:
			if (!parse_int(targ->t_str, &val.ui)) {
				tok_invalid(targ, kw);
				goto fail;
			}
			/* XXX: check size */
			cfg->cfg_p1_nonce_len = val.ui;
			break;
		case KW_P2_LIFETIME_SECS:
			if (!parse_int(targ->t_str, &val.ui)) {
				tok_invalid(targ, kw);
				goto fail;
			}
			/* XXX: check size */
			cfg->cfg_p2_lifetime_secs = val.ui;
			break;
		case KW_P2_SOFTLIFE_SECS:
			if (!parse_int(targ->t_str, &val.ui)) {
				tok_invalid(targ, kw);
				goto fail;
			}
			/* XXX: check size */
			cfg->cfg_p2_softlife_secs = val.ui;
			break;
		case KW_P2_IDLETIME_SECS:
			if (!parse_int(targ->t_str, &val.ui)) {
				tok_invalid(targ, kw);
				goto fail;
			}
			/* XXX: check size */
			cfg->cfg_p2_idletime_secs = val.ui;
			break;
		case KW_P2_LIFETIME_KB:
			if (!parse_int(targ->t_str, &val.ui)) {
				tok_invalid(targ, kw);
				goto fail;
			}
			/* XXX: check size */
			cfg->cfg_p2_lifetime_kb = val.ui;
			break;
		case KW_P2_SOFTLIFE_KB:
			if (!parse_int(targ->t_str, &val.ui)) {
				tok_invalid(targ, kw);
				goto fail;
			}
			/* XXX: check size */
			cfg->cfg_p2_softlife_kb = val.ui;
			break;
		case KW_P2_NONCE_LEN:
			if (!parse_int(targ->t_str, &val.ui)) {
				tok_invalid(targ, kw);
				goto fail;
			}
			/* XXX: check size */
			cfg->cfg_p2_nonce_len = val.ui;
			break;
		case KW_LOCAL_ID_TYPE:
			if (!parse_p1_id_type(targ->t_str,
			    &cfg->cfg_local_id_type)) {
				tok_invalid(targ, kw);
				goto fail;
			}
			break;
		case KW_USE_HTTP:
			cfg->cfg_use_http = B_TRUE;
			break;
		case KW_P2_PFS:
			if (!parse_dh(targ->t_str,
			    &cfg->cfg_default.rule_p2_dh)) {
				tok_error(targ, "Invalid p2_pfs value",
				    "value");
				goto fail;
			}
			break;
		case KW_P1_XFORM:
			if (!parse_xform(&ic, &xf))
				goto fail;
			add_xf(&cfg->cfg_default, xf);
			xf = NULL;
			break;
		case KW_AUTH_METHOD:
		case KW_OAKLEY_GROUP:
		case KW_AUTH_ALG:
		case KW_ENCR_ALG:
			tok_error(t, "Configuration parameter cannot be "
			    "used outside of a transform definition",
			    "parameter");
			goto fail;
		case KW_LABEL:
		case KW_LOCAL_ADDR:
		case KW_REMOTE_ADDR:
		case KW_LOCAL_ID:
		case KW_REMOTE_ID:
		case KW_IMMEDIATE:
			tok_error(t, "Configuration parameter cannot be "
			    "used outside of a rule definition", "parameter");
			goto fail;
		}

		tok_free(t);
		tok_free(targ);
		t = NULL;
		targ = NULL;
	}

	tok_free(t);
	tok_free(targ);
	input_cursor_fini(&ic);
	input_free(in);

	(void) bunyan_info(log, "Finished processing config",
	    BUNYAN_T_UINT32, "numrules", (uint32_t)rule_count,
	    BUNYAN_T_END);

	if (check_only) {
		cfg_free(cfg);
	} else {
		config_t *old = NULL;

		cfg->cfg_refcnt = 1;

		VERIFY0(pthread_rwlock_wrlock(&cfg_lock));
		old = config;
		config = cfg;
		VERIFY0(pthread_rwlock_unlock(&cfg_lock));
		if (old != NULL)
			CONFIG_REFRELE(old);
	}
	(void) bunyan_trace(log, "process_config() exit", BUNYAN_T_END);
	return;

fail:
	tok_free(t);
	tok_free(targ);
	input_cursor_fini(&ic);
	input_free(in);
	cfg_free(cfg);
	cfg = NULL;

	if (!check_only)
		exit(1);
}

static boolean_t
parse_xform(input_cursor_t *restrict ic, config_xf_t **restrict xfp)
{
	config_xf_t *xf = NULL;
	token_t *start_t = NULL, *t = NULL, *targ = NULL;
	uint64_t val = 0;
	const char *start = NULL, *end = NULL;
	size_t kwcount[KW_MAX] = { 0 };
	boolean_t ok = B_TRUE;

	xf = calloc(1, sizeof (*xf));
	VERIFY3P(xf, !=, NULL);

	if ((start_t = input_token(ic, B_FALSE)) == NULL) {
		(void) bunyan_error(log,
		    "Unexpected end of input processing transform",
		    BUNYAN_T_END);
		goto fail;
	}

	if (strcmp(start_t->t_str, "{") != 0) {
		(void) bunyan_error(log, "Expected '{' after p1_xform",
		    BUNYAN_T_STRING, "string", start_t->t_str,
		    BUNYAN_T_END);
		goto fail;
	}

	start = start_t->t_linep + start_t->t_col;

	/*CONSTCOND*/
	while (1) {
		t = input_token(ic, B_FALSE);
		if (t == NULL) {
			(void) bunyan_error(log,
			    "Unexpected end of input processing transform",
			    BUNYAN_T_END);
			goto fail;
		}
		if (strcmp(t->t_str, "}") == 0)
			break;

		keyword_t kw = KW_NONE;
		if (!parse_kw(t->t_str, &kw)) {
			tok_error(t, "Unknown configuration parameter",
			    "parameter");
			goto fail;
		}

		if (kwcount[kw] > 0 && !KW_IS_MULTI(kw)) {
			tok_error(t,
			    "Parameter can only appear once in a transform",
			    "parameter");
			goto fail;
		}

		if (KW_HAS_ARG(kw)) {
			targ = input_token(ic, KW_USE_MINUS(kw));
			if (targ == NULL) {
				tok_error(t,
				    "Parameter is missing an argument",
				    "parameter");
				goto fail;
			}
		}

		switch (kw) {
		case KW_AUTH_METHOD:
			if (!parse_auth(targ->t_str, &xf->xf_authtype)) {
				tok_error(targ,
				    "Unknown authentication method",
				    "authmethod");
				goto fail;
			}
			break;
		case KW_OAKLEY_GROUP:
			if (!parse_dh(targ->t_str, &xf->xf_dh)) {
				tok_error(targ,
				    "Unknown oakley (DH) group",
				    "group");
				goto fail;
			}
			break;
		case KW_AUTH_ALG:
			if (!parse_authalg(targ->t_str, &xf->xf_auth)) {
				tok_error(targ,
				    "Unknown authentication algorithm",
				    "algorithm");
				goto fail;
			}
			break;
		case KW_ENCR_ALG:
			if (!parse_encralg(targ->t_str, &xf->xf_encr)) {
				tok_error(targ,
				    "Unknown encryption algorithm",
				    "algorithm");
				goto fail;
			}
			if (!parse_encrbits(ic, xf))
				goto fail;
			break;
		case KW_P1_LIFETIME_SECS:
			if (!parse_int(targ->t_str, &val)) {
				tok_error(targ, "Invalid value", "value");
				goto fail;
			}
			xf->xf_lifetime_secs = (uint32_t)val;
			break;
		case KW_P1_NONCE_LEN:
			if (!parse_int(targ->t_str, &val)) {
				tok_error(targ, "Invalid value", "value");
				goto fail;
			}
			/* XXX: validate length */
			xf->xf_nonce_len = (uint32_t)val;
			break;
		default:
			(void) bunyan_error(log, "Parameter keyword not "
			    "allowed in transform definition",
			    BUNYAN_T_STRING, "keyword", t->t_str,
			    BUNYAN_T_END);
			goto fail;
		}

		kwcount[kw]++;

		tok_free(t);
		tok_free(targ);
		t = NULL;
		targ = NULL;
	}

	if (kwcount[KW_ENCR_ALG] == 0) {
		tok_error(start_t,
		    "Transform missing encryption algorithm", NULL);
		ok = B_FALSE;
	}
	if (kwcount[KW_AUTH_ALG] == 0) {
		tok_error(start_t,
		    "Transform missing authentication algorithm", NULL);
		ok = B_FALSE;
	}

	end = t->t_linep + t->t_col;

	if (!ok)
		goto fail;

	/*
	 * end points to closing '}' of transform, so end - start + 2
	 * includes closing } plus room for NUL
	 */
	val = (uint64_t)(end - start) + 2;
	xf->xf_str = calloc(1, val);
	VERIFY3P(xf->xf_str, !=, NULL);
	(void) strlcpy(xf->xf_str, start, val);

	tok_free(start_t);
	tok_free(t);
	tok_free(targ);
	*xfp = xf;
	return (B_TRUE);

fail:
	tok_free(start_t);
	tok_free(t);
	tok_free(targ);
	free(xf);
	*xfp = NULL;
	return (B_FALSE);
}

static boolean_t
parse_encrbits(input_cursor_t *restrict ic, config_xf_t *restrict xf)
{
	const token_t *tpeek = NULL;
	token_t *t = NULL;
	uint64_t val = 0;

	if ((tpeek = input_peek(ic, B_FALSE)) == NULL)
		goto truncated;

	/* No key length given, that's ok */
	if (strcmp(tpeek->t_str, "(") != 0)
		return (B_TRUE);

	/* consume '(' */
	tok_free(input_token(ic, B_FALSE));

	if ((t = input_token(ic, B_FALSE)) == NULL)
		goto truncated;

	if (!parse_int(t->t_str, &val))
		goto invalid;
	if (val > SIZE_MAX)
		goto toobig;
	xf->xf_minbits = (size_t)val;
	tok_free(t);

	if ((t = input_token(ic, B_FALSE)) == NULL)
		goto truncated;
	if (strcmp(t->t_str, ")") == 0) {
		xf->xf_maxbits = xf->xf_minbits;
		goto done;
	}

	if (strcmp(t->t_str, "..") != 0)
		goto unexpected;
	tok_free(t);

	if ((t = input_token(ic, B_TRUE)) == NULL)
		goto truncated;
	if (!parse_int(t->t_str, &val))
		goto invalid;
	if (val > SIZE_MAX)
		goto toobig;
	xf->xf_maxbits = val;

	if (xf->xf_maxbits < xf->xf_minbits) {
		(void) bunyan_error(log,
		    "Maximum keysize is smaller than minimum keysize",
		    BUNYAN_T_STRING, "value", t->t_str,
		    BUNYAN_T_UINT32, "line", t->t_line,
		    BUNYAN_T_UINT32, "col", t->t_col,
		    BUNYAN_T_END);
		tok_free(t);
		return (B_FALSE);
	}

	tok_free(t);
	if ((t = input_token(ic, B_TRUE)) == NULL)
		goto truncated;
	if (strcmp(t->t_str, ")") != 0)
		goto unexpected;

done:
	tok_free(t);
	return (B_TRUE);

unexpected:
	(void) bunyan_error(log, "Unexpected value after key length",
	    BUNYAN_T_STRING, "value", t->t_str,
	    BUNYAN_T_UINT32, "line", t->t_line,
	    BUNYAN_T_UINT32, "col", t->t_col,
	    BUNYAN_T_END);
	tok_free(t);
	return (B_FALSE);

invalid:
	(void) bunyan_error(log, "Invalid key bitlength",
	    BUNYAN_T_STRING, "bitlength", t->t_str,
	    BUNYAN_T_UINT32, "line", t->t_line,
	    BUNYAN_T_UINT32, "col", t->t_col,
	    BUNYAN_T_END);
	tok_free(t);
	return (B_FALSE);

toobig:
	(void) bunyan_error(log, "Keysize is too large",
	    BUNYAN_T_UINT64, "keysize", val,
	    BUNYAN_T_UINT32, "line", t->t_line,
	    BUNYAN_T_UINT32, "col", t->t_col,
	    BUNYAN_T_END);
	tok_free(t);
	return (B_FALSE);

truncated:
	tok_free(t);
	bunyan_error(log, "Truncated input while reading transform",
	    BUNYAN_T_END);
	return (B_FALSE);
}

static boolean_t
parse_rule(input_cursor_t *restrict ic, const token_t *start,
    config_rule_t **restrict rulep)
{
	token_t *t = NULL, *targ = NULL;
	token_t *local_id = NULL;
	config_rule_t *rule = NULL;
	config_xf_t *xf = NULL;
	config_id_t *remid = NULL;
	config_addr_t addr = { 0 };
	size_t kwcount[KW_MAX] = { 0 };
	config_auth_id_t local_id_type = CFG_AUTH_ID_IPV4;
	boolean_t ok = B_TRUE;

	*rulep = NULL;

	rule = calloc(1, sizeof (*rule));
	VERIFY3P(rule, !=, NULL);

	while ((t = input_token(ic, B_FALSE)) != NULL) {
		keyword_t kw = KW_NONE;

		if (strcmp(t->t_str, "}") == 0)
			break;

		if (!parse_kw(t->t_str, &kw)) {
			tok_log(t, BUNYAN_L_ERROR,
			    "Unrecognized configuration parameter",
			    "parameter");
			goto fail;
		}

		if (KW_HAS_ARG(kw)) {
			targ = input_token(ic, KW_USE_MINUS(kw));
			if (targ == NULL) {
				(void) bunyan_error(log, "Input truncated "
				    "while reading rule", BUNYAN_T_END);
				goto fail;
			}
		}

		if (kwcount[kw] > 0 && !KW_IS_MULTI(kw)) {
			tok_log(t, BUNYAN_L_ERROR,
			    "Configuration parameter can only appear once in a "
			    "transform definition", "parameter");
			goto fail;
		}

		switch (kw) {
		case KW_LABEL:
			rule->rule_label = strdup(targ->t_str);
			if (rule->rule_label == NULL)
				goto fail;
			break;
		case KW_P2_PFS:
			if (!parse_dh(targ->t_str, &rule->rule_p2_dh)) {
				tok_invalid(targ, KW_P2_PFS);
				goto fail;
			}
			break;
		case KW_P1_XFORM:
			if (!parse_xform(ic, &xf))
				goto fail;

			add_xf(rule, xf);
			xf = NULL;
			break;
		case KW_LOCAL_ADDR:
			(void) memset(&addr, 0, sizeof (addr));
			if (!parse_address(ic, targ, &addr))
				goto fail;
			add_addr(&rule->rule_local_addr,
			    &rule->rule_nlocal_addr, &addr);
			break;
		case KW_REMOTE_ADDR:
			(void) memset(&addr, 0, sizeof (addr));
			if (!parse_address(ic, targ, &addr))
				goto fail;
			add_addr(&rule->rule_remote_addr,
			    &rule->rule_nremote_addr, &addr);
			break;
		case KW_LOCAL_ID:
			/* Set aside we're done */
			VERIFY3P(local_id, ==, NULL);
			local_id = targ;
			targ = NULL;
			break;
		case KW_REMOTE_ID:
			if (!parse_p1_id(ic, targ, &remid))
				goto fail;
			add_remid(rule, remid);
			break;
		case KW_LOCAL_ID_TYPE:
			if (!parse_p1_id_type(targ->t_str, &local_id_type)) {
				tok_log(t, BUNYAN_L_ERROR,
				    "Unable to parse local_id_type", "value");
				goto fail;
			}
			break;
		case KW_IMMEDIATE:
			rule->rule_immediate = B_TRUE;
			break;
		default:
			tok_log(t, BUNYAN_L_ERROR, "Configuration "
			    "parameter is invalid inside a rule definition",
			    "parameter");
			goto fail;
		}

		kwcount[(kw)]++;

		tok_free(t);
		tok_free(targ);
		t = NULL;
		targ = NULL;
	}

	if (t == NULL) {
		(void) bunyan_error(log,
		    "Input truncated while reading rule",
		    BUNYAN_T_END);
		goto fail;
	}

	if (kwcount[KW_LOCAL_ID_TYPE] > 0 && kwcount[KW_LOCAL_ID] == 0) {
		config_id_t *id = NULL;
		switch (local_id_type) {
		case CFG_AUTH_ID_IPV4:
		case CFG_AUTH_ID_IPV6:
			break;
		default:
			tok_error(start,
			    "Local ID type specified, but "
			    "local ID value missing in rule", NULL);
			goto fail;
		}
	} else if (kwcount[KW_LOCAL_ID_TYPE] > 0 && kwcount[KW_LOCAL_ID] > 0) {
		if (!parse_p1_id(ic, local_id, &rule->rule_local_id)) {
			if (errno == EINVAL)
				tok_error(local_id,
				    "Unable to parse local id type", "str");
			goto fail;
		}
		if (local_id_type != rule->rule_local_id->cid_type) {
			tok_error(local_id,
			    "Local ID type in rule does not match given "
			    "local ID", NULL);
			goto fail;
		}
	} else if (kwcount[KW_LOCAL_ID_TYPE] == 0 && kwcount[KW_LOCAL_ID] > 0) {
		if (!parse_p1_id(ic, local_id, &rule->rule_local_id))
			goto fail;
	}

	/* Try to show as many errors as we can */
	if (kwcount[KW_LABEL] == 0) {
		tok_error(start, "Rule is missing a required label",
		    NULL);
		ok = B_FALSE;
	}
	if (kwcount[KW_LOCAL_ADDR] == 0) {
		tok_error(start,
		    "Rule is missing a required local address", NULL);
		ok = B_FALSE;
	}
	if (kwcount[KW_REMOTE_ADDR] == 0) {
		tok_error(start,
		    "Rule is missing a required remote address", NULL);
		ok = B_FALSE;
	}
	if (kwcount[KW_P1_XFORM] > 1) {
		ikev2_auth_type_t authtype = rule->rule_xf[0]->xf_authtype;

		for (size_t i = 1; rule->rule_xf[i] != NULL; i++) {
			if (rule->rule_xf[i]->xf_authtype == authtype)
				continue;
			tok_error(start,
			    "All transforms in rule must use the same "
			    "authentication type", NULL);
			ok = B_FALSE;
			break;
		}

		if (authtype != IKEV2_AUTH_SHARED_KEY_MIC &&
		    kwcount[KW_LOCAL_ID] == 0) {
			tok_error(start,
			    "Non-preshared authentication methods require "
			    "a local-id", NULL);
			ok = B_FALSE;
		}
	}

	if (!ok)
		goto fail;

	tok_free(t);
	tok_free(targ);
	tok_free(local_id);
	*rulep = rule;
	return (B_TRUE);

fail:
	tok_free(t);
	tok_free(targ);
	tok_free(local_id);
	free(rule);
	return (B_FALSE);
}

static boolean_t
parse_address(input_cursor_t *restrict ic, token_t *restrict taddr,
    config_addr_t *restrict addrp)
{
	const token_t *tpeek = NULL;
	token_t *t = NULL;
	boolean_t ip6 = B_FALSE;
	boolean_t ok = B_FALSE;

	t = taddr;

	if (!parse_ip(t->t_str, &addrp->cfa_start4)) {
		if (!parse_ip6(t->t_str, &addrp->cfa_start6)) {
			tok_log(t, BUNYAN_L_ERROR,
			    "Unable to parse address", "address");
			return (B_FALSE);
		}
		ip6 = B_TRUE;
	}

	tpeek = input_peek(ic, B_TRUE);
	if (strcmp(tpeek->t_str, "-") == 0) {
		/* consume - */
		tok_free(input_token(ic, B_TRUE));

		addrp->cfa_type =
		    ip6 ? CFG_ADDR_IPV6_RANGE : CFG_ADDR_IPV4_RANGE;

		t = input_token(ic, B_FALSE);
		if (t == NULL)
			goto truncated;

		ok = ip6 ? parse_ip6(t->t_str, &addrp->cfa_end6) :
		    parse_ip(t->t_str, &addrp->cfa_end4);
		if (!ok) {
			tok_log(t, BUNYAN_L_ERROR,
			    "Unable to parse address range", "address");
		}
		tok_free(t);
		return (ok);
	} else if (strcmp(tpeek->t_str, "/") == 0) {
		uint64_t val = 0;

		addrp->cfa_type =
		    ip6 ? CFG_ADDR_IPV6_PREFIX : CFG_ADDR_IPV4_PREFIX;

		/* consume "/" */
		tok_free(input_token(ic, B_TRUE));

		t = input_token(ic, B_FALSE);
		if (t == NULL)
			goto truncated;

		if (!parse_int(t->t_str, &val)) {
			tok_log(t, BUNYAN_L_ERROR,
			    "Cannot parse mask length", "mask_len");
			return (B_FALSE);
		}
		tok_free(t);
		t = NULL;
		if ((ip6 && val > 128) || (!ip6 && val > 32)) {
			(void) bunyan_error(log, "Mask length too long",
			    BUNYAN_T_UINT64, "mask", val,
			    BUNYAN_T_END);
			return (B_FALSE);
		}
		addrp->cfa_endu.cfa_num = (uint8_t)val;
		return (B_TRUE);
	} else {
		addrp->cfa_type =
		    ip6 ? CFG_ADDR_IPV6 : CFG_ADDR_IPV4;
	}

	return (B_TRUE);

truncated:
	(void) bunyan_error(log, "Input truncated while parsing address",
	    BUNYAN_T_END);
	return (B_FALSE);
}

static boolean_t
parse_dh(const char *restrict str, ikev2_dh_t *dhp)
{
	uint64_t val = 0;
	boolean_t found = B_FALSE;

	for (size_t i = 0; i < ARRAY_SIZE(xf_dh_tab); i++) {
		if (strcmp(xf_dh_tab[i].xfd_str, str) == 0) {
			val = xf_dh_tab[i].xfd_id;
			found = B_TRUE;
			break;
		}
	}

	if (!found && !parse_int(str, &val))
		return (B_FALSE);

	/*
	 * NOTE: a default case is explicitly avoided so that the addition
	 * of newer values in ikev2.h will cause a compilation error if they
	 * are not added here.
	 */
	switch ((ikev2_dh_t)val) {
	case IKEV2_DH_NONE:
	case IKEV2_DH_MODP_768:
	case IKEV2_DH_MODP_1024:
	case IKEV2_DH_EC2N_155:
	case IKEV2_DH_EC2N_185:
	case IKEV2_DH_MODP_1536:
	case IKEV2_DH_MODP_2048:
	case IKEV2_DH_MODP_3072:
	case IKEV2_DH_MODP_4096:
	case IKEV2_DH_MODP_6144:
	case IKEV2_DH_MODP_8192:
	case IKEV2_DH_ECP_256:
	case IKEV2_DH_ECP_384:
	case IKEV2_DH_ECP_521:
	case IKEV2_DH_MODP_1024_160:
	case IKEV2_DH_MODP_2048_224:
	case IKEV2_DH_MODP_2048_256:
	case IKEV2_DH_ECP_192:
	case IKEV2_DH_ECP_224:
	case IKEV2_DH_BRAINPOOL_P224R1:
	case IKEV2_DH_BRAINPOOL_P256R1:
	case IKEV2_DH_BRAINPOOL_P384R1:
	case IKEV2_DH_BRAINPOOL_P512R1:
		*dhp = (ikev2_dh_t)val;
		return (B_TRUE);
	}

	return (B_FALSE);
}

static boolean_t
parse_ip(const char *restrict str, in_addr_t *restrict addrp)
{
	if (inet_pton(AF_INET, str, addrp) != 1)
		return (B_FALSE);
	return (B_TRUE);
}

static boolean_t
parse_ip6(const char *restrict str, in6_addr_t *restrict addrp)
{
	if (inet_pton(AF_INET6, str, addrp) != 1)
		return (B_FALSE);
	return (B_TRUE);
}

static boolean_t
parse_int(const char *restrict str, uint64_t *restrict intp)
{
	errno = 0;
	*intp = strtoull(str, NULL, 0);
	return ((errno == 0) ? B_TRUE : B_FALSE);
}

static boolean_t
parse_fp(const char *restrict str, double *restrict dp)
{
	errno = 0;
	*dp = strtod(str, NULL);
	return ((errno == 0) ? B_TRUE : B_FALSE);
}

static boolean_t
parse_kw(const char *restrict str, keyword_t *restrict kwp)
{
	for (keyword_t kw = KW_NONE; kw < KW_MAX; kw++) {
		if (strcmp(keyword_tab[kw].kw_str, str) == 0) {
			*kwp = kw;
			VERIFY3S(*kwp, <, KW_MAX);
			return (B_TRUE);
		}
	}
	return (B_FALSE);
}

static boolean_t
parse_auth(const char *restrict str, ikev2_auth_type_t *restrict authp)
{
	for (size_t i = 0; i < ARRAY_SIZE(auth_tab); i++) {
		if (strcmp(auth_tab[i].a_str, str) == 0) {
			*authp = auth_tab[i].a_id;
			return (B_TRUE);
		}
	}
	return (B_FALSE);
}

static boolean_t
parse_authalg(const char *restrict str, ikev2_xf_auth_t *authp)
{
	for (size_t i = 0; i < ARRAY_SIZE(xf_auth_tab); i++) {
		if (strcmp(xf_auth_tab[i].xfa_str, str) == 0) {
			*authp = xf_auth_tab[i].xfa_id;
			return (B_TRUE);
		}
	}
	return (B_FALSE);
}

static boolean_t
parse_encralg(const char *restrict str, ikev2_xf_encr_t *restrict encp)
{
	for (size_t i = 0; i < ARRAY_SIZE(xf_encr_tab); i++) {
		if (strcmp(xf_encr_tab[i].xfe_str, str) == 0) {
			*encp = xf_encr_tab[i].xfe_id;
			return (B_TRUE);
		}
	}
	return (B_FALSE);
}

static boolean_t
parse_p1_id_type(const char *restrict str, config_auth_id_t *restrict p1p)
{
	for (size_t i = 0; i < ARRAY_SIZE(p1_id_tab); i++) {
		if (strcmp(p1_id_tab[i].p1_str, str) == 0) {
			*p1p = p1_id_tab[i].p1_id;
			return (B_TRUE);
		}
	}
	return (B_FALSE);
}

static boolean_t
parse_p1_id(input_cursor_t *restrict ic, token_t *restrict t,
    config_id_t **restrict idp)
{
	config_id_t *id = NULL;
	void *ptr = NULL;
	struct sockaddr_storage ss = { 0 };
	sockaddr_u_t addr = { .sau_ss = &ss };
	size_t len = 0;
	config_auth_id_t idtype = CFG_AUTH_ID_DNS;

	*idp = NULL;

	/*
	* Sadly, while the existing ike.config requires one specify a type
	* for the local id, it tries to guess the type of the remote ID
	* string, however it is not documented on how that is done.  This
	* is a best guess at matching that.  We assume if the string
	* successfully parses as either an IPV4 or IPV6 address that it
	* should should be of the respective type, an email address must
	* contain a '@', something with '.' that didn't parse as an
	* IPV4 address is a DNS name, something with ':' that didn't parse
	* as an IPV6 address is a GN (based on draft-ietf-pkix-generalname-00),
	* while something with '=' that didn't parse as a GN is a DN.
	*
	* We currently don't parse the _{PREFIX,RANGE} variants of IPV4 and
	* IPV6.  Those seem to be ID types specific to IKEv1, and are not
	* present in IKEv2.  When we add IKEv1 support, we likely will
	* get rid of them altogether and require our peer to never offer
	* such an ID.  Every IKEv1 implementation encountered so far appears to
	* allow one to choose the type of ID presented during authentication,
	* so it seems unlikely it would cause any interoperability concerns.
	*/
	if (inet_pton(AF_INET, t->t_str, addr.sau_sin) == 1) {
		idtype = CFG_AUTH_ID_IPV4;
		len = sizeof (in_addr_t);
		ptr = &addr.sau_sin->sin_addr;
	} else if (inet_pton(AF_INET6, t->t_str, addr.sau_sin6) == 1) {
		idtype = CFG_AUTH_ID_IPV6;
		len = sizeof (in6_addr_t);
		ptr = &addr.sau_sin6->sin6_addr;
	} else if (strchr(t->t_str, '@') != NULL) {
		idtype = CFG_AUTH_ID_EMAIL;
		len = strlen(t->t_str) + 1;
		ptr = t->t_str;
	} else if (strchr(t->t_str, '.') != NULL) {
		idtype = CFG_AUTH_ID_DNS;
		len = strlen(t->t_str) + 1;
		ptr = t->t_str;
	} else if (strchr(t->t_str, ':') != NULL) {
		idtype = CFG_AUTH_ID_GN;
		/* TODO */
		INVALID("implement me!");
	} else if (strchr(t->t_str, '=') != NULL) {
		idtype = CFG_AUTH_ID_DN;
		/* TODO */
		INVALID("implement me!");
	} else {
		tok_error(t, "Unable to determine ID type", "id");
		return (B_FALSE);
	}

	if ((id = config_id_new(idtype, ptr, len)) == NULL)
		return (B_FALSE);

	*idp = id;
	return (B_TRUE);
}

static token_t *
tok_new(const char *startp, const char *endp, const char *linep, size_t line,
    size_t col)
{
	VERIFY3P(endp, >=, startp);

	token_t *t = NULL;
	size_t len = (size_t)(endp - startp) + 1;

	t = calloc(1, sizeof (*t));
	VERIFY3P(t, !=, NULL);

	t->t_str = calloc(1, len);
	VERIFY3P(t, !=, NULL);

	(void) strlcpy(t->t_str, startp, len);
	t->t_linep = linep;
	t->t_line = line;
	t->t_col = col;
	return (t);
}

static void
tok_free(token_t *t)
{
	if (t == NULL)
		return;
	free(t->t_str);
	free(t);
}

#define	STR(x) case x: return (#x)
static const char *
cfg_auth_id_str(config_auth_id_t id)
{
	switch (id) {
	STR(CFG_AUTH_ID_DN);
	STR(CFG_AUTH_ID_DNS);
	STR(CFG_AUTH_ID_GN);
	STR(CFG_AUTH_ID_IPV4);
	STR(CFG_AUTH_ID_IPV4_PREFIX);
	STR(CFG_AUTH_ID_IPV4_RANGE);
	STR(CFG_AUTH_ID_IPV6);
	STR(CFG_AUTH_ID_IPV6_PREFIX);
	STR(CFG_AUTH_ID_IPV6_RANGE);
	STR(CFG_AUTH_ID_EMAIL);
	}
	return ("UNKNOWN");
}
#undef	STR

static void
tok_log(const token_t *restrict t, bunyan_level_t level, const char *msg,
    const char *strname)
{
	char *linecpy = NULL;
	const char *endp = strchr(t->t_linep, '\n');
	size_t len = 0;

	if (endp != NULL)
		len = endp - t->t_linep + 1;
	else
		len = strlen(t->t_linep) + 1;

	linecpy = malloc(len);
	VERIFY3P(linecpy, !=, NULL);
	(void) strlcpy(linecpy, t->t_linep, len);

	getlog(level)(log, msg,
	    BUNYAN_T_STRING, "line", linecpy,
	    BUNYAN_T_UINT32, "lineno", t->t_line + 1,
	    BUNYAN_T_UINT32, "col", t->t_col + 1,
	    (strname != NULL) ? BUNYAN_T_STRING : BUNYAN_T_END,
	    strname, t->t_str, BUNYAN_T_END);

	free(linecpy);
}

static void
tok_error(const token_t *restrict t, const char *restrict msg,
    const char *restrict tname)
{
	tok_log(t, BUNYAN_L_ERROR, msg, tname);
}

static void
tok_invalid(token_t *restrict t, keyword_t kw)
{
	char buf[128] = { 0 };
	(void) snprintf(buf, sizeof (buf), "Invalid %s parameter",
	    keyword_tab[kw]);
	tok_error(t, buf, "parameter");
}

static input_t *
input_new(FILE *restrict f)
{
	input_t *in = NULL;
	char *p = NULL;
	ssize_t n = 0;
	size_t cnt = 0;
	size_t nlines = 0;
	struct stat sb = { 0 };
	int fd = -1;

	in = calloc(1, sizeof (*in));
	VERIFY3P(in, !=, NULL);

	fd = fileno(f);
	if (fstat(fd, &sb) == -1) {
		STDERR(error, "stat failed");
		goto fail;
	}

	/*
	 * Try to read in one go, however the input could be a pipe instead
	 * of a file, in which case we have to keep growing the buffer
	 * (up to the limit)
	 */
	if (S_ISREG(sb.st_mode)) {
		in->in_buflen = sb.st_size + 2;
	} else {
		in->in_buflen = CONFIG_CHUNK;
	}
	in->in_buf = calloc(1, in->in_buflen);
	VERIFY3P(in->in_buf, !=, NULL);

	do {
		n = fread(in->in_buf + cnt, 1, in->in_buflen - cnt - 1, f);
		if (n < 0) {
			STDERR(error, "read failed");
			goto fail;
		}
		cnt += n;

		if (cnt + 1 >= in->in_buflen) {
			if (in->in_buflen >= CONFIG_MAX) {
				(void) bunyan_error(log,
				    "Input size exceeds limits",
				    BUNYAN_T_UINT32, "size",
				    (uint32_t)in->in_buflen,
				    BUNYAN_T_UINT32, "limit",
				    (uint32_t)CONFIG_MAX,
				    BUNYAN_T_END);
				goto fail;
			}

			size_t newlen = P2ROUNDUP(in->in_buflen + CONFIG_CHUNK,
			    CONFIG_CHUNK);

			char *newp = realloc(in->in_buf, newlen);
			VERIFY3P(newp, !=, NULL);

			in->in_buf = newp;
			in->in_buflen = newlen;
		}
	} while (n > 0);
	in->in_buf[cnt] = '\0';

	for (p = in->in_buf, nlines = 0; p != NULL; p = strchr(p + 1, '\n'))
		nlines++;

	in->in_lines = calloc(nlines + 1, sizeof (char *));
	VERIFY3P(in->in_lines, !=, NULL);

	for (p = in->in_buf, nlines = 0; p != NULL; p = strchr(p + 1, '\n'))
		in->in_lines[nlines++] = p;

	return (in);

fail:
	input_free(in);
	return (NULL);
}

static token_t *
input_token(input_cursor_t *ic, boolean_t minus_is_sep)
{
	token_t *t = NULL;
	if (ic->ic_peek != NULL) {
		t = ic->ic_peek;
		ic->ic_peek = NULL;
	} else {
		t = input_next_token(ic, minus_is_sep);
	}

	return (t);
}

/* NOTE: Results of input_peek() should NOT be freed */
static const token_t *
input_peek(input_cursor_t *ic, boolean_t minus_is_sep)
{
	if (ic->ic_peek != NULL)
		return (ic->ic_peek);

	ic->ic_peek = input_next_token(ic, minus_is_sep);
	return (ic->ic_peek);
}

/*
 * Actually get the next token from the input.  This is used both by
 * input_token() and input_peek() and shouldn't be called by anything else.
 */
static token_t *
input_next_token(input_cursor_t *ic, boolean_t minus_is_sep)
{
	char *start = NULL, *end = NULL;
	const char *linep = NULL;
	uint32_t line = 0, col = 0;

	VERIFY3P(ic->ic_p, >=, ic->ic_input->in_buf);
	VERIFY3P(ic->ic_p, <, ic->ic_input->in_buf + ic->ic_input->in_buflen);

again:
	while (*ic->ic_p != '\0' && isspace(*ic->ic_p))
		ic->ic_p++;

	if (*ic->ic_p == '#') {
		/* skip to next line */
		while (*ic->ic_p != '\0' && *ic->ic_p != '\n')
			ic->ic_p++;
		goto again;
	}

	if (*ic->ic_p == '\0')
		return (NULL);

	start = ic->ic_p;
	end = start + 1;

	/* If the first character is a separator, we're done */
	if (issep(*start, minus_is_sep)) {
		ic->ic_p = end;
		goto done;
	}

	if (*start == '"') {
		while (*end != '\0' && *end != '\n' && *end != '"')
			end++;

		if (*end != '"') {
			input_cursor_getpos(ic, start, &linep, &line, &col);
			(void) bunyan_error(log, "Unterminated quoted string",
			    BUNYAN_T_UINT32, "line", line,
			    BUNYAN_T_UINT32, "col", col,
			    BUNYAN_T_END);
			return (NULL);
		}

		start++;
		ic->ic_p = end + 1;
		goto done;
	}

	while (*end != '\0' && !isspace(*end)) {
		if (issep(*end, minus_is_sep) || isspace(*end))
			break;
		end++;
	}
	ic->ic_p = end;

done:
	input_cursor_getpos(ic, start, &linep, &line, &col);
	return (tok_new(start, end, linep, line, col));
}

static void
input_cursor_getpos(input_cursor_t *restrict ic, const char *restrict p,
    const char **restrict linepp, uint32_t *restrict linep,
    uint32_t *restrict colp)
{
	VERIFY3P(ic->ic_input->in_buf, <=, p);
	VERIFY3P(ic->ic_input->in_buf + ic->ic_input->in_buflen, >, p);

	char **lineidx = ic->ic_input->in_lines;
	uint32_t line;
	for (line = 1; lineidx[line] != NULL && lineidx[line] <= p; line++)
		;

	line--;
	*linep = line;
	*colp = (uint32_t)(p - lineidx[line]);
	*linepp = lineidx[line];
}

static void
input_cursor_init(input_cursor_t *restrict ic, input_t *restrict in)
{
	(void) memset(ic, 0, sizeof (*ic));
	ic->ic_input = in;
	ic->ic_p = in->in_buf;
}

static void
input_cursor_fini(input_cursor_t *ic)
{
	free(ic->ic_peek);
	(void) memset(ic, 0, sizeof (*ic));
}

static void
input_free(input_t *in)
{
	if (in == NULL)
		return;

	free(in->in_buf);
	free(in->in_lines);
	free(in);
}

#define	CHUNK_SZ	(8)
/*
 * Append a string onto an array of strings.  Since these shouldn't be heavily
 * called, we're not (currently at least) worried about the possibility
 * of excessive realloc() calls.
 */
static void
add_str(char ***restrict ppp, size_t *restrict allocp, const char *restrict str)
{
	char *newstr = NULL;
	char **array = *ppp;
	size_t nelems = 0;

	while (nelems < *allocp && array[nelems] != NULL)
		nelems++;

	if (nelems + 2 > *allocp) {
		char **newarray = NULL;
		size_t newsize = *allocp + CHUNK_SZ;
		size_t amt = newsize * sizeof (char *);

		VERIFY3U(amt, >, newsize);
		VERIFY3U(amt, >=, sizeof (char *));

		/* realloc_array() would be nice */
		newarray = realloc(array, amt);
		VERIFY3P(newarray, !=, NULL);

		*ppp = array = newarray;
		*allocp = newsize;
	}

	newstr = strdup(str);
	VERIFY3P(newstr, !=, NULL);

	array[nelems++] = newstr;
	array[nelems] = NULL;
}

static void
add_xf(config_rule_t *restrict rule, config_xf_t *restrict xf)
{
	size_t nxf = 0;

	while (nxf < rule->rule_nxf && rule->rule_xf[nxf] != NULL)
		nxf++;

	if (nxf + 2 > rule->rule_nxf) {
		config_xf_t **newxf = NULL;
		size_t newalloc = rule->rule_nxf + CHUNK_SZ;
		size_t amt = newalloc * sizeof (config_xf_t *);

		VERIFY3U(amt, >, newalloc);
		VERIFY3U(amt, >=, sizeof (config_xf_t *));

		newxf = realloc(rule->rule_xf, amt);
		VERIFY3P(newxf, !=, NULL);

		rule->rule_nxf = newalloc;
		rule->rule_xf = newxf;
	}

	rule->rule_xf[nxf++] = xf;
	rule->rule_xf[nxf] = NULL;
}

static void
add_rule(config_t *restrict cfg, config_rule_t *restrict rule)
{
	/* TODO: validate label value is unique */
	size_t nrules = 0;

	while (nrules < cfg->cfg_rules_alloc && cfg->cfg_rules[nrules] != NULL)
		nrules++;

	if (nrules + 2 > cfg->cfg_rules_alloc) {
		config_rule_t **newrules = NULL;
		size_t newalloc = cfg->cfg_rules_alloc + CHUNK_SZ;
		size_t amt = newalloc * sizeof (config_rule_t *);

		VERIFY3U(amt, >, newalloc);
		VERIFY3U(amt, >=, sizeof (config_rule_t *));

		newrules = realloc(cfg->cfg_rules, amt);
		VERIFY3P(newrules, !=, NULL);

		cfg->cfg_rules = newrules;
		cfg->cfg_rules_alloc = newalloc;
	}

	rule->rule_config = cfg;
	cfg->cfg_rules[nrules++] = rule;
	cfg->cfg_rules[nrules] = NULL;
}

static void
add_addr(config_addr_t **restrict addrs, size_t *restrict naddrs,
    const config_addr_t *restrict src)
{
	config_addr_t *newaddrs = NULL;
	size_t newlen = *naddrs + 1;
	size_t newamt = newlen * sizeof (config_addr_t);

	VERIFY3U(newamt, >=, sizeof (config_addr_t));
	VERIFY3U(newamt, >, newlen);

	newaddrs = realloc(*addrs, newamt);
	VERIFY3P(newaddrs, !=, NULL);

	(void) memcpy(&newaddrs[*naddrs], src, sizeof (*src));

	*addrs = newaddrs;
	*naddrs += 1;
}

static void
add_remid(config_rule_t *restrict rule, config_id_t *restrict id)
{
	config_id_t **ids = NULL;
	size_t amt = 0;

	for (size_t i = 0;
	    rule->rule_remote_id != NULL && rule->rule_remote_id[i] != NULL;
	    i++) {
		amt++;
	}

	ids = recallocarray(rule->rule_remote_id, amt, amt + 1,
	    sizeof (config_id_t *));
	VERIFY3P(ids, !=, NULL);

	ids[amt] = id;
	rule->rule_remote_id = ids;
}

/* Is the given character a token separator? */
static boolean_t
issep(char c, boolean_t minus_is_sep)
{
	switch (c) {
	case '{': case '}':
	case '(': case ')':
	case '/':
		return (B_TRUE);
	case '-':
		if (minus_is_sep)
			return (B_TRUE);
		break;
	}
	return (B_FALSE);
}
