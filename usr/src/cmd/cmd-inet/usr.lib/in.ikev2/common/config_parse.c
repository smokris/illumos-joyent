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

#define	CONFIG_MAX	((size_t)1024*1024)
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
	KW_MAX
} keyword_t;

static struct {
	const char	*kw_str;
	boolean_t	kw_has_arg;
	boolean_t	kw_minus;
} keyword_tab[] = {
	{ "", B_FALSE },
	{ "cert_root", B_TRUE, B_FALSE },
	{ "cert_trust", B_TRUE, B_FALSE },
	{ "expire_timer", B_TRUE, B_FALSE },
	{ "ignore_crls", B_FALSE },
	{ "ldap_server", B_TRUE, B_FALSE },
	{ "pkcs11_path", B_TRUE, B_FALSE },
	{ "retry_limit", B_TRUE, B_FALSE },
	{ "retry_timer_init", B_TRUE, B_FALSE },
	{ "retry_timer_max", B_TRUE, B_FALSE },
	{ "proxy", B_TRUE, B_FALSE },
	{ "socks", B_TRUE, B_FALSE },
	{ "use_http", B_FALSE },
	{ "p1_lifetime_secs", B_TRUE, B_FALSE },
	{ "p1_nonce_len", B_TRUE, B_FALSE },
	{ "p2_lifetime_secs", B_TRUE, B_FALSE },
	{ "p2_softlife_secs", B_TRUE, B_FALSE },
	{ "p2_idletime_secs", B_TRUE, B_FALSE },
	{ "p2_lifetime_kb", B_TRUE, B_FALSE },
	{ "p2_softlife_kb", B_TRUE, B_FALSE },
	{ "p2_nonce_len", B_TRUE, B_FALSE },
	{ "local_id_type", B_TRUE, B_FALSE },
	{ "p1_xform", B_FALSE },
	{ "auth_method", B_TRUE, B_FALSE },
	{ "oakley_group", B_TRUE, B_FALSE },
	{ "auth_alg", B_TRUE, B_FALSE },
	{ "encr_alg", B_TRUE, B_FALSE },
	{ "label", B_TRUE, B_FALSE },
	{ "local_addr", B_TRUE, B_TRUE },
	{ "remote_addr", B_TRUE, B_TRUE },
	{ "p2_pfs", B_TRUE, B_FALSE },
	{ "local_id", B_TRUE, B_FALSE },
	{ "remote_id", B_TRUE, B_FALSE },
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
	char 	*in_buf;
	size_t	in_buflen;
	char	**in_lines;
} input_t;

typedef struct input_cursor {
	input_t 	*ic_input;
	char		*ic_p;
	token_t		*ic_peek;
	bunyan_logger_t	*ic_log;
} input_cursor_t;

static void add_str(char ***restrict, size_t *restrict, const char *restrict);
static void add_xf(void *restrict, config_xf_t *restrict, boolean_t);
static void add_rule(config_t *restrict, config_rule_t *restrict);

static token_t *tok_new(const char *, const char *, const char *, size_t,
    size_t);
static void tok_free(token_t *);
static void tok_log(token_t *restrict, bunyan_logger_t *restrict,
     bunyan_level_t, const char *restrict, const char *restrict);
static void tok_error(token_t *restrict, bunyan_logger_t *restrict,
    const char *restrict, const char *restrict);
static void tok_invalid(token_t *restrict, bunyan_logger_t *restrict,
    keyword_t);

static boolean_t parse_rule(input_cursor_t *restrict, const token_t *restrict,
    config_rule_t **restrict);
static boolean_t parse_address(input_cursor_t *restrict,
    config_addr_t *restrict);

static boolean_t parse_xform(input_cursor_t *restrict, config_xf_t **restrict);
static boolean_t parse_encrbits(input_cursor_t *restrict,
    config_xf_t *restrict);

static boolean_t parse_kw(const char *restrict, keyword_t *restrict);
static boolean_t parse_auth(const char *restrict, ikev2_auth_type_t *restrict);
static boolean_t parse_authalg(const char *restrict, ikev2_xf_auth_t *restrict);
static boolean_t parse_encralg(const char *restrict, ikev2_xf_encr_t *restrict);
static boolean_t parse_p1_id(const char *restrict, config_auth_id_t *restrict);
static boolean_t parse_p2_pfs(const char *restrict, ikev2_dh_t *restrict);
static boolean_t parse_ip(const char *restrict, in_addr_t *restrict);
static boolean_t parse_ip6(const char *restrict, in6_addr_t *restrict);
static boolean_t parse_int(const char *restrict, uint64_t *restrict);
static boolean_t parse_fp(const char *restrict, double *restrict);

static input_t *input_new(FILE *restrict, bunyan_logger_t *restrict);
static void input_free(input_t *);

static void input_cursor_init(input_cursor_t *, input_t *, bunyan_logger_t *);
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
process_config(FILE *f, boolean_t check_only, bunyan_logger_t *blog)
{
	input_t *in = input_new(f, blog);
	token_t *t = NULL, *targ = NULL;
	config_t *cfg = NULL; 
	config_xf_t *xf = NULL;
	input_cursor_t ic = { 0 };
	union {
		uint64_t	ui;
		double		d;
	} val;

	if (in == NULL) {
		STDERR(error, blog, "failure reading input");
		return;
	}

	cfg = calloc(1, sizeof (*cfg));
	VERIFY3P(cfg, !=, NULL);

	input_cursor_init(&ic, in, blog);
	while ((t = input_token(&ic, B_TRUE)) != NULL) {
		keyword_t kw;

		if (strcmp(t->t_str, "{") == 0) {
			config_rule_t *rule = NULL;

			if (!parse_rule(&ic, t, &rule))
				goto fail;

			add_rule(cfg, rule);
			tok_free(t);
			continue;
		}

		if (!parse_kw(t->t_str, &kw)) {
			tok_error(t, blog,
			    "Unrecognized configuration parameter",
			    "parameter");
			goto fail;
		}

		VERIFY3S(kw, !=, KW_NONE);
		VERIFY3S(kw, !=, KW_MAX);

		if (keyword_tab[kw].kw_has_arg) {
			targ = input_token(&ic, keyword_tab[kw].kw_minus);
			if (targ == NULL) {
				tok_error(t, blog,
				    "Parameter is missing argument",
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
				tok_invalid(t, blog, KW_EXPIRE_TIMER);
				goto fail;
			}
			cfg->cfg_expire_timer = val.ui * NANOSEC;
			break;
		case KW_IGNORE_CRLS:
			cfg->cfg_ignore_crls = B_TRUE;
			break;
		case KW_LDAP_SERVER:
		case KW_PKCS11_PATH:
			tok_log(t, blog, BUNYAN_L_INFO,
			    "Ignoring deprecated configuration parameter",
			    "parameter");
			break;
		case KW_RETRY_LIMIT:
			if (!parse_int(targ->t_str, &val.ui)) {
				tok_invalid(t, blog, KW_RETRY_LIMIT);
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
				tok_invalid(targ, blog, kw);
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
				tok_invalid(targ, blog, kw);
				goto fail;
			}
			break;
		case KW_P1_LIFETIME_SECS:
			if (!parse_int(targ->t_str, &val.ui)) {
				tok_invalid(targ, blog, kw);
				goto fail;
			}
			cfg->cfg_p1_lifetime_secs = val.ui;
			break;
		case KW_P1_NONCE_LEN:
			if (!parse_int(targ->t_str, &val.ui)) {
				tok_invalid(targ, blog, kw);
				goto fail;
			}
			/* XXX: check size */
			cfg->cfg_p1_nonce_len = val.ui;
			break;
		case KW_P2_LIFETIME_SECS:
			if (!parse_int(targ->t_str, &val.ui)) {
				tok_invalid(targ, blog, kw);
				goto fail;
			}
			/* XXX: check size */
			cfg->cfg_p2_lifetime_secs = val.ui;
			break;
		case KW_P2_SOFTLIFE_SECS:
			if (!parse_int(targ->t_str, &val.ui)) {
				tok_invalid(targ, blog, kw);
				goto fail;
			}
			/* XXX: check size */
			cfg->cfg_p2_softlife_secs = val.ui;
			break;
		case KW_P2_IDLETIME_SECS:
			if (!parse_int(targ->t_str, &val.ui)) {
				tok_invalid(targ, blog, kw);
				goto fail;
			}
			/* XXX: check size */
			cfg->cfg_p2_idletime_secs = val.ui;
			break;
		case KW_P2_LIFETIME_KB:
			if (!parse_int(targ->t_str, &val.ui)) {
				tok_invalid(targ, blog, kw);
				goto fail;
			}
			/* XXX: check size */
			cfg->cfg_p2_lifetime_kb = val.ui;
			break;
		case KW_P2_SOFTLIFE_KB:
			if (!parse_int(targ->t_str, &val.ui)) {
				tok_invalid(targ, blog, kw);
				goto fail;
			}
			/* XXX: check size */
			cfg->cfg_p2_softlife_kb = val.ui;
			break;
		case KW_P2_NONCE_LEN:
			if (!parse_int(targ->t_str, &val.ui)) {
				tok_invalid(targ, blog, kw);
				goto fail;
			}
			/* XXX: check size */
			cfg->cfg_p2_nonce_len = val.ui;
			break;
		case KW_LOCAL_ID_TYPE:
			tok_log(t, blog, BUNYAN_L_INFO, "Unimplemented "
			    "configuration parameter", "keyword");
			break;
		case KW_USE_HTTP:
			cfg->cfg_use_http = B_TRUE;
			break;
		case KW_P2_PFS:
			if (!parse_p2_pfs(targ->t_str, &cfg->cfg_p2_pfs)) {
				tok_error(targ, blog, "Invalid p2_pfs value",
				    "value");
				goto fail;
			}
			break;
		case KW_P1_XFORM:
			if (!parse_xform(&ic, &xf))
				goto fail;
			add_xf(cfg, xf, B_FALSE);
			xf = NULL;
			break;
		case KW_AUTH_METHOD:
		case KW_OAKLEY_GROUP:
		case KW_AUTH_ALG:
		case KW_ENCR_ALG:
			tok_error(t, blog, "Configuration parameter cannot be "
			    "used outside of a transform definition",
			    "parameter");
			goto fail;
		case KW_LABEL:
		case KW_LOCAL_ADDR:
		case KW_REMOTE_ADDR:
		case KW_LOCAL_ID:
		case KW_REMOTE_ID:
			tok_error(t, blog, "Configuration parameter cannot be "
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

	if (check_only) {
		cfg_free(cfg);
	} else {
		config_t *old = NULL;

		cfg->cfg_refcnt = 1;

		PTH(pthread_rwlock_wrlock(&cfg_lock));
		old = config;
		config = cfg;
		PTH(pthread_rwlock_unlock(&cfg_lock));
		CONFIG_REFRELE(old);
	}
	return;

fail:
	tok_free(t);
	tok_free(targ);
	input_cursor_fini(&ic);
	input_free(in);
	cfg_free(cfg);
}

static boolean_t
parse_xform(input_cursor_t *restrict ic, config_xf_t **restrict xfp)
{
	config_xf_t *xf = NULL;
	token_t *t = NULL, *targ = NULL;
	boolean_t seen_authalg = B_FALSE;
	boolean_t seen_encralg = B_FALSE;
	boolean_t seen_dh = B_FALSE;
	boolean_t seen_authmethod = B_FALSE;
	boolean_t seen_lifetime_secs = B_FALSE;
	boolean_t seen_nonce_len = B_FALSE;
	uint64_t val = 0;

	xf = calloc(1, sizeof (*xf));
	VERIFY3P(xf, !=, NULL);

	if ((t = input_token(ic, B_FALSE)) == NULL) {
		bunyan_error(ic->ic_log, "Unexpected end of input processing "
		    "transform", BUNYAN_T_END);
		goto fail;
	}

	if (strcmp(t->t_str, "{") != 0) {
		bunyan_error(ic->ic_log, "Expected '{' after p1_xform",
		    BUNYAN_T_STRING, "string", t->t_str,
		    BUNYAN_T_END);
		goto fail;
	}

	/*CONSTCOND*/
	while (1) {
		if ((t = input_token(ic, B_FALSE)) == NULL) {
			bunyan_error(ic->ic_log,
			    "Unexpected end of input processing transform",
			    BUNYAN_T_END);
			goto fail;
		}
		if (strcmp(t->t_str, "}") == 0)
			break;

		/* All of the keywords require an argument */
		if ((targ = input_token(ic, B_FALSE)) == NULL) {
			tok_error(t, ic->ic_log,
			    "Missing argument to parameter", "parameter");
			goto fail;
		}

		keyword_t kw = KW_NONE;

		if (!parse_kw(t->t_str, &kw)) {
			tok_error(t, ic->ic_log,
			    "Unknown configuration parameter", "parameter");
			goto fail;
		}

		switch (kw) {
		case KW_AUTH_METHOD:
			if (seen_authmethod)
				goto duplicate;
			if (!parse_auth(targ->t_str, &xf->xf_authtype)) {
				tok_error(targ, ic->ic_log,
				    "Unknown authentication method",
				    "authmethod");
				goto fail;
			}
			seen_authmethod = B_TRUE;
			break;
		case KW_OAKLEY_GROUP:
			if (seen_dh)
				goto duplicate;
			if (!parse_int(targ->t_str, &val)) {
				tok_error(targ, ic->ic_log,
				    "Unknown oakley (DH) group",
				    "group");
				goto fail;
			}
			/* XXX: Should have a way to validate the value */
			seen_dh = B_TRUE;
			xf->xf_dh = (ikev2_dh_t)val;
			break;
		case KW_AUTH_ALG:
			if (seen_authalg)
				goto duplicate;
			if (!parse_authalg(targ->t_str, &xf->xf_auth)) {
				tok_error(targ, ic->ic_log,
				    "Unknown authentication algorithm",
				    "algorithm");
				goto fail;
			}
			seen_authalg = B_TRUE;
			break;
		case KW_ENCR_ALG:
			if (seen_encralg)
				goto duplicate;
			if (!parse_encralg(targ->t_str, &xf->xf_encr)) {
				tok_error(targ, ic->ic_log,
				    "Unknown encryption algorithm",
				    "algorithm");
				goto fail;
			}
			seen_encralg = B_TRUE;
			if (!parse_encrbits(ic, xf))
				goto fail;
			break;
		case KW_P1_LIFETIME_SECS:
			if (seen_lifetime_secs)
				goto duplicate;
			if (!parse_int(targ->t_str, &val)) {
				tok_error(targ, ic->ic_log, "Invalid value",
				    "value");
				goto fail;
			}
			xf->xf_lifetime_secs = (uint32_t)val;
			seen_lifetime_secs = B_TRUE;
			break;
		case KW_P1_NONCE_LEN: /*xf_nonce_len*/
			if (seen_nonce_len)
				goto duplicate;
			if (!parse_int(targ->t_str, &val)) {
				tok_error(targ, ic->ic_log, "Invalid value",
				    "value");
				goto fail;
			}
			/* XXX: validate length */
			xf->xf_nonce_len = (uint32_t)val;
			seen_nonce_len = B_TRUE;
			break;
		default:
			bunyan_error(ic->ic_log, "Parameter keyword not "
			    "allowed in transform definition",
			    BUNYAN_T_STRING, "keyword", t->t_str,
			    BUNYAN_T_END);
			goto fail;
		}

		tok_free(t);
		tok_free(targ);
		t = NULL;
		targ = NULL;
	}
	*xfp = xf;
	return (B_TRUE);

duplicate:
	tok_error(t, ic->ic_log, "Duplicate configuration parameter",
	    "parameter");

fail:
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
		bunyan_error(ic->ic_log,
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
	bunyan_error(ic->ic_log, "Unexpected value after key length",
	    BUNYAN_T_STRING, "value", t->t_str,
	    BUNYAN_T_UINT32, "line", t->t_line,
	    BUNYAN_T_UINT32, "col", t->t_col,
	    BUNYAN_T_END);
	tok_free(t);
	return (B_FALSE);

invalid:
	bunyan_error(ic->ic_log, "Invalid key bitlength",
	    BUNYAN_T_STRING, "bitlength", t->t_str,
	    BUNYAN_T_UINT32, "line", t->t_line,
	    BUNYAN_T_UINT32, "col", t->t_col,
	    BUNYAN_T_END);
	tok_free(t);
	return (B_FALSE);

toobig:
	bunyan_error(ic->ic_log, "Keysize is too large",
	    BUNYAN_T_UINT64, "keysize", val,
	    BUNYAN_T_UINT32, "line", t->t_line,
	    BUNYAN_T_UINT32, "col", t->t_col,
	    BUNYAN_T_END);
	tok_free(t);
	return (B_FALSE);

truncated:
	tok_free(t);
	bunyan_error(ic->ic_log, "Truncated input while reading transform",
	    BUNYAN_T_END);
	return (B_FALSE);
}

static boolean_t
parse_rule(input_cursor_t *restrict ic, const token_t *start,
    config_rule_t **restrict rulep)
{
	token_t *t = NULL, *targ = NULL;
	config_rule_t *rule = NULL;
	config_xf_t *xf = NULL;
	config_addr_t addr = { 0 };
	boolean_t seen_label = B_FALSE;
	boolean_t seen_local_addr = B_FALSE;
	boolean_t seen_remote_addr = B_FALSE;
	boolean_t seen_local_id_type = B_FALSE;
	boolean_t seen_local_id = B_FALSE;
	boolean_t seen_remote_id = B_FALSE;
	boolean_t seen_p2_lifetime_secs = B_FALSE;
	boolean_t seen_p2_pfs = B_FALSE;
	boolean_t seen_p1_xform = B_FALSE;
	boolean_t has_non_preshared = B_FALSE;

	*rulep = NULL;

	rule = calloc(1, sizeof (*rule));
	VERIFY3P(rule, !=, NULL);

	while ((t = input_token(ic, B_FALSE)) != NULL) {
		keyword_t kw = KW_NONE;

		if (strcmp(t->t_str, "}") == 0)
			break;

		if (!parse_kw(t->t_str, &kw)) {
			tok_log(t, ic->ic_log, BUNYAN_L_ERROR,
			    "Unrecognized configuration parameter",
			    "parameter");
			goto fail;
		}

		switch (kw) {
		case KW_LOCAL_ADDR:
		case KW_REMOTE_ADDR:
		case KW_P1_XFORM:
			break;
		default:
			targ = input_token(ic, B_FALSE);
			if (targ == NULL) {
				bunyan_error(ic->ic_log, "Input truncated "
				    "while reading rule", BUNYAN_T_END);
				goto fail;
			}
		}

		switch (kw) {
		case KW_LABEL:
			if (seen_label)
				goto duplicate;
			rule->rule_label = strdup(targ->t_str);
			if (rule->rule_label == NULL)
				goto fail;
			seen_label = B_TRUE;
			break;
		case KW_P2_PFS:
			if (seen_p2_pfs)
				goto duplicate;
			if (!parse_p2_pfs(targ->t_str, &rule->rule_p2_dh)) {
				tok_invalid(targ, ic->ic_log, KW_P2_PFS);
				goto fail;
			}
			break;
		case KW_P1_XFORM:
			if (!parse_xform(ic, &xf))
				goto fail;

			add_xf(rule, xf, B_TRUE);
			if (xf->xf_authtype != IKEV2_AUTH_SHARED_KEY_MIC)
				has_non_preshared = B_TRUE;
			seen_p1_xform = B_TRUE;
			xf = NULL;
			break;
		case KW_LOCAL_ADDR:
			(void) memset(&addr, 0, sizeof (addr));
			if (!parse_address(ic, &addr))
				goto fail;
			seen_local_addr = B_TRUE;
			break;
		case KW_REMOTE_ADDR:
			(void) memset(&addr, 0, sizeof (addr));
			if (!parse_address(ic, &addr))
				goto fail;
			seen_remote_addr = B_TRUE;
			break;
		case KW_LOCAL_ID:
			/*
			 * According to the man page, only one ID is used
			 * per rule, but instead of erroring, it just uses
			 * the first one.
			 */
			if (seen_local_id)
				break;
			rule->rule_local_id = strdup(targ->t_str);
			if (rule->rule_local_id == NULL)
				goto fail;
			seen_local_id = B_TRUE;
			break;
		case KW_REMOTE_ID:
			/* XXX: allow multiple remote ids */
			/* See KW_LOCAL_ID above */
			if (seen_remote_id)
				break;
			rule->rule_remote_id = strdup(targ->t_str);
			if (rule->rule_remote_id == NULL)
				goto fail;
			seen_remote_id = B_TRUE;
			break;
		case KW_LOCAL_ID_TYPE:
			if (seen_local_id_type)
				goto duplicate;
			if (!parse_p1_id(targ->t_str,
			    &rule->rule_local_id_type)) {
				tok_log(t, ic->ic_log, BUNYAN_L_ERROR,
				    "Unable to parse local_id_type", "value");
				goto fail;
			}
			seen_local_id_type = B_TRUE;
			break;
		default:
			tok_log(t, ic->ic_log, BUNYAN_L_ERROR, "Configuration "
			    "parameter is invalid inside a rule definition",
			    "parameter");
			goto fail;
		}

		tok_free(t);
		tok_free(targ);
		t = NULL;
		targ = NULL;
	}

	if (t == NULL) {
		bunyan_error(ic->ic_log, "Input truncated while reading rule",
		    BUNYAN_T_END);
		goto fail;
	}

	/* Try to show as many errors as we can */
	if (!seen_label)
		tok_error(t, ic->ic_log, "Rule is missing a required label",
		    NULL);
	if (!seen_local_addr)
		tok_error(t, ic->ic_log,
		    "Rule is missing a required local address", NULL);
	if (!seen_remote_addr)
		tok_error(t, ic->ic_log,
		    "Rule is missing a required remote address", NULL);

	if (!seen_label || !seen_local_addr || !seen_remote_addr)
		goto fail;

	tok_free(t);
	tok_free(targ);
	*rulep = rule;
	return (B_TRUE);

duplicate:
	tok_log(t, ic->ic_log, BUNYAN_L_ERROR,
	    "Configuration parameter can only appear once in a transform "
	    "definition", "parameter");

fail:
	tok_free(t);
	tok_free(targ);
	free(rule);
	return (B_FALSE);
}

static boolean_t
parse_address(input_cursor_t *restrict ic, config_addr_t *restrict addrp)
{
	const token_t *tpeek = NULL;
	token_t *t = NULL;
	boolean_t ip6 = B_FALSE;
	boolean_t ok = B_FALSE;

	t = input_token(ic, B_TRUE);
	if (t == NULL)
		goto truncated;

	if (!parse_ip(t->t_str, &addrp->cfa_startu.cfa_ip4)) {
		if (!parse_ip6(t->t_str, &addrp->cfa_startu.cfa_ip6)) {
			tok_log(t, ic->ic_log, BUNYAN_L_ERROR,
			    "Unable to parse address", "address");
			return (B_FALSE);
		}
		ip6 = B_TRUE;
	}
	tok_free(t);

	tpeek = input_peek(ic, B_TRUE);
	if (strcmp(tpeek->t_str, "-") == 0) {
		/* consume - */
		tok_free(input_token(ic, B_TRUE));

		addrp->cfa_type =
		    ip6 ? CFG_ADDR_IPV6_RANGE : CFG_ADDR_IPV4_RANGE;

		t = input_token(ic, B_FALSE);
		if (t == NULL)
			goto truncated;

		ok = ip6 ? parse_ip6(t->t_str, &addrp->cfa_endu.cfa_ip6) :
		    parse_ip(t->t_str, &addrp->cfa_endu.cfa_ip4);
		if (!ok) {
			tok_log(t, ic->ic_log, BUNYAN_L_ERROR,
			    "Unable to parse address", "address");
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
			tok_log(t, ic->ic_log, BUNYAN_L_ERROR,
			    "Cannot parse mask length", "mask_len");
			return (B_FALSE);
		}
		tok_free(t);
		t = NULL;
		if ((ip6 && val > 128) || (!ip6 && val > 32)) {
			bunyan_error(ic->ic_log, "Mask length too long",
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
	bunyan_error(ic->ic_log, "Input truncated while parsing address",
	     BUNYAN_T_END);
	return (B_FALSE);
}

static boolean_t
parse_p2_pfs(const char *restrict str, ikev2_dh_t *dhp)
{
	uint64_t val = 0;

	if (!parse_int(str, &val))
		return (B_FALSE);

	/* XXX: validate value */

	if (dhp != NULL)
		*dhp = (int)val;
	return (B_TRUE);
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
parse_p1_id(const char *restrict str, config_auth_id_t *restrict p1p)
{
	for (size_t i = 0; i < ARRAY_SIZE(p1_id_tab); i++) {
		if (strcmp(p1_id_tab[i].p1_str, str) == 0) {
			*p1p = p1_id_tab[i].p1_id;
			return (B_TRUE);
		}
	}
	return (B_FALSE);
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
tok_log(token_t *restrict t, bunyan_logger_t *restrict blog,
    bunyan_level_t level, const char *msg, const char *strname)
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

	if (strname != NULL) {
		getlog(level)(blog, msg, BUNYAN_T_STRING, strname, t->t_str,
		    BUNYAN_T_STRING, "line", linecpy,
		    BUNYAN_T_UINT32, "lineno", t->t_line,
		    BUNYAN_T_UINT32, "col", t->t_col,
		    BUNYAN_T_END);
	} else {
		getlog(level)(blog, msg,
		    BUNYAN_T_STRING, "line", linecpy,
		    BUNYAN_T_UINT32, "lineno", t->t_line,
		    BUNYAN_T_UINT32, "col", t->t_col,
		    BUNYAN_T_END);
	}
	free(linecpy);
}

static void
tok_error(token_t *restrict t, bunyan_logger_t *restrict b,
    const char *restrict msg, const char *restrict tname)
{
	tok_log(t, b, BUNYAN_L_ERROR, msg, tname);
}

static void
tok_invalid(token_t *restrict t, bunyan_logger_t *restrict b, keyword_t kw)
{
	char buf[128] = { 0 };
	(void) snprintf(buf, sizeof (buf), "Invalid %s parameter",
	    keyword_tab[kw]);
	tok_error(t, b, buf, "parameter");
}

static input_t *
input_new(FILE *restrict f, bunyan_logger_t *restrict blog)
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
		STDERR(error, blog, "stat failed");
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
			STDERR(error, blog, "read failed");
			goto fail;
		}
		cnt += n;

		if (cnt + 1 >= in->in_buflen) {
			if (in->in_buflen >= CONFIG_MAX) {
				bunyan_error(blog, "Input size exceeds limits",
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
	if (ic->ic_peek != NULL ) {
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
			bunyan_error(ic->ic_log, "Unterminated quoted string",
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
input_cursor_init(input_cursor_t *restrict ic, input_t *restrict in,
    bunyan_logger_t *blog)
{
	(void) memset(ic, 0, sizeof (*ic));
	ic->ic_input = in;
	ic->ic_p = in->in_buf;
	ic->ic_log = blog;
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
add_xf(void *restrict ptr, config_xf_t *restrict xf, boolean_t ptr_is_rule)
{
	config_xf_t **xfp = NULL;
	size_t cur = 0;
	size_t nxf = 0;

	if (ptr_is_rule) {
		config_rule_t *crp = ptr;

		cur = crp->rule_nxf;
		xfp = crp->rule_xf;
	} else {
		config_t *cp = ptr;

		cur = cp->cfg_xforms_alloc;
		xfp = cp->cfg_xforms;
	}

	while (nxf < cur && xfp[nxf] != NULL)
		nxf++;

	if (nxf + 2 > cur) {
		config_xf_t **newxf = NULL;
		size_t newalloc = cur + CHUNK_SZ;
		size_t amt = newalloc * sizeof (config_xf_t *);

		VERIFY3U(amt, >, newalloc);
		VERIFY3U(amt, >=, sizeof (config_xf_t *));

		newxf = realloc(xfp, amt);
		VERIFY3P(newxf, !=, NULL);

		if (ptr_is_rule) {
			config_rule_t *crp = ptr;

			crp->rule_nxf = newalloc;
			crp->rule_xf = xfp = newxf;
		} else {
			config_t *cp = ptr;

			cp->cfg_xforms = xfp = newxf;
			cp->cfg_xforms_alloc = newalloc;
		}
	}

	xfp[nxf++] = xf;
	xfp[nxf] = NULL;
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
