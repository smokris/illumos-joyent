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
 <F12>* uint32_t makes it cleaner for logging with bunyan
 */
typedef struct token {
	char		*t_str;
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

static boolean_t cfg_add_str(char ***restrict, const char *restrict);

static token_t *tok_new(const char *, const char *, size_t, size_t);
static void tok_free(token_t *);
static void tok_log(token_t *restrict, bunyan_logger_t *restrict,
     bunyan_level_t, const char *, const char *);

static config_rule_t *parse_rule(input_cursor_t *);
static boolean_t parse_address(input_cursor_t *restrict,
    config_addr_t *restrict);

static config_xf_t *parse_xform(input_cursor_t *);
static boolean_t parse_encrbits(input_cursor_t *restrict,
    config_xf_t *restrict);

static boolean_t parse_kw(const char *restrict, keyword_t *restrict);
static boolean_t parse_auth(const char *restrict, ikev2_auth_type_t *restrict);
static boolean_t parse_authalg(const char *restrict, ikev2_xf_auth_t *restrict);
static boolean_t parse_encralg(const char *restrict, ikev2_xf_encr_t *restrict);
static boolean_t parse_p1_id(const char *restrict, config_auth_id_t *restrict);
static boolean_t parse_ip(const char *restrict, in_addr_t *restrict);
static boolean_t parse_ip6(const char *restrict, in6_addr_t *restrict);
static boolean_t parse_int(const char *restrict, uint64_t *restrict);
static boolean_t parse_fp(const char *restrict, double *restrict);

static input_t *input_new(FILE *restrict, bunyan_logger_t *restrict);
static void input_free(input_t *);

static void input_cursor_init(input_cursor_t *, input_t *, bunyan_logger_t *);
static void input_cursor_fini(input_cursor_t *);
static token_t *input_token(input_cursor_t *, boolean_t);
static token_t *input_peek(input_cursor_t *, boolean_t);
static token_t *input_next_token(input_cursor_t *, boolean_t);
static void input_cursor_getpos(input_cursor_t *restrict, const char *restrict,
    uint32_t *restrict, uint32_t *restrict);

static boolean_t issep(char c, boolean_t);

void
process_config(FILE *f, boolean_t check_only, bunyan_logger_t *blog)
{
	input_t *in = input_new(f, blog);
	token_t *t = NULL, *targ = NULL;
	input_cursor_t ic = { 0 };
	union {
		uint64_t	ui;
		double		d;
	} val;

	if (in == NULL) {
		STDERR(error, blog, "failure reading input");
		return;
	}

	PTH(pthread_rwlock_wrlock(&cfg_lock));

	input_cursor_init(&ic, in, blog);
	while ((t = input_token(&ic, B_TRUE)) != NULL) {
		keyword_t kw;

		if (strcmp(t->t_str, "{") == 0) {
			free(parse_rule(&ic));
			continue;
		}

		if (!parse_kw(t->t_str, &kw)) {
			bunyan_error(blog, "Unrecognized keyword",
			    BUNYAN_T_STRING, "keyword", t->t_str,
			    BUNYAN_T_UINT32, "line", t->t_line,
			    BUNYAN_T_UINT32, "col", t->t_col,
			    BUNYAN_T_END);
			goto done;
		}

		VERIFY3S(kw, !=, KW_NONE);
		VERIFY3S(kw, !=, KW_MAX);

		if (keyword_tab[kw].kw_has_arg) {
			targ = input_token(&ic, keyword_tab[kw].kw_minus);
			if (targ == NULL) {
				bunyan_error(blog,
				    "Missing argument to parameter",
				    BUNYAN_T_STRING, "parameter", t->t_str,
				    BUNYAN_T_UINT32, "line", t->t_line,
				    BUNYAN_T_UINT32, "col", t->t_col,
				    BUNYAN_T_END);
				goto done;
			}
		}

		switch (kw) {
		case KW_NONE:
		case KW_MAX:
			INVALID("t->t_val.t_kw");
			break;
		case KW_CERT_ROOT:
			if (!check_only && !cfg_add_str(&cfg_cert_root,
			    targ->t_str))
				goto done;
			break;
		case KW_CERT_TRUST:
			if (!check_only && !cfg_add_str(&cfg_cert_trust,
			    targ->t_str))
				goto done;
			break;
		case KW_EXPIRE_TIMER:
			if (!parse_int(targ->t_str, &val.ui)) {
				bunyan_error(blog, "Invalid argument",
				    BUNYAN_T_STRING, "parameter", t->t_str,
				    BUNYAN_T_STRING, "arg", targ->t_str,
				    BUNYAN_T_UINT32, "line", targ->t_line,
				    BUNYAN_T_UINT32, "col", targ->t_col,
				    BUNYAN_T_END);
				goto done;
			}
			if (!check_only)
				cfg_expire_timer = val.ui * NANOSEC;
			break;
		case KW_IGNORE_CRLS:
			if (!check_only)
				cfg_ignore_crls = B_TRUE;
			break;
		case KW_LDAP_SERVER:
		case KW_PKCS11_PATH:
			bunyan_info(blog, "Ignoring deprecated parameter",
			    BUNYAN_T_STRING, "parameter", t->t_str,
			    BUNYAN_T_UINT32, "line", t->t_line,
			    BUNYAN_T_UINT32, "col", t->t_col,
			    BUNYAN_T_END);
			break;
		case KW_RETRY_LIMIT:
			if (!parse_int(targ->t_str, &val.ui)) {
				bunyan_error(blog, "Invalid argument",
				    BUNYAN_T_STRING, "parameter", t->t_str,
				    BUNYAN_T_STRING, "arg", targ->t_str,
				    BUNYAN_T_UINT32, "line", targ->t_line,
				    BUNYAN_T_UINT32, "col", targ->t_col,
				    BUNYAN_T_END);
				goto done;
			}
			if (!check_only)
				cfg_retry_limit = val.ui;
			break;
		case KW_RETRY_TIMER_INIT:
		case KW_RETRY_TIMER_MAX:
		case KW_PROXY:
		case KW_SOCKS:
		case KW_USE_HTTP:
		case KW_P1_LIFETIME_SECS:
		case KW_P1_NONCE_LEN:
		case KW_P2_LIFETIME_SECS:
		case KW_P2_SOFTLIFE_SECS:
		case KW_P2_IDLETIME_SECS:
		case KW_P2_LIFETIME_KB:
		case KW_P2_SOFTLIFE_KB:
		case KW_P2_NONCE_LEN:
		case KW_LOCAL_ID_TYPE:
		case KW_P2_PFS:
			tok_log(t, blog, BUNYAN_L_INFO, "Unimplemented "
			    "configuration parameter", "keyword");
			break;
		case KW_P1_XFORM:
			free(parse_xform(&ic));
			break;
		case KW_AUTH_METHOD:
		case KW_OAKLEY_GROUP:
		case KW_AUTH_ALG:
		case KW_ENCR_ALG:
			tok_log(t, blog, BUNYAN_L_ERROR, "Configuration "
			    "parameter cannt be used outside of a transform "
			    "definition", "parameter");
			goto done;
		case KW_LABEL:
		case KW_LOCAL_ADDR:
		case KW_REMOTE_ADDR:
		case KW_LOCAL_ID:
		case KW_REMOTE_ID:
			tok_log(t, blog, BUNYAN_L_ERROR, "Configuration "
			    "parameter cannot be used outside of a rule "
			    "definition", "parameter");
			goto done;
		}

		tok_free(t);
		tok_free(targ);
		t = NULL;
		targ = NULL;
	}

done:
	PTH(pthread_rwlock_unlock(&cfg_lock));
	tok_free(t);
	tok_free(targ);
	input_cursor_fini(&ic);
	input_free(in);
}

static config_xf_t *
parse_xform(input_cursor_t *ic)
{
	config_xf_t *xf = NULL;
	token_t *t = NULL, *targ = NULL;
	boolean_t seen_authalg = B_FALSE;
	boolean_t seen_encralg = B_FALSE;
	boolean_t seen_dh = B_FALSE;
	boolean_t seen_authmethod = B_FALSE;
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
			bunyan_error(ic->ic_log,
			    "Missing argument to parameter",
			    BUNYAN_T_STRING, "parameter", t->t_str,
			    BUNYAN_T_UINT32, "line", t->t_line,
			    BUNYAN_T_UINT32, "col", t->t_col,
			    BUNYAN_T_END);
			goto fail;
		}

		keyword_t kw = KW_NONE;

		if (!parse_kw(t->t_str, &kw)) {
			bunyan_error(ic->ic_log, "Unknown keyword",
			    BUNYAN_T_STRING, "keyword", t->t_str,
			    BUNYAN_T_UINT32, "line", t->t_line,
			    BUNYAN_T_UINT32, "col", t->t_col,
			    BUNYAN_T_END);
			goto fail;
		}

		switch (kw) {
		case KW_AUTH_METHOD:
			if (seen_authmethod) {
				bunyan_error(ic->ic_log, "Duplicate transform "
				    "parameter",
				    BUNYAN_T_STRING, "parameter", targ->t_str,
				    BUNYAN_T_UINT32, "line", targ->t_line,
				    BUNYAN_T_UINT32, "col", targ->t_col,
				    BUNYAN_T_END);
				goto fail;
			}
			if (!parse_auth(targ->t_str, &xf->xf_authtype)) {
				bunyan_error(ic->ic_log,
				    "Invalid authentication method",
				    BUNYAN_T_STRING, "method", targ->t_str,
				    BUNYAN_T_UINT32, "line", targ->t_line,
				    BUNYAN_T_UINT32, "col", targ->t_col,
				    BUNYAN_T_END);
				goto fail;
			}
			seen_authmethod = B_TRUE;
			break;
		case KW_OAKLEY_GROUP:
			if (seen_dh) {
				bunyan_error(ic->ic_log, "Duplicate transform "
				    "parameter",
				    BUNYAN_T_STRING, "parameter", targ->t_str,
				    BUNYAN_T_UINT32, "line", targ->t_line,
				    BUNYAN_T_UINT32, "col", targ->t_col,
				    BUNYAN_T_END);
				goto fail;
			}
			if (!parse_int(targ->t_str, &val)) {
				bunyan_error(ic->ic_log,
				    "Invalid oakley (DH) group",
				    BUNYAN_T_STRING, "group", targ->t_str,
				    BUNYAN_T_UINT32, "line", targ->t_line,
				    BUNYAN_T_UINT32, "col", targ->t_col,
				    BUNYAN_T_END);
				goto fail;
			}
			/* XXX: Should have a way to validate the value */
			seen_dh = B_TRUE;
			xf->xf_dh = (ikev2_dh_t)val;
			break;
		case KW_AUTH_ALG:
			if (seen_authalg) {
				bunyan_error(ic->ic_log,
				    "Duplicate authentication algorithm",
				    BUNYAN_T_STRING, "parameter", targ->t_str,
				    BUNYAN_T_UINT32, "line", targ->t_line,
				    BUNYAN_T_UINT32, "col", targ->t_col,
				    BUNYAN_T_END);
				goto fail;
			}
			if (!parse_authalg(targ->t_str, &xf->xf_auth)) {
				bunyan_error(ic->ic_log,
				    "Unknown authentication algorithm",
				    BUNYAN_T_STRING, "algorithm", targ->t_str,
				    BUNYAN_T_UINT32, "line", targ->t_line,
				    BUNYAN_T_UINT32, "col", targ->t_col,
				    BUNYAN_T_END);
				goto fail;
			}
			seen_authalg = B_TRUE;
			break;
		case KW_ENCR_ALG:
			if (seen_encralg) {
				bunyan_error(ic->ic_log,
				    "Duplicate authentication algorithm",
				    BUNYAN_T_STRING, "parameter", targ->t_str,
				    BUNYAN_T_UINT32, "line", targ->t_line,
				    BUNYAN_T_UINT32, "col", targ->t_col,
				    BUNYAN_T_END);
				goto fail;
			}
			if (!parse_encralg(targ->t_str, &xf->xf_encr)) {
				bunyan_error(ic->ic_log, "Unknown encryption "
				    "algorithm",
				    BUNYAN_T_STRING, "algorithm", targ->t_str,
				    BUNYAN_T_UINT32, "line", targ->t_line,
				    BUNYAN_T_UINT32, "col", targ->t_col,
				    BUNYAN_T_END);
				goto fail;
			}
			seen_encralg = B_TRUE;
			if (!parse_encrbits(ic, xf))
				goto fail;
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
	return (xf);

fail:
	tok_free(t);
	tok_free(targ);
	free(xf);
	return (NULL);	
}

static boolean_t
parse_encrbits(input_cursor_t *restrict ic, config_xf_t *restrict xf)
{
	token_t *t = NULL;
	uint64_t val = 0;

	if ((t = input_peek(ic, B_FALSE)) == NULL)
		goto truncated;

	/* No key length given, that's ok */
	if (strcmp(t->t_str, "(") != 0)
		return (B_TRUE);

	/* consume '(' */
	t = input_token(ic, B_FALSE);
	tok_free(t);

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

static config_rule_t *
parse_rule(input_cursor_t *ic)
{
	token_t *t = NULL, *targ = NULL;
	config_rule_t *rule = NULL;
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
			break;
		case KW_P2_PFS:
			break;
		case KW_P1_XFORM:
			free(parse_xform(ic));
			break;
		case KW_LOCAL_ADDR:
			(void) memset(&addr, 0, sizeof (addr));
			if (!parse_address(ic, &addr)) {
				goto fail;
			}
			break;
		case KW_REMOTE_ADDR:
			(void) memset(&addr, 0, sizeof (addr));
			if (!parse_address(ic, &addr)) {
				goto fail;
			}
			break;
		case KW_LOCAL_ID:
			break;
		case KW_REMOTE_ID:
			break;
		case KW_LOCAL_ID_TYPE:
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

done:
	tok_free(t);
	tok_free(targ);
	return (rule);

fail:
	tok_free(t);
	tok_free(targ);
	free(rule);
	return (NULL);
}

static boolean_t
parse_address(input_cursor_t *restrict ic, config_addr_t *restrict addrp)
{
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
	t = input_peek(ic, B_TRUE);
	if (strcmp(t->t_str, "-") == 0) {
		/* consume - */
		t = input_token(ic, B_TRUE);
		tok_free(t);

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
	} else if (strcmp(t->t_str, "/") == 0) {
		uint64_t val = 0;

		addrp->cfa_type =
		    ip6 ? CFG_ADDR_IPV6_PREFIX : CFG_ADDR_IPV4_PREFIX;

		/* consume "/" */
		t = input_token(ic, B_TRUE);
		tok_free(t);

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
tok_new(const char *startp, const char *endp, size_t line, size_t col)
{
	VERIFY3P(endp, >=, startp);

	token_t *t = NULL;
	size_t len = (size_t)(endp - startp) + 1;

	t = calloc(1, sizeof (*t));
	VERIFY3P(t, !=, NULL);

	t->t_str = calloc(1, len);
	VERIFY3P(t, !=, NULL);

	(void) strlcpy(t->t_str, startp, len);
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
	int (*logf)(bunyan_logger_t *, const char *, ...) = NULL;

	switch (level) {
	case BUNYAN_L_TRACE:
		logf = bunyan_trace;
		break;
	case BUNYAN_L_DEBUG:
		logf = bunyan_debug;
		break;
	case BUNYAN_L_INFO:
		logf = bunyan_info;
		break;
	case BUNYAN_L_WARN:
		logf = bunyan_warn;
		break;
	case BUNYAN_L_ERROR:
		logf = bunyan_error;
		break;
	case BUNYAN_L_FATAL:
		logf = bunyan_fatal;
		break;
	}

	logf(blog, msg, BUNYAN_T_STRING, strname, t->t_str,
	    BUNYAN_T_UINT32, "line", t->t_line,
	    BUNYAN_T_UINT32, "col", t->t_col);
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

	fprintf(stderr, "token: \'%s\'\n", (t != NULL) ? t->t_str : "(NULL)");
	return (t);
}

/* NOTE: results of input_peek() should NOT be freed */
static token_t *
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
			input_cursor_getpos(ic, start, &line, &col);
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
	input_cursor_getpos(ic, start, &line, &col);
	return (tok_new(start, end, line, col));
}

static void
input_cursor_getpos(input_cursor_t *restrict ic, const char *restrict p,
    uint32_t *restrict linep, uint32_t *restrict colp)
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

/*
 * Append a string onto an array of strings.  Since these shouldn't be heavily
 * called, we're not (currently at least) worried about the possibility
 * of excessive realloc() calls.
 */
static boolean_t
cfg_add_str(char ***restrict ppp, const char *restrict str)
{
	char *newstr = NULL;
	char **array = NULL;
	char **narray = NULL;
	size_t nelems = 0;

	/* XXX: use realloc_array once it's available */
	for (array = *ppp; array != NULL && array[nelems] != NULL; nelems++)
		;

	size_t len = (nelems + 2) * sizeof (char *);
	if (len < (nelems + 2) || len < sizeof (char *)) {
		errno = EOVERFLOW;
		return (B_FALSE);
	}

	newstr = strdup(str);
	if (newstr == NULL)
		return (B_FALSE);

	narray = realloc(array, len);
	if (narray == NULL) {
		free(newstr);
		return (B_FALSE);
	}

	narray[nelems] = newstr;
	*ppp = narray;
	return (B_TRUE);
}

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
