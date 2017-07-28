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
 * Copyright 2017 Jason King.
 * Copyright (c) 2017, Joyent, Inc.
 */
#include <sys/time.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <umem.h>
#include <netinet/in.h>
#include "config.h"
#include "ikev2.h"

/*
 * Various types of tokens.  Some of these keywords are for cfgfile
 * compatability with in.iked and are ignored.
 */
typedef enum token_type_e {
	T_NONE,
	T_STRING,
	T_INTEGER,
	T_FLOAT,
	T_LBRACE,
	T_RBRACE,
	T_LPAREN,
	T_RPAREN,
	T_DOTDOT,
	T_IPV4,
	T_IPV6,
	T_HYPHEN,
	T_SLASH,	/* he is real! */
	T_KEYWORD,
	T_P1_ID_TYPE,
	T_AUTH_METHOD,
} token_type_t;

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

static const char *keyword_tab[KW_MAX] = {
	"",	/* NONE */
	"cert_root",
	"cert_trust",
	"expire_timer",
	"ignore_crls",
	"ldap_server",
	"pkcs11_path",
	"retry_limit",
	"retry_timer_init",
	"retry_timer_max",
	"proxy",
	"socks",
	"use_http",
	"p1_lifetime_secs",
	"p1_nonce_len",
	"p2_lifetime_secs",
	"p2_softlife_secs",
	"p2_idletime_secs",
	"p2_lifetime_kb",
	"p2_softlife_kb",
	"p2_nonce_len",
	"local_id_type",
	"p1_xform",
	"auth_method",
	"oakley_group",
	"auth_alg",
	"encr_alg",
	"label",
	"local_addr",
	"remote_addr",
	"local_id_type",
	"local_id",
	"remote_id"
};

typedef struct token {
	token_type_t	t_type;
	size_t		t_line;
	size_t		t_col;
	union {
			char			*t_str;
			keyword_t		t_kw;
			uint64_t		t_int;
			double			t_float;
			in_addr_t		t_in;
			in6_addr_t		t_in6;
			ikev2_id_type_t		t_id;
			ikev2_auth_type_t	t_auth;
	} t_val;
} token_t;

typedef struct input {
	char	*i_name;
	char	*i_buf;
	size_t	i_len;
	char	**i_lines;
	size_t	i_nlines;
} input_t;

volatile hrtime_t cfg_retry_max = SEC2NSEC(60);
volatile hrtime_t cfg_retry_init = SEC2NSEC(1);

static token_t *tok_new(token_type_t, size_t, size_t, ...);
static void tok_free(token_t *);

static token_t *
tok_new(token_type_t type, size_t line, size_t col, ...)
{
	token_t *t = NULL;
	in_addr_t *ip4p = NULL;
	in6_addr_t *ip6p = NULL;
	va_list ap;

	if ((t = umem_zalloc(sizeof (*t), UMEM_DEFAULT)) == NULL)
		return (NULL);
	t->t_type = type;
	t->t_line = line;
	t->t_col = col;

	va_start(ap, col);
	switch (type) {
	case T_NONE:
	case T_LBRACE:
	case T_RBRACE:
	case T_LPAREN:
	case T_RPAREN:
	case T_DOTDOT:
	case T_HYPHEN:
	case T_SLASH:
		break;
	case T_STRING:
		t->t_val.t_str = strdup(va_arg(ap, char *));
		if (t->t_val.t_str == NULL) {
			tok_free(t);
			return (NULL);
		}
		break;
	case T_INTEGER:
		t->t_val.t_int = va_arg(ap, uint64_t);
		break;
	case T_FLOAT:
		t->t_val.t_float = va_arg(ap, double);
		break;
	case T_KEYWORD:
		t->t_val.t_kw = va_arg(ap, keyword_t);
		break;
	case T_P1_ID_TYPE:
		t->t_val.t_id = va_arg(ap, ikev2_id_type_t);
		break;
	case T_AUTH_METHOD:
		t->t_val.t_auth = va_arg(ap, ikev2_auth_type_t);
		break;
	case T_IPV4:
		ip4p = va_arg(ap, in_addr_t *);
		(void) memcpy(&t->t_val.t_in, ip4p, sizeof (*ip4p));
		break;
	case T_IPV6:
		ip6p = va_arg(ap, in6_addr_t *);
		(void) memcpy(&t->t_val.t_in6, ip6p, sizeof (*ip6p));
		break;
	}

	return (t);
}

static void
tok_free(token_t *t)
{
	if (t == NULL)
		return;
	if (t->t_type == T_STRING)
		free(t->t_val.t_str);
	(void) memset(t, 0, sizeof (*t));
	umem_free(t, sizeof (*t));
}

