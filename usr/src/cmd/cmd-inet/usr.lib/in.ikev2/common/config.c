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
#include <sys/debug.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <umem.h>
#include <netinet/in.h>
#include <errno.h>
#include <bunyan.h>
#include <ctype.h>
#include <stdio.h>
#include "config.h"
#include "ikev2.h"

#ifndef ARRAY_SIZE
#define	ARRAY_SIZE(x)	(sizeof (x) / sizeof (x[0]))
#endif

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
	T_ENCR_ALG,
	T_AUTH_ALG
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

static struct {
	ikev2_auth_type_t	a_id;
	const char		a_str[];
} auth_tab[] = {
	{ IKEV2_AUTH_NONE, "" },
	{ IKEV2_AUTH_RSA_SIG, "rsa_sig" },
	{ IKEV2_AUTH_SHARED_KEY_MIC, "preshared" },
	{ IKEV2_AUTH_DSS_SIG, "dss_sig" }
};

static struct {
	config_auth_id_t	p1_id;
	const char		p1_str[];
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
	const char	xfa_str[];
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
	const char	xfe_str[];
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
			config_auth_id_t	t_auth;
			ikev2_xf_encr_t		t_encralg;
			ikev2_xf_auth_t		t_authalg;
	} t_val;
} token_t;

typedef struct tokens {
	token_t	**t_tokens;
	size_t	t_ntokens;
	size_t	t_alloc;
} tokens_t;

typedef struct input {
	char	*i_name;
	char	*i_buf;
	size_t	i_len;
	char	**i_lines;
	size_t	i_nlines;
	size_t	i_alloc;
} input_t;

volatile hrtime_t cfg_retry_max = SEC2NSEC(60);
volatile hrtime_t cfg_retry_init = SEC2NSEC(1);

static token_t *tok_new(token_type_t, size_t, size_t, ...);
static void tok_free(token_t *);
static void tok_fail(char *, size_t, size_t, bunyan_logger_t *);
static token_t *tok_str(char **, size_t, size_t *, bunyan_logger_t *);
static token_t *tok_num(char **, size_t, size_t *, bunyan_logger_t *);
static token_t *tok_enum(char **, size_t, size_t *, bunyan_logger_t *);
static token_t *tok_int(char **, size_t, size_t *, bunyan_logger_t *);
static token_t *tok_fp(char **, size_t, size_t *, bunyan_logger_t *);

#define	INPUT_CHUNK_SZ	(64)
input_t *
input_new(const char *name, FILE *f)
{
	input_t *in = NULL;
	char *line = NULL;
	size_t linesz = 0;
	ssize_t n = 0;

	in = malloc(sizeof (*in));
	if (in == NULL)
		return (NULL);
	(void) memset(in, 0, sizeof (*in));

	in->i_name = strdup(name);
	if (in->i_name == NULL)
		goto error;

	while ((n = getline(&line, &linesz, f)) > 0) {
		if (in->i_nlines + 1 >= in->i_alloc) {
			size_t newlen = in->i_alloc + INPUT_CHUNK_SZ;
			size_t amt = newlen * sizeof (char *);

			if (amt < newlen || amt < sizeof (char *)) {
				errno = EOVERFLOW;
				goto error;
			}

			char **newbuf = realloc(in->i_lines, amt);
			if (newbuf == NULL)
				goto error;

			in->i_lines = newbuf;
			in->i_alloc = newlen;
		}

		char *str = strdup(line);
		if (str == NULL)
			goto error;

		in->i_lines[in->i_nlines++] = str;
	}

	if (ferror(f))
		goto error;

	return (in);

error:
	input_free(in);
	return (NULL);
}

void
input_free(input_t *in)
{
	if (in == NULL)
		return;

	free(in->i_name);
	free(in->i_lines);
	free(in);
}

#define	TOKEN_CHUNK_SZ	(64)
static boolean_t
tokens_grow(tokens_t *tokens)
{
	size_t newsize = tokens->t_alloc + TOKEN_CHUNK_SZ;
	if (newsize < tokens->t_alloc || newsize < TOKEN_CHUNK_SZ) {
		errno = EOVERFLOW;
		return (B_FALSE);
	}

	size_t amt = newsize * sizeof (token_t *);
	if (amt < newsize || amt < sizeof (token_t *)) {
		errno = EOVERFLOW;
		return (B_FALSE);
	}

	token_t **newp = umem_zalloc(amt, UMEM_DEFAULT);
	if (newp == NULL)
		return (B_FALSE);

	/* as newsize > tokens->t_alloc, if it doesn't overflow, these can't */
	amt = tokens->t_ntokens * sizeof (token_t *);
	(void) memcpy(newp, tokens->t_tokens, amt);

	amt = tokens->t_alloc * sizeof (token_t *);
	umem_free(tokens->t_tokens, amt);

	tokens->t_tokens = newp;
	tokens->t_alloc = newsize;
	return (B_TRUE);	
}

/*
 * NOTE: This only releases the space allocated by the members of tokens_t
 * but not tokens itself (as it usually will just be on the stack)
 */
static void
tokens_free(tokens_t *tokens)
{
	if (tokens == NULL)
		return;

	for (size_t i = 0; i < tokens->t_ntokens; i++)
		tok_free(tokens->t_tokens[i]);
	umem_free(tokens->t_tokens, tokens->t_alloc * sizeof (token_t *));
	(void) memset(tokens, 0, sizeof (*tokens));
}

static boolean_t
tokenize_input(input_t *in, tokens_t *tokens, bunyan_logger_t *blog)
{
	char *p = NULL;
	size_t line = 0;
	size_t col = 1;
	size_t i;

	(void) memset(tokens, 0, sizeof (*tokens));
	for (line = 0; line < in->i_nlines; line++) {
		for (p = in->i_lines[line], col = 0; p[0] != '\0'; p++, col++) {
			token_t *t = NULL;

			switch (*p) {
			case '\n':
			case ' ':
			case '\t':
				continue;
			case '#':
				while (p[1] != '\0' && p[1] != '\n') {
					p++;
					col++;
				}
				continue;
			case '{':
				t = tok_new(T_LBRACE, line, col);
				break;
			case '}':
				t = tok_new(T_RBRACE, line, col);
				break;
			case '(':
				t = tok_new(T_LPAREN, line, col);
				break;
			case ')':
				t = tok_new(T_RPAREN, line, col);
				break;
			case '-':
				t = tok_new(T_HYPHEN, line, col);
				break;
			case '/':
				t = tok_new(T_SLASH, line, col);
				break;
			case '.':
				if (p[1] != '.')
					goto fail;
				t = tok_new(T_DOTDOT, line, col);
				col++;
				p++;
				break;
			case '"':
				t = tok_str(&p, line, &col, blog);
				break;
			default:
				if (p[0] == '+' || isdigit(p[0]))
					t = tok_num(&p, line, &col, blog);
				else if (isalpha(p[0]))
					t = tok_enum(&p, line, &col, blog);
				else
					goto fail;
			}

			if (t == NULL)
				return (B_TRUE);

			if (tokens->t_ntokens + 1 >= tokens->t_alloc) {
				if (!tokens_grow(tokens)) {
					tok_free(t);
					return (B_FALSE);
				}
			}
			tokens->t_tokens[tokens->t_ntokens++] = t;
		}
	}
	return (B_TRUE);

fail:
	tok_fail(in->i_lines[line], line, col, blog);
	return (B_FALSE);
}

static void
tok_fail(char *lineptr, size_t line, size_t col, bunyan_logger_t *blog)
{
	char *start = lineptr;
	char *end = start;
	size_t len = 0;

	for (size_t i = 0; i < col - 1; i++)
		VERIFY3U(lineptr[i], !=, '\0');

	start = lineptr + col - 1;
	while (end[0] != '\0' && end[0] != ' ' && end[0] != '\n')
		end++;
	len = (size_t)(end - start) + 1;

	char str[len];
	(void) strlcpy(str, start, len);

	bunyan_error(blog, "Unrecognized token",
	    BUNYAN_T_UINT32, "line", (uint32_t)line + 1,
	    BUNYAN_T_UINT32, "column", (uint32_t)col,
	    BUNYAN_T_STRING, "val", lineptr,
	    BUNYAN_T_STRING, "token", str,
	    BUNYAN_T_END);
}

static token_t *
tok_str(char **p, size_t line, size_t *col, bunyan_logger_t *blog)
{
	VERIFY3U(p[0][0], ==, '"');
	char *end = *p;

	end++;
	while (end[0] != '\0' && end[0] != '\n' && end[0] != '"')
		end++;

	switch (end[0]) {
	case '\0':
		/* XXX: error */
		return (NULL);
	case '\n':
		/* XXX: error */
		return (NULL);
	}

	size_t len = (size_t)(end - *p) + 1;
	char str[len];

	(void) strlcpy(str, *p, len);
	token_t *t = tok_new(T_STRING, line, *col, str);

	if (t == NULL)
		return (NULL);

	*col += len;
	return (t);
}

static token_t *
tok_num(char **p, size_t line, size_t *col, bunyan_logger_t *blog)
{
	char *end = *p;
	size_t digits = 0, letters = 0, dot = 0, colon = 0, plus = 0;

	while (end[0] != '\0') {
		boolean_t stop = B_FALSE;

		switch (end[0]) {
		case '0': case '1': case '2': case '3': case '4':
		case '5': case '6': case '7': case '8': case '9':
			digits++;
			break;
		case 'a': case 'b': case 'c': case 'd': case 'e': case 'f':
		case 'A': case 'B': case 'C': case 'D': case 'E': case 'F':
			letters++;
			break;
		case ':':
			colon++;
			break;
		case '.':
			dot++;
			break;
		case '+':
			plus++;
			break;
		default:
			stop = B_TRUE;
		}

		end++;
	}

	/* allow leading + */
	if (end[0] == '+')
		end++;

	/* '0x....' is always an integer */
	if (end[0] == '0' && end[1] == 'x')
		return (tok_int(p, line, col, blog));

	
	while (isdigit(end[0]))
		end++;

	/* digits '.' digit should be floating point */
	if (end[0] == '.' && isdigit(end[1]))
		return (tok_fp(p, line, col, blog));

	/* anything else and we treat the run of digits as an int */
	return (tok_int(p, line, col, blog));
}

static token_t *
tok_ip(char **p, size_t line, size_t *col, bunyan_logger_t *blog)
{
	token_t *t = NULL;
	char *end = *p;
	in_addr_t addr = { 0 };
	size_t len = 0;

	while (end[0] != '\0' && (isdigit(end[0]) || end[0] == '.'))
		end++;

	len = (size_t)(end - *p) + 1;
	if (len > INET_ADDRSTRLEN)
		return (NULL);

	char str[len];
	(void) strlcpy(str, *p, len);

	if (inet_pton(AF_INET, str, &addr) != 1)
		return (NULL);

	t = tok_new(T_IPV4, line, *col, &addr);
	if (t == NULL)
		return (NULL);

	*col += len;
	return (t);
}

static token_t *
tok_ip6(char **p, size_t line, size_t *col, bunyan_logger_t *blog)
{
	token_t *t = NULL;
	char *end = *p;
	in6_addr_t addr = { 0 };
	size_t len = 0;

	while (end[0] != '\0' && (isxdigit(end[0]) || end[0] == ':'))
		end++;

	len = (size_t)(end - *p) + 1;
	if (len > INET6_ADDRSTRLEN)
		return (NULL);

	char str[len];
	(void) strlcpy(str, *p, len);

	if (inet_pton(AF_INET6, str, &addr) != 1)
		return (NULL);

	t = tok_new(T_IPV6, line, *col, &addr);
	if (t == NULL)
		return (NULL);

	*col += len;
	return (t);
}

static token_t *
tok_int(char **p, size_t line, size_t *col, bunyan_logger_t *blog)
{
	token_t *t = NULL;
	char *end = NULL;
	uint64_t val = 0;
	size_t len = 0;

	errno = 0;
	val = strtoull(*p, &end, 0);
	if (val == 0 && errno != 0)
		return (NULL);

	len = (size_t)(end - *p);
	t = tok_new(T_INTEGER, line, *col, val);
	if (t == NULL)
		return (NULL);

	*col += len;
	return (t);
}

static token_t *
tok_fp(char **p, size_t line, size_t *col, bunyan_logger_t *blog)
{
	token_t *t = NULL;
	char *end = NULL;
	double val = 0.0;
	size_t len = 0;

	errno = 0;
	val = strtod(*p, &end);
	if (errno != 0)
		return (NULL);

	len = (size_t)(end - *p);
	t = tok_new(T_FLOAT, line, *col, val);
	if (t == NULL)
		return (NULL);

	*col += len;
	return (t);
}

static token_t *
tok_enum(char **p, size_t line, size_t *col, bunyan_logger_t *blog)
{
	token_t *t = NULL;
	char *end = *p;

	while (end[0] == '_' || (end[0] >= 'a' && end[0] <='z') ||
	    (end[0] >= 'A' && end[0] <= 'Z') ||
	    (end[0] >= '1' && end[0] <= '9'))
		end++;

	size_t len = (size_t)(end - *p) + 1;
	char str[len];

	(void) strlcpy(str, *p, len);

	for (keyword_t kw = 0; kw < KW_MAX; kw++) {
		if (strcmp(keyword_tab[kw], str) != 0)
			continue;

		t = tok_new(T_KEYWORD, line, *col, kw);
		if (t == NULL)
			return (NULL);

		*col += len;
		return (t);
	}

	for (size_t i = 0; i < ARRAY_SIZE(auth_tab); i++) {
		if (strcmp(str, auth_tab[i].a_str) != 0)
			continue;

		t = tok_new(T_AUTH_METHOD, line, *col, auth_tab[i].a_id);
		if (t == NULL)
			return (NULL);

		*col += len;
		return (t);
	}

	for (size_t i = 0; i < ARRAY_SIZE(p1_id_tab); i++) {
		if (strcmp(str, p1_id_tab[i].p1_str) != 0)
			continue;

		t = tok_new(T_P1_ID_TYPE, line, *col, p1_id_tab[i].p1_id);
		if (t == NULL)
			return (NULL);

		*col += len;
		return (t);
	}

	for (size_t i = 0; i < ARRAY_SIZE(xf_encr_tab); i++) {
		if (strcmp(str, xf_encr_tab[i].xfe_str) != 0)
			continue;

		t = tok_new(T_ENCR_ALG, line, *col, xf_encr_tab[i].xfe_id);
		if (t == NULL)
			return (NULL);

		*col += len;
		return (t);
	}

	for (size_t i = 0; i < ARRAY_SIZE(xf_auth_tab); i++) {
		if (strcmp(str, xf_auth_tab[i].xfa_str) != 0)
			continue;

		t = tok_new(T_AUTH_ALG, line, *col, xf_auth_tab[i].xfa_id);
		if (t == NULL)
			return (NULL);

		*col += len;
		return (t);
	}

	return (NULL);
}

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
	case T_ENCR_ALG:
		t->t_val.t_encralg = va_arg(ap, ikev2_xf_encr_t);
		break;
	case T_AUTH_ALG:
		t->t_val.t_authalg = va_arg(ap, ikev2_xf_auth_t);
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

static const char *
tok_id_str(token_type_t id)
{
#define	STR(x) case x: return (#x)
	switch (id) {
	STR(T_NONE);
	STR(T_STRING);
	STR(T_INTEGER);
	STR(T_FLOAT);
	STR(T_LBRACE);
	STR(T_RBRACE);
	STR(T_LPAREN);
	STR(T_RPAREN);
	STR(T_DOTDOT);
	STR(T_IPV4);
	STR(T_IPV6);
	STR(T_HYPHEN);
	STR(T_SLASH);
	STR(T_KEYWORD);
	STR(T_P1_ID_TYPE);
	STR(T_AUTH_METHOD);
	STR(T_ENCR_ALG);
	STR(T_AUTH_ALG);
	}
	return ("UNKNOWN");
}

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

static void
tok_log(token_t *t, bunyan_logger_t *blog)
{
	const char *idstr = tok_id_str(t->t_type);

	switch (t->t_type) {
	case T_NONE:
	case T_LBRACE:
	case T_RBRACE:
	case T_LPAREN:
	case T_RPAREN:
	case T_DOTDOT:
	case T_HYPHEN:
	case T_SLASH:
		bunyan_trace(blog, idstr,
		    BUNYAN_T_UINT32, "line", (uint32_t)t->t_line + 1,
		    BUNYAN_T_UINT32, "column", (uint32_t)t->t_col + 1,
		    BUNYAN_T_END);
		break;
	case T_STRING:
		bunyan_trace(blog, idstr,
		    BUNYAN_T_UINT32, "line", (uint32_t)t->t_line + 1,
		    BUNYAN_T_UINT32, "column", (uint32_t)t->t_col + 1,
		    BUNYAN_T_STRING, "value", t->t_val.t_str,
		    BUNYAN_T_END);
		break;
	case T_INTEGER:
		bunyan_trace(blog, idstr,
		    BUNYAN_T_UINT32, "line", (uint32_t)t->t_line + 1,
		    BUNYAN_T_UINT32, "column", (uint32_t)t->t_col + 1,
		    BUNYAN_T_UINT64, "value", t->t_val.t_int,
		    BUNYAN_T_END);
		break;
	case T_FLOAT:
		bunyan_trace(blog, idstr,
		    BUNYAN_T_UINT32, "line", (uint32_t)t->t_line + 1,
		    BUNYAN_T_UINT32, "column", (uint32_t)t->t_col + 1,
		    BUNYAN_T_DOUBLE, "value", t->t_val.t_float,
		    BUNYAN_T_END);
		break;
	case T_IPV4:
		bunyan_trace(blog, idstr,
		    BUNYAN_T_UINT32, "line", (uint32_t)t->t_line + 1,
		    BUNYAN_T_UINT32, "column", (uint32_t)t->t_col + 1,
		    BUNYAN_T_IP, "value", t->t_val.t_in,
		    BUNYAN_T_END);
		break;
	case T_IPV6:
		bunyan_trace(blog, idstr,
		    BUNYAN_T_UINT32, "line", (uint32_t)t->t_line + 1,
		    BUNYAN_T_UINT32, "column", (uint32_t)t->t_col + 1,
		    BUNYAN_T_IP6, "value", t->t_val.t_in6,
		    BUNYAN_T_END);
		break;
	case T_KEYWORD:
		bunyan_trace(blog, idstr,
		    BUNYAN_T_UINT32, "line", (uint32_t)t->t_line + 1,
		    BUNYAN_T_UINT32, "column", (uint32_t)t->t_col + 1,
		    BUNYAN_T_STRING, "value", keyword_tab[t->t_val.t_kw],
		    BUNYAN_T_END);
		break;
	case T_P1_ID_TYPE:
		bunyan_trace(blog, idstr,
		    BUNYAN_T_UINT32, "line", (uint32_t)t->t_line + 1,
		    BUNYAN_T_UINT32, "column", (uint32_t)t->t_col + 1,
		    BUNYAN_T_STRING, "value", cfg_auth_id_str(t->t_val.t_auth),
		    BUNYAN_T_END);
		break;
	case T_AUTH_METHOD:
	case T_ENCR_ALG:
	case T_AUTH_ALG:
		/* XXX: stringify */
		bunyan_trace(blog, idstr,
		    BUNYAN_T_UINT32, "line", (uint32_t)t->t_line + 1,
		    BUNYAN_T_UINT32, "column", (uint32_t)t->t_col + 1,
		    BUNYAN_T_INT32, "value", (int32_t)t->t_val.t_id,
		    BUNYAN_T_END);
		break;
	}
}
