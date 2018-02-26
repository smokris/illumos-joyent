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

#ifndef _UTIL_H
#define	_UTIL_H

/*
 * Describe the purpose of the file here.
 */

#ifdef __cplusplus
extern "C" {
#endif

struct config_id;

const char *enum_printf(const char *, ...);
const char *afstr(sa_family_t);
const char *event_str(event_t);
const char *port_source_str(ushort_t);
const char *symstr(void *, char *, size_t);
const char *pfkey_op_str(uint8_t);
const char *pfkey_satype_str(uint8_t);

void log_reset_keys(void);
void key_add_ike_version(const char *, uint8_t);
void key_add_ike_spi(const char *, uint64_t);
void key_add_addr(const char *, const struct sockaddr *);
void key_add_id(const char *, const char *, struct config_id *);
char *writehex(uint8_t *, size_t, char *, char *, size_t);

void sockaddr_copy(const struct sockaddr *, struct sockaddr_storage *,
    boolean_t);
int sockaddr_cmp(const struct sockaddr *, const struct sockaddr *);
boolean_t addr_is_zero(const struct sockaddr *);

char *ustrdup(const char *, int);
void ustrfree(char *);
void strarray_free(char **);

#ifdef __cplusplus
}
#endif

#endif /* _UTIL_H */
