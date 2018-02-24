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
#ifndef _CONFIG_IMPL_H
#define	_CONFIG_IMPL_H

struct config;
struct config_xf;
struct config_rule;

struct config *config_new(void);
struct config_xf *config_xf_new(void);
struct config_rule *config_rule_new(void);

void config_xf_free(struct config_xf *);
void config_xfs_free(struct config_xf **);
void config_rule_free(struct config_rule *);

#ifdef __cplusplus
}
#endif

#endif /* _CONFIG_IMPL_H */
