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
 * Copyright 2017 Joyent, Inc.
 */

#ifndef _IKEV2_ENUM_H
#define	_IKEV2_ENUM_H

#include "ikev2.h"

#ifdef __cplusplus
extern "C" {
#endif

const char *ikev2_exch_str(ikev2_exch_t);
const char *ikev2_pay_str(ikev2_pay_type_t);
const char *ikev2_pay_short_str(ikev2_pay_type_t);
const char *ikev2_spi_str(ikev2_spi_proto_t);
const char *ikev2_xf_type_str(ikev2_xf_type_t);
const char *ikev2_xf_encr_str(ikev2_xf_encr_t);
const char *ikev2_xf_auth_str(ikev2_xf_auth_t);
const char *ikev2_auth_type_str(ikev2_auth_type_t);
const char *ikev2_dh_str(ikev2_dh_t);
const char *ikev2_notify_str(ikev2_notify_type_t);
const char *ikev2_prf_str(ikev2_prf_t);

#ifdef __cplusplus
}
#endif

#endif /* _IKEV2_ENUM_H */
