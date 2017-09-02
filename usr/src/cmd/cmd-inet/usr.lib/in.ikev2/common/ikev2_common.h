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

#ifndef _IKEV2_COMMON_H
#define	_IKEV2_COMMON_H

#include <inttypes.h>
#include "ikev2.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct ikev2_sa_result_s {
	uint64_t		sar_spi;
	uint32_t		sar_match;
	ikev2_spi_proto_t	sar_proto;
	ikev2_xf_encr_t		sar_encr;
	ikev2_xf_auth_t		sar_auth;
	ikev2_prf_t		sar_prf;
	ikev2_dh_t		sar_dh;
	uint16_t		sar_encr_keylen;
	boolean_t		sar_esn;
	uint8_t			sar_propnum;
} ikev2_sa_result_t;
#define	SA_RESULT_HAS(res, which) ((res)->sar_match & ((uint32_t)1 << (which)))

struct pkt_s;
struct config_rule_s;
struct parsedmsg_s;
struct ikev2_sa_s;

ikev2_xf_auth_t ikev2_pfkey_to_auth(int);
ikev2_xf_encr_t ikev2_pfkey_to_encr(int);

boolean_t ikev2_sa_from_acquire(struct pkt_s *restrict,
    struct parsedmsg_s *restrict, uint32_t, ikev2_dh_t);
boolean_t ikev2_sa_add_result(struct pkt_s *restrict,
    const ikev2_sa_result_t *restrict);
boolean_t ikev2_sa_from_rule(struct pkt_s *restrict,
    const struct config_rule_s *restrict, uint64_t);

boolean_t ikev2_sa_match_rule(struct config_rule_s *restrict,
    struct pkt_s *restrict, ikev2_sa_result_t *restrict);
boolean_t ikev2_sa_match_acquire(struct parsedmsg_s *restrict, ikev2_dh_t,
    struct pkt_s *restrict, ikev2_sa_result_t *restrict);

void ikev2_no_proposal_chosen(struct ikev2_sa_s *restrict,
    const struct pkt_s *restrict, ikev2_spi_proto_t, uint64_t);
void ikev2_invalid_ke(const struct pkt_s *, ikev2_spi_proto_t, uint64_t,
    ikev2_dh_t);

#ifdef __cplusplus
}
#endif

#endif /* _IKEV2_COMMON_H */
