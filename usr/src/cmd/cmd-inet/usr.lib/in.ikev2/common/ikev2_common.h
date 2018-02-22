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

#include <net/pfkeyv2.h>
#include <inttypes.h>
#include <sys/types.h>
#include "ikev2.h"
#include "pkcs11.h"

#ifdef __cplusplus
extern "C" {
#endif

struct pkt_s;
struct config_rule;
struct parsedmsg_s;
struct ikev2_sa_s;
struct ikev2_child_sa_s;
struct pkt_payload;

/*
 * The SA payload is used to describe a host's policy (for both IKE traffic
 * and when creating IPsec SAs) to a peer.  RFC7296 2.7 has all the details,
 * but briefly, mechanisms are organized by type (ENCR, AUTH, PRF, etc) and
 * then grouped into proposals.  Depending on the type of SA being negotiated
 * (as indicated in the protocol field of the proposal), some types are
 * required, while others are mandatory.  For example, for an ESP SA,
 * a proposal MUST specify at least one encryption algorithm and if ESNs can
 * be used if that proposal is selected.  It can optionally include an
 * integrity (AUTH) mechanism if one should be used if this proposal is
 * selected.  A given proposal then loosely means 'any 1 of each type (ENCR,
 * AUTH, ...) from this list is acceptable.'
 *
 * When evaluating proposals, we track which types of mechanisms (transforms)
 * are present in our policy, which types are present in the peer's policy
 * we are currently evaluating, as well as which types have found a matching
 * value.  For a given type, the matching value is then saved in their
 * respective fields (ism_encr for the matching ENCR mechanism, etc.).  Since
 * not every transform type is used with a given SA type, this allows us to
 * make sure we have a match for every type either we or our peer has proposed.
 *
 * For convenience, when negotiating IKE SAs, we also include the authentication
 * method (preshared, RSA sig, etc.) from the matching local policy as well as
 * the IKE lifetime from the matching local policy.  These are not negotiated
 * in IKEv2 (i.e. there is no choosing by the responder, each side just uses
 * whatever is in their local configuration), and are ignored when performing
 * non-IKE evaluations.
 */
typedef struct ikev2_sa_match_s {
	uint64_t		ism_spi;	/* SPI from matching proposal */
	uint32_t		ism_match;	/* types that match */
	uint32_t		ism_have;	/* types in our policy */
	uint32_t		ism_seen;	/* types from peer */
	ikev2_spi_proto_t	ism_satype;
	ikev2_xf_encr_t		ism_encr;
	ikev2_xf_auth_t		ism_auth;
	ikev2_prf_t		ism_prf;
	ikev2_dh_t		ism_dh;
	uint16_t		ism_encr_keylen;
	uint16_t		ism_encr_saltlen;
	boolean_t		ism_esn;
	uint8_t			ism_propnum;
	ikev2_auth_type_t	ism_authmethod;	/* auth method for IKE_AUTH */
} ikev2_sa_match_t;
#define	SEEN(which) ((uint32_t)1 << (which))
#define	SA_MATCH_HAS(m, which) ((m)->ism_have & SEEN(which))
#define	SA_MATCH_SEEN(m, which) ((m)->ism_seen & SEEN(which))
#define	SA_MATCHES(m, which) ((m)->ism_match & SEEN(which))
#define	SA_MATCH(m) \
    (!!(((m)->ism_match & (m)->ism_seen & (m)->ism_have) == (m)->ism_have))

enum {
	CSA_IN,
	CSA_OUT
};

/* Key length maxes in bytes for array sizing */
#define	ENCR_MAX SADB_1TO8(IKEV2_ENCR_KEYLEN_MAX + IKEV2_ENCR_SALTLEN_MAX)
#define	AUTH_MAX SADB_1TO8(IKEV2_AUTH_KEYLEN_MAX)

/* XXX: Needs a better name */
typedef struct ikev2_child_sa_state_s {
	struct ikev2_child_sa_s	*csa_child;
	uint8_t			csa_child_encr[ENCR_MAX];
	uint8_t			csa_child_auth[AUTH_MAX];
	boolean_t		csa_child_added;
} ikev2_child_sa_state_t;

/*
 * When creating a new IKEv2 SA and/or creating a child SA (either as
 * part of the IKE_SA_INIT/IKE_AUTH exchanges or as a standalone
 * CREATE_CHILD_SA exchang), there is a fair amount of transitory state
 * that needs to be kept, but only until we've either successfully created
 * the SA in question, or we error out.  That is what is stored here.
 */
typedef struct ikev2_sa_args_s {
	struct ikev2_sa_s	*i2a_i2sa; /* The new IKE SA being created */
	struct parsedmsg_s	*i2a_pmsg;
	sadb_msg_t		*i2a_sadb_msg;
	struct ikev2_child_sa_s *i2a_old_csa; /* Orig Child SA during rekey */

	ikev2_dh_t		i2a_dh;

	CK_OBJECT_HANDLE	i2a_pubkey;
	CK_OBJECT_HANDLE	i2a_privkey;
	CK_OBJECT_HANDLE	i2a_dhkey;

	uint8_t			i2a_nonce_i[IKEV2_NONCE_MAX];
	uint8_t			i2a_nonce_r[IKEV2_NONCE_MAX];
	size_t			i2a_nonce_i_len;
	size_t			i2a_nonce_r_len;

	uint8_t			i2a_cookie[IKEV2_COOKIE_MAX];
	size_t			i2a_cookielen;

	uint8_t			*i2a_init_i;
	size_t			i2a_init_i_len;
	uint8_t			*i2a_init_r;
	size_t			i2a_init_r_len;

	ikev2_child_sa_state_t	i2a_child[2];	/* in, out */
	uint64_t		i2a_spi;
	boolean_t		i2a_is_auth;
} ikev2_sa_args_t;

ikev2_xf_auth_t ikev2_pfkey_to_auth(int);
ikev2_xf_encr_t ikev2_pfkey_to_encr(int);

boolean_t ikev2_sa_add_result(struct pkt_s *restrict,
    const ikev2_sa_match_t *restrict, uint64_t);
boolean_t ikev2_sa_from_rule(struct pkt_s *restrict,
    const struct config_rule *restrict, uint64_t);

boolean_t ikev2_sa_match_rule(struct config_rule *restrict,
    struct pkt_s *restrict, ikev2_sa_match_t *restrict, boolean_t);
boolean_t ikev2_sa_check_prop(struct config_rule *restrict,
    struct pkt_s *restrict, ikev2_sa_match_t *restrict, boolean_t);

char *ikev2_id_str(struct pkt_payload *restrict, char *restrict, size_t);

boolean_t ikev2_ke(ikev2_sa_args_t *restrict, struct pkt_s *restrict);
boolean_t ikev2_create_nonce(ikev2_sa_args_t *restrict, boolean_t, size_t);
void ikev2_save_nonce(ikev2_sa_args_t *restrict, struct pkt_s *restrict);

void ikev2_save_i2sa_results(struct ikev2_sa_s *restrict,
    ikev2_sa_match_t *restrict);
boolean_t ikev2_create_i2sa_keys(struct ikev2_sa_s *restrict, CK_OBJECT_HANDLE,
    uint8_t *restrict, size_t, uint8_t *restrict, size_t);

ikev2_sa_args_t *ikev2_sa_args_new(boolean_t);
void ikev2_sa_args_free(ikev2_sa_args_t *);

#ifdef __cplusplus
}
#endif

#endif /* _IKEV2_COMMON_H */
