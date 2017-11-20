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

#include <inttypes.h>
#include <bunyan.h>
#include <note.h>
#include "ikev2.h"

/*
 * All the payload checks take a pointer and length to the payload data i.e.
 * they exclude the payload header.  Though to (hopefully) be less confusing,
 * we report sizes including the payload header to reflect the value seen
 * or expected in the payload header.
 */

/* Cast to uint32_t so bunyan logging isn't full of casts */
#define	L(_len)	((uint32_t)((_len) + sizeof (ikev2_payload_t)))

#define	IKEV2_KE_MIN	((uint32_t)(sizeof (ikev2_ke_t) + 1))
boolean_t
ikev2_check_ke(const uint8_t *buf, size_t buflen)
{
	NOTE(ARGUNUSED(buf))

	if (buflen < IKEV2_KE_MIN) {
		(void) bunyan_warn(log,
		    "KE payload is smaller than absolute minimum",
		    BUNYAN_T_UINT32, "buflen", L(buflen),
		    BUNYAN_T_UINT32, "minimum", L(IKEV2_KE_MIN),
		    BUNYAN_T_END);
		return (B_FALSE);
	}

	return (B_TRUE);
}

boolean_t
ikev2_check_id(const uint8_t *buf, size_t buflen, boolean_t id_i)
{
	static const char id_i_min[] =
	    "IDi payload is smaller than absolute minimum";
	static const char id_r_min[] =
	    "IDr payload is smaller than absolute minimum";

	const ikev2_id_t *id = (const ikev2_id_t *)buf;

	if (buflen < sizeof (ikev2_id_t)) {
		(void) bunyan_warn(log, id_i ? id_i_min : id_r_min,
		    BUNYAN_T_UINT32, "buflen", L(buflen),
		    BUNYAN_T_UINT32, "minimum", L(sizeof (ikev2_id_t)),
		    BUNYAN_T_END);
		return (B_FALSE);
	}

	switch ((ikev2_id_type_t)id->id_type) {
	case IKEV2_ID_IPV4_ADDR:
	case IKEV2_ID_FQDN:
	case IKEV2_ID_RFC822_ADDR:
	case IKEV2_ID_IPV6_ADDR:
	case IKEV2_ID_DER_ASN1_DN:
	case IKEV2_ID_DER_ASN1_GN:
	case IKEV2_ID_KEY_ID:
	case IKEV2_ID_FC_NAME:
	}

	return (B_TRUE);
}
