/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */

/*
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright 2017 Jason King.
 * Copyirght 2017 Joyent, Inc.
 */

#ifndef _PKT_H
#define	_PKT_H

#include <stddef.h>
#include <sys/types.h>
#include "ike.h"
#include "ikev2.h"

#ifdef __cplusplus
extern "C" {
#endif

struct ikev2_sa_s;
struct pkt_s;
struct pkt_stack_s;

typedef struct pkt_s		pkt_t;

/*
 * For both payload and notify indices, the pointers point to start of
 * the payload data, which immediately follows the respective headers.
 * If either type of index (more likely notify) has no associated data,
 * the length will equal zero, however the data pointer will still contain
 * the start of where the data would be if present.  This makes it possible
 * to still access the respective headers if necessary.
 */
typedef struct pkt_payload {
	uint8_t		*pp_ptr;	/* Start of payload data */
	uint16_t	pp_len;		/* Excludes payload header */
	uint8_t		pp_type;
} pkt_payload_t;
#define	PKT_PAYLOAD_NUM	(16)	/* usually don't need more than this */

typedef struct pkt_notify {
	uint8_t		*pn_ptr;	/* Start of payload data */
	uint32_t	pn_doi;		/* Ignored with IKEv2 */
	uint16_t	pn_len;		/* Excludes notify header + SPI */
	uint16_t	pn_type;
	uint8_t		pn_proto;
	uint64_t	pn_spi;
} pkt_notify_t;
#define	PKT_NOTIFY_NUM	(8)

#define	MAX_PACKET_SIZE	(8192)	/* largest datagram we accept */
struct pkt_s {
				/* NOT refheld */
	struct ikev2_sa_s	*pkt_sa;

				/* Transmit count */
	size_t			pkt_xmit;

				/* Raw packet data */
	uint64_t		pkt_raw[SADB_8TO64(MAX_PACKET_SIZE)];

				/*
				 * Points to one past last bit of valid data
				 * in pkt_raw
				 */
	uint8_t			*pkt_ptr;

				/* Copy of ISAKMP header in local byte order */
	ike_header_t		pkt_header;

				/* Payload index */
	pkt_payload_t		pkt_payloads[PKT_PAYLOAD_NUM];
	pkt_payload_t		*pkt_payload_extra;
	uint16_t		pkt_payload_count;
	uint16_t		pkt_payload_alloc;

	pkt_notify_t		pkt_notify[PKT_NOTIFY_NUM];
	pkt_notify_t		*pkt_notify_extra;
	uint16_t		pkt_notify_count;
	uint16_t		pkt_notify_alloc;

				/* Set once we've added an encrypted payload */
	pkt_payload_t		*pkt_encr_pay;

				/* Ready for transmit */
	boolean_t		pkt_done;
};

typedef struct pkt_sa_state {
	pkt_t		*pss_pkt;
	uint16_t	*pss_lenp;
	pkt_payload_t	*pss_pld;
	ike_prop_t	*pss_prop;
	ike_xform_t	*pss_xf;
} pkt_sa_state_t;

inline uint8_t *
pkt_start(pkt_t *pkt)
{
	return ((uint8_t *)&pkt->pkt_raw);
}

inline size_t
pkt_len(const pkt_t *pkt)
{
	const uint8_t *start = (const uint8_t *)&pkt->pkt_raw;
	size_t len = (size_t)(pkt->pkt_ptr - start);

	ASSERT3P(pkt->pkt_ptr, >=, start);
	ASSERT3U(len, <=, MAX_PACKET_SIZE);
	return ((size_t)(pkt->pkt_ptr - start));
}

inline size_t
pkt_write_left(const pkt_t *pkt)
{
	return (MAX_PACKET_SIZE - pkt_len(pkt));
}

inline size_t
pkt_read_left(const pkt_t *pkt, const uint8_t *ptr)
{
	const uint8_t *start = (const uint8_t *)&pkt->pkt_raw;
	ASSERT3P(ptr, >=, start);
	ASSERT3P(ptr, <=, pkt->pkt_ptr);
	return ((size_t)(pkt->pkt_ptr - ptr));
}

inline pkt_payload_t *
pkt_payload(pkt_t *pkt, uint16_t idx)
{
	ASSERT3U(idx, <, pkt->pkt_payload_count);
	if (idx < PKT_PAYLOAD_NUM)
		return (&pkt->pkt_payloads[idx]);
	return (pkt->pkt_payload_extra + (idx - PKT_PAYLOAD_NUM));
}

inline pkt_notify_t *
pkt_notify(pkt_t *pkt, uint16_t idx)
{
	ASSERT3U(idx, <, pkt->pkt_notify_count);
	if (idx < PKT_NOTIFY_NUM)
		return (&pkt->pkt_notify[idx]);
	return (pkt->pkt_notify_extra + (idx - PKT_NOTIFY_NUM));
}

inline void
pkt_adv_ptr(pkt_t *pkt, size_t amt)
{
	ike_header_t *hdr = (ike_header_t *)&pkt->pkt_raw;

	/*
	 * The layout of ike_header_t and pkt->pkt_raw currently guarantees
	 * this alignment
	 */
	ASSERT(I2_P2ALIGNED(&hdr->length, sizeof (uint32_t)));

	pkt->pkt_ptr += amt;
	pkt->pkt_header.length += amt;
	hdr->length = htonl(pkt->pkt_header.length);

	/* However no alignment guarantees for this unfortunately */
	if (pkt->pkt_encr_pay != NULL) {
		ike_payload_t *ip = ((ike_payload_t *)pkt->pkt_encr_pay) - 1;
		uint16_t val = BE_IN16(&ip->pay_length) + amt;

		BE_OUT16(&ip->pay_length, val);
		pkt->pkt_encr_pay->pp_len += amt;
	}
}

inline void
put32(pkt_t *pkt, uint32_t val)
{
	BE_OUT32(pkt->pkt_ptr, val);
	pkt_adv_ptr(pkt, sizeof (uint32_t));
}

inline void
put64(pkt_t *pkt, uint64_t val)
{
	BE_OUT64(pkt->pkt_ptr, val);
	pkt_adv_ptr(pkt, sizeof (uint64_t));
}

#define	PKT_APPEND_STRUCT(_pkt, _struct)				\
do {									\
	VERIFY3U(pkt_write_left(_pkt), >=, sizeof (_struct));		\
	(void) memcpy((_pkt)->pkt_ptr, &(_struct), sizeof (_struct));	\
	pkt_adv_ptr(_pkt, sizeof (_struct));				\
/*CONSTCOND*/								\
} while (0)

#define	PKT_APPEND_DATA(_pkt, _ptr, _len)		\
do {							\
	if ((_len) == 0)				\
		break;					\
	VERIFY3U(pkt_write_left(_pkt), >=, (_len));	\
	(void) memcpy((_pkt)->pkt_ptr, (_ptr), (_len));	\
	pkt_adv_ptr(_pkt, (_len));			\
/*CONSTCOND*/						\
} while (0)

void pkt_hdr_ntoh(ike_header_t *restrict, const ike_header_t *restrict);
void pkt_hdr_hton(ike_header_t *restrict, const ike_header_t *restrict);

boolean_t pkt_done(pkt_t *);
void pkt_init(void);
void pkt_fini(void);
void pkt_free(pkt_t *);

pkt_payload_t *pkt_get_payload(pkt_t *, int, pkt_payload_t *);
pkt_notify_t *pkt_get_notify(pkt_t *, int, pkt_notify_t *);

#ifdef __cplusplus
}
#endif

#endif /* _PKT_H */
