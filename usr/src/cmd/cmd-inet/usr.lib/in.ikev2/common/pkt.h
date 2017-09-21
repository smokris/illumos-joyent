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

#include <note.h>
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
/*
 * All of the documented exchanges in RFC7296 use less than 16 payloads
 * in any given packet of an exchange.  However certain payloads (CERT,
 * CERTREQ, N, and V) can appear an arbitrary number of times in a packet.
 * Typically this would be if a large number of certificates are being
 * sent or requested in an exchange.  The value of 16 was chosen so
 * that most of the time, we won't need to use pkt_payload_extra to
 * hold additional indicies, and is a nice power of two.
 */
#define	PKT_PAYLOAD_NUM	(16)	/* usually don't need more than this */

typedef struct pkt_notify {
	uint8_t		*pn_ptr;	/* Start of payload data */
	uint32_t	pn_doi;		/* Ignored with IKEv2 */
	uint16_t	pn_len;		/* Excludes notify header + SPI */
	uint16_t	pn_type;
	uint8_t		pn_proto;
	uint64_t	pn_spi;
} pkt_notify_t;
/*
 * Similar to PKT_PAYLOAD_NUM, we choose a power of two that should be
 * larger than the typical number of notification payloads that would
 * appear in a packet of any given exchange.
 */
#define	PKT_NOTIFY_NUM	(8)

/*
 * RFC7296 Section 2 states that an implementation MUST accept
 * payloads up to 1280 octects long, and SHOULD be able to send,
 * receive, and support messages up to 3000 octets long.  We elect to
 * round this up to the next power of two (8192).  Similar to the
 * rational for the sizing of pkt_t.pkt_payloads and pkt_t.pkt_notify,
 * unless a large number of certificates or certificate requests are included
 * this should be more than enough, especially if the recommendation in RFC7296
 * of using "Hash and URL" formats for the CERT and CERTREQ payloads is
 * followed (instead of including the certificates and/or certificate chains).
 */
#define	MAX_PACKET_SIZE	(8192)
struct pkt_s {
				/* refheld */
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

				/* Payload index */
	pkt_payload_t		pkt_payloads[PKT_PAYLOAD_NUM];
	pkt_payload_t		*pkt_payload_extra;
	uint16_t		pkt_payload_count;
	uint16_t		pkt_payload_alloc;

	pkt_notify_t		pkt_notify[PKT_NOTIFY_NUM];
	pkt_notify_t		*pkt_notify_extra;
	uint16_t		pkt_notify_count;
	uint16_t		pkt_notify_alloc;

				/* Ready for transmit */
	boolean_t		pkt_done;
};

/* Used to help construct SA payloads */
typedef struct pkt_sa_state {
	pkt_t		*pss_pkt;	/* Packet in question */
	uint16_t	*pss_lenp;	/* Ptr to SA payload length field */
	pkt_payload_t	*pss_pld;	/* Ptr to SA payload index */
	ike_prop_t	*pss_prop;	/* Ptr to current proposal struct */
	ike_xform_t	*pss_xf;	/* Ptr to current xform struct */
} pkt_sa_state_t;

inline uint8_t *
pkt_start(pkt_t *pkt)
{
	return ((uint8_t *)&pkt->pkt_raw);
}

inline ike_header_t *
pkt_header(const pkt_t *pkt)
{
	return ((ike_header_t *)&pkt->pkt_raw);
}

inline size_t
pkt_len(const pkt_t *pkt)
{
	const uint8_t *start = (const uint8_t *)&pkt->pkt_raw;
	size_t len = (size_t)(pkt->pkt_ptr - start);

	VERIFY3P(pkt->pkt_ptr, >=, start);
	VERIFY3U(len, <=, MAX_PACKET_SIZE);
	return ((size_t)(pkt->pkt_ptr - start));
}

inline size_t
pkt_write_left(const pkt_t *pkt)
{
	return (MAX_PACKET_SIZE - pkt_len(pkt));
}

inline pkt_payload_t *
pkt_payload(pkt_t *pkt, uint16_t idx)
{
	VERIFY3U(idx, <, pkt->pkt_payload_count);
	if (idx < PKT_PAYLOAD_NUM)
		return (&pkt->pkt_payloads[idx]);
	return (pkt->pkt_payload_extra + (idx - PKT_PAYLOAD_NUM));
}

inline ike_payload_t *
pkt_idx_to_payload(pkt_payload_t *idxp)
{
	VERIFY3P(idxp->pp_ptr, !=, NULL);

	/*
	 * This _always_ points to the first byte after the ISAKMP/IKEV2
	 * payload header (empty payloads will have pp_len set to 0.
	 * ike_payload_t is defined as having byte alignment, so
	 * we can always backup up from pp_ptr to get to the payload
	 * header.
	 */
	ike_payload_t *pay = (ike_payload_t *)idxp->pp_ptr;
	return (pay - 1);
}

inline pkt_notify_t *
pkt_notify(pkt_t *pkt, uint16_t idx)
{
	VERIFY3U(idx, <, pkt->pkt_notify_count);
	if (idx < PKT_NOTIFY_NUM)
		return (&pkt->pkt_notify[idx]);
	return (pkt->pkt_notify_extra + (idx - PKT_NOTIFY_NUM));
}

inline void
put32(pkt_t *pkt, uint32_t val)
{
	BE_OUT32(pkt->pkt_ptr, val);
	pkt->pkt_ptr += sizeof (uint32_t);
}

inline void
put64(pkt_t *pkt, uint64_t val)
{
	BE_OUT64(pkt->pkt_ptr, val);
	pkt->pkt_ptr += sizeof (uint64_t);
}

#define	PKT_APPEND_STRUCT(_pkt, _struct)				\
do {									\
	VERIFY3U(pkt_write_left(_pkt), >=, sizeof (_struct));		\
	(void) memcpy((_pkt)->pkt_ptr, &(_struct), sizeof (_struct));	\
	(_pkt)->pkt_ptr += sizeof (_struct);				\
NOTE(CONSTCOND) } while (0)

#define	PKT_APPEND_DATA(_pkt, _ptr, _len)		\
do {							\
	if ((_len) == 0)				\
		break;					\
	VERIFY3U(pkt_write_left(_pkt), >=, (_len));	\
	(void) memcpy((_pkt)->pkt_ptr, (_ptr), (_len));	\
	(_pkt)->pkt_ptr += (_len);			\
NOTE(CONSTCOND) } while (0)

boolean_t pkt_done(pkt_t *);
void pkt_init(void);
void pkt_fini(void);
void pkt_free(pkt_t *);

pkt_payload_t *pkt_get_payload(pkt_t *, uint8_t, pkt_payload_t *);
pkt_notify_t *pkt_get_notify(pkt_t *, uint16_t, pkt_notify_t *);

#ifdef __cplusplus
}
#endif

#endif /* _PKT_H */
