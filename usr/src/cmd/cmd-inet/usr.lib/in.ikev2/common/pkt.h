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

#include <sys/types.h>
#include "ike.h"
#include "ikev2.h"
#include "buf.h"

#ifdef __cplusplus
extern "C" {
#endif

struct ikev2_sa_s;
struct pkt_s;
struct pkt_stack_s;

typedef struct pkt_s		pkt_t;
typedef struct pkt_stack_s	pkt_stack_t;

typedef boolean_t (*pkt_finish_fn)(pkt_t *restrict, uint8_t *restrict,
    uintptr_t, size_t);

typedef enum pkt_stack_item_e {
	PSI_NONE,
	PSI_PACKET,
	PSI_SK,
	PSI_SA,
	PSI_PAYLOAD,
	PSI_PROP,
	PSI_XFORM,
	PSI_XFORM_ATTR,
	PSI_DEL,
	PSI_TSP,
	PSI_TS
} pkt_stack_item_t;

struct pkt_stack_s {
	pkt_finish_fn		stk_finish;
	uint8_t			*stk_ptr;
	size_t			stk_count;
	pkt_stack_item_t	stk_type;
};
#define	PKT_STACK_DEPTH	(6)	/* maximum depth needed */

typedef struct pkt_payload {
	uint8_t		*pp_ptr;
	uint16_t	pp_len;
	uint8_t		pp_type;
} pkt_payload_t;
#define	PKT_PAYLOAD_NUM	(16)	/* usually don't need more than this */

typedef struct pkt_notify {
	uint8_t		*pn_ptr;
	uint32_t	pn_doi;		/* Ignored with IKEv2 */
	uint16_t	pn_len;
	uint16_t	pn_type;
	uint8_t		pn_proto;
	uint64_t	pn_spi;
} pkt_notify_t;
#define	PKT_NOTIFY_NUM	(8)

#define	MAX_PACKET_SIZE	(8192)	/* largest datagram we accept */
struct pkt_s {
				/* NOT refheld */
	struct ikev2_sa_s	*pkt_sa;

				/* Raw packet data */
	uint64_t		pkt_raw[SADB_8TO64(MAX_PACKET_SIZE)];
				/*
				 * Points to one past last bit of valid data
				 * in pkt_raw
				 */
	uint8_t			*pkt_ptr;

				/* Copy of ISAKMP header in local byte order */
	ike_header_t		pkt_header;

	pkt_payload_t		pkt_payloads[PKT_PAYLOAD_NUM];
	pkt_payload_t		*pkt_payload_extra;
	uint16_t		pkt_payload_count;
	uint16_t		pkt_payload_alloc;

	pkt_notify_t		pkt_notify[PKT_NOTIFY_NUM];
	pkt_notify_t		*pkt_notify_extra;
	uint16_t		pkt_notify_count;
	uint16_t		pkt_notify_alloc;

	struct pkt_stack_s	stack[PKT_STACK_DEPTH];
	uint_t			stksize;
	boolean_t		pkt_stk_error;

	size_t			pkt_xmit;
};

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

#define	PKT_APPEND_STRUCT(_pkt, _struct) do {				\
	ASSERT3U(pkt_write_left(_pkt), <=, sizeof (_struct));		\
	(void) memcpy((_pkt)->pkt_ptr, &(_struct), sizeof (_struct));	\
	(_pkt)->pkt_ptr += sizeof (_struct);				\
/*CONSTCOND*/								\
} while (0)

#define	PKT_APPEND_DATA(_pkt, _ptr, _len) do {		\
	ASSERT3U(pkt_write_left(_pkt), <=, len);	\
	(void) memcpy((_pkt)->pkt_ptr, (_ptr), (_len));	\
	(_pkt)->pkt_ptr += (_len);			\
/*CONSTCOND*/						\
} while (0)

void pkt_hdr_ntoh(ike_header_t *restrict, const ike_header_t *restrict);
void pkt_hdr_hton(ike_header_t *restrict, const ike_header_t *restrict);
void put32(pkt_t *, uint32_t);
void put64(pkt_t *, uint64_t);

boolean_t pkt_done(pkt_t *);
void pkt_init(void);
void pkt_fini(void);
void pkt_free(pkt_t *);

boolean_t pkt_pay_shift(pkt_t *, uint8_t, size_t, ssize_t);
pkt_payload_t *pkt_get_payload(pkt_t *, int, pkt_payload_t *);
pkt_notify_t *pkt_get_notify(pkt_t *, int, pkt_notify_t *);

#ifdef __cplusplus
}
#endif

#endif /* _PKT_H */
