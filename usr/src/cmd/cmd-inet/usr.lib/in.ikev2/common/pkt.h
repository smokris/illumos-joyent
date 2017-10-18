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

#include <net/pfkeyv2.h>
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
 * round this up to a power of two (8192).  Similar to the
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

uint8_t *pkt_start(const pkt_t *);
ike_header_t *pkt_header(const pkt_t *);
size_t pkt_len(const pkt_t *);
size_t pkt_write_left(const pkt_t *);
boolean_t put32(pkt_t *, uint32_t);
boolean_t put64(pkt_t *, uint64_t);
boolean_t pkt_append_data(pkt_t *restrict, const void *restrict, size_t);
boolean_t pkt_done(pkt_t *);
void pkt_init(void);
void pkt_fini(void);
void pkt_free(pkt_t *);
pkt_payload_t *pkt_get_payload(pkt_t *, uint8_t, pkt_payload_t *);
pkt_notify_t *pkt_get_notify(pkt_t *, uint16_t, pkt_notify_t *);

#define	PKT_APPEND_STRUCT(_pkt, _struct) \
	VERIFY(pkt_append_data(_pkt, &(_struct), sizeof (_struct)))

#ifdef __cplusplus
}
#endif

#endif /* _PKT_H */
