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
 * Copyright 2017 Jason King.
 * Copyright 2017 Joyent, Inc.
 */
#include <stddef.h>
#include <assert.h>
#include <umem.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/byteorder.h>
#include <ipsec_util.h>
#include <locale.h>
#include <netinet/in.h>
#include <security/cryptoki.h>
#include <errno.h>
#include <sys/socket.h>
#include <pthread.h>
#include <sys/debug.h>
#include <note.h>
#include <err.h>
#include <limits.h>
#include <bunyan.h>
#include "ikev1.h"
#include "ikev2.h"
#include "ikev2_sa.h"
#include "pkt.h"
#include "pkt_impl.h"
#include "pkcs11.h"

static umem_cache_t	*pkt_cache;

static size_t pkt_item_rank(pkt_stack_item_t);
static boolean_t pkt_finish(pkt_t *restrict, uint8_t *restrict, uintptr_t,
    size_t);
static int pkt_reset(void *);

pkt_t *
pkt_out_alloc(uint64_t i_spi, uint64_t r_spi, uint8_t version,
    uint8_t exch_type, uint32_t msgid)
{
	pkt_t *pkt = umem_cache_alloc(pkt_cache, UMEM_DEFAULT);

	if (pkt == NULL)
		return (NULL);

	pkt->pkt_header.initiator_spi = i_spi;
	pkt->pkt_header.responder_spi = r_spi;
	pkt->pkt_header.version = version;
	pkt->pkt_header.exch_type = exch_type;
	pkt->pkt_header.msgid = msgid;

	/*
	 * Skip over bytes in pkt->raw for the header -- we keep
	 * pkt->header (the local byte order copy) updated and then
	 * write out the final version (in network byte order) in this
	 * space once we're done building the packet by stacking a
	 * finish callback before anything else.
	 */
	pkt_stack_push(pkt, PSI_PACKET, pkt_finish, 0);
	pkt->pkt_ptr += sizeof (ike_header_t);
	return (pkt);
}

static boolean_t
pkt_finish(pkt_t *restrict pkt, uint8_t *restrict ptr, uintptr_t swaparg,
    size_t numpay)
{
	NOTE(ARGUNUSED(swaparg, numpay))

	ike_header_t *rawhdr;

	rawhdr = (ike_header_t *)ptr;
	pkt->pkt_header.length = pkt_len(pkt);
	pkt_hdr_hton(rawhdr, &pkt->pkt_header);
	return (B_TRUE);
}

static pkt_walk_ret_t
pkt_index_cb(uint8_t paytype, uint8_t resv, uint8_t *restrict ptr, size_t len,
    void *restrict cookie)
{
	pkt_t *pkt = cookie;

	if (!pkt_add_index(pkt, paytype, ptr, len))
		return (PKT_WALK_ERROR);
	return (PKT_WALK_OK);
}

boolean_t
pkt_index_payloads(pkt_t *pkt, uint8_t *buf, size_t buflen, uint8_t first,
    bunyan_logger_t *restrict l)
{
	VERIFY3P(pkt_start(pkt), <, buf);
	VERIFY3P(pkt->pkt_ptr, >=, buf + buflen);

	if (pkt_payload_walk(buf, buflen, pkt_index_cb, first,
	    pkt, l) != PKT_WALK_OK)
		return (B_FALSE);
	return (B_TRUE);
}

#define	PKT_CHUNK_SZ	(8)
boolean_t
pkt_add_index(pkt_t *pkt, uint8_t type, uint8_t *buf, uint16_t buflen)
{
	pkt_payload_t *pay = NULL;
	ssize_t idx = pkt->pkt_payload_count - PKT_PAYLOAD_NUM;

	if (pkt->pkt_payload_count < PKT_PAYLOAD_NUM) {
		VERIFY3S(idx, <, 0);
		pay = &pkt->pkt_payloads[pkt->pkt_payload_count];
	} else if (idx < pkt->pkt_payload_alloc) {
		VERIFY3S(idx, >=, 0);
		pay = &pkt->pkt_payload_extra[idx];
	} else {
		pkt_payload_t *newpay = NULL;
		size_t newsz = pkt->pkt_payload_alloc + PKT_CHUNK_SZ;
		size_t amt = newsz * sizeof (pkt_payload_t);

		VERIFY3U(amt, <, newsz);
		VERIFY3U(amt, <=, sizeof (pkt_payload_t));

		newpay = umem_zalloc(amt, UMEM_DEFAULT);
		if (newpay == NULL)
			return (B_FALSE);

		if (pkt->pkt_payload_extra != NULL) {
			/*
			 * If the new size doesn't overflow, the original,
			 * smaller size cannot either.
			 */
			(void) memcpy(newpay, pkt->pkt_payload_extra,
			    pkt->pkt_payload_count * sizeof (pkt_payload_t));
			umem_free(pkt->pkt_payload_extra,
			    pkt->pkt_payload_alloc * sizeof (pkt_payload_t));
		}

		pkt->pkt_payload_extra = newpay;
		pkt->pkt_payload_alloc = newsz;

		VERIFY3S(idx, >=, 0);
		pay = &pkt->pkt_payload_extra[idx];
	}

	pkt->pkt_payload_count++;
	pay->pp_type = type;
	pay->pp_ptr = buf;
	pay->pp_len = buflen;
	return (B_TRUE);
}

boolean_t
pkt_add_nindex(pkt_t *pkt, uint16_t type, uint8_t *buf, size_t buflen)
{
	pkt_notify_t *n = NULL;
	ssize_t idx = pkt->pkt_notify_count - PKT_NOTIFY_NUM;

	if (pkt->pkt_notify_count < PKT_NOTIFY_NUM) {
		VERIFY3S(idx, <, 0);
		n = &pkt->pkt_notify[pkt->pkt_notify_count];
	} else if (idx < pkt->pkt_notify_alloc) {
		VERIFY3S(idx, >=, 0);
		n = &pkt->pkt_notify_extra[idx];
	} else {
		pkt_notify_t *newn = NULL;
		size_t newsz = pkt->pkt_notify_alloc + PKT_CHUNK_SZ;
		size_t amt = newsz * sizeof (pkt_notify_t);

		VERIFY3U(amt, <, newsz);
		VERIFY3U(amt, <=, sizeof (pkt_notify_t));

		newn = umem_zalloc(amt, UMEM_DEFAULT);
		if (newn == NULL)
			return (B_FALSE);

		if (pkt->pkt_notify_extra != NULL) {
			(void) memcpy(newn, pkt->pkt_notify_extra,
			    pkt->pkt_notify_count * sizeof (pkt_notify_t));
			umem_free(pkt->pkt_notify_extra,
			    pkt->pkt_notify_alloc * sizeof (pkt_notify_t));
		}

		pkt->pkt_notify_extra = newn;
		pkt->pkt_notify_alloc = newsz;

		VERIFY3S(idx, >=, 0);
		n = &pkt->pkt_notify_extra[idx];
	}

	pkt->pkt_notify_count++;
	n->pn_type = type;
	n->pn_ptr = buf;
	n->pn_len = buflen;
	return (B_TRUE);
}

/*
 * Allocate an pkt_t for an inbound packet, populate the local byte order
 * header, and cache the location of the payloads in the payload field.
 */
pkt_t *
pkt_in_alloc(uint8_t *restrict buf, size_t buflen, bunyan_logger_t *restrict l)
{
	ike_header_t *hdr = (ike_header_t *)buf;
	pkt_t *pkt = NULL;
	uint8_t first;

	/* If inbound checks didn't catch these, it's a bug */
	VERIFY3U(buflen, >=, sizeof (ike_header_t));
	VERIFY3U(buflen, ==, ntohl(hdr->length));
	VERIFY3U(buflen, <=, MAX_PACKET_SIZE);

	first = hdr->next_payload;
	buf += sizeof (*hdr);
	buflen -= sizeof (*hdr);

	if ((pkt = umem_cache_alloc(pkt_cache, UMEM_DEFAULT)) == NULL) {
		STDERR(error, l, "umem_cache_alloc failed");
		return (NULL);
	}

	(void) memcpy(&pkt->pkt_raw, buf, buflen);
	pkt_hdr_ntoh(&pkt->pkt_header, (const ike_header_t *)&pkt->pkt_raw);
	pkt->pkt_ptr += buflen;

	if (!pkt_index_payloads(pkt, pkt_start(pkt), pkt_len(pkt), first, l)) {
		pkt_free(pkt);
		return (NULL);
	}

	return (pkt);
}

static boolean_t
payload_finish(pkt_t *restrict pkt, uint8_t *restrict ptr, uintptr_t arg,
    size_t numsub)
{
	NOTE(ARGUNUSED(numsub))
	ike_payload_t pay = { 0 };
	size_t len = (size_t)(pkt->pkt_ptr - ptr);

	VERIFY3P(pkt->pkt_ptr, >, ptr);
	VERIFY3U(len, <, MAX_PACKET_SIZE);
	VERIFY3U(arg, <, 256);

	(void) memcpy(&pay, ptr, sizeof (pay));
	pay.pay_next = (uint8_t)arg;
	pay.pay_length = htons((uint16_t)len);
	(void) memcpy(ptr, &pay, sizeof (pay));
	return (B_TRUE);
}

boolean_t
pkt_add_payload(pkt_t *pkt, uint8_t ptype, uint8_t resv)
{
	ike_payload_t pay = { 0 };

	if (pkt_write_left(pkt) < sizeof (pay))
		return (B_FALSE);

	/* Special case for first payload */
	if (pkt->pkt_ptr - (uint8_t *)&pkt->pkt_raw == sizeof (ike_header_t))
		pkt->pkt_header.next_payload = (uint8_t)ptype;

	/*
	 * Otherwise we'll set it when we replace the current top of
	 * the stack
	 */
	pkt_stack_item_t type =
	    (ptype == IKEV2_PAYLOAD_SA) ? PSI_SA : PSI_PAYLOAD;
	pkt_stack_push(pkt, type, payload_finish, (uintptr_t)ptype);
	pay.pay_next = IKE_PAYLOAD_NONE;
	pay.pay_reserved = resv;
	PKT_APPEND_STRUCT(pkt, pay);
	return (B_TRUE);
}

static boolean_t prop_finish(pkt_t *restrict, uint8_t *restrict, uintptr_t,
    size_t);

boolean_t
pkt_add_prop(pkt_t *pkt, uint8_t propnum, uint8_t proto, size_t spilen,
    uint64_t spi)
{
	ike_prop_t	prop = { 0 };

	if (pkt_write_left(pkt) < sizeof (prop) + spilen)
		return (B_FALSE);

	pkt_stack_push(pkt, PSI_PROP, prop_finish, (uintptr_t)IKE_PROP_MORE);

	prop.prop_more = IKE_PROP_NONE;
	prop.prop_num = propnum;
	prop.prop_proto = (uint8_t)proto;
	prop.prop_spilen = spilen;
	PKT_APPEND_STRUCT(pkt, prop);

	switch (spilen) {
	case sizeof (uint32_t):
		VERIFY3U(spi, <=, UINT_MAX);
		put32(pkt, (uint32_t)spi);
		break;
	case sizeof (uint64_t):
		put64(pkt, spi);
		break;
	case 0:
		break;
	default:
		INVALID(spilen);
	}

	return (B_TRUE);
}

static boolean_t
prop_finish(pkt_t *restrict pkt, uint8_t *restrict ptr, uintptr_t more,
    size_t numxform)
{
	ike_prop_t	prop = { 0 };
	ptrdiff_t	len = pkt->pkt_ptr - ptr;

	VERIFY3U(len, <=, USHRT_MAX);
	VERIFY3U(numxform, <, 256);

	(void) memcpy(&prop, ptr, sizeof (prop));
	prop.prop_more = (uint8_t)more;
	prop.prop_len = htons((uint16_t)len);
	prop.prop_numxform = (uint8_t)numxform;
	(void) memcpy(ptr, &prop, sizeof (prop));
	return (B_TRUE);
}

static boolean_t pkt_xform_finish(pkt_t *restrict, uint8_t *restrict, uintptr_t,
    size_t);

boolean_t
pkt_add_xform(pkt_t *pkt, uint8_t xftype, uint16_t xfid)
{
	ike_xform_t	xf = { 0 };

	if (pkt_write_left(pkt) < sizeof (xf))
		return (B_FALSE);

	pkt_stack_push(pkt, PSI_XFORM, pkt_xform_finish,
	    (uintptr_t)IKE_XFORM_MORE);

	ASSERT3U(xfid, <, USHRT_MAX);

	/* mostly for completeness */
	xf.xf_more = IKE_XFORM_NONE;
	xf.xf_type = xftype;
	xf.xf_id = htons(xfid);
	PKT_APPEND_STRUCT(pkt, xf);
	return (B_TRUE);
}

static boolean_t
pkt_xform_finish(pkt_t *restrict pkt, uint8_t *restrict ptr, uintptr_t more,
    size_t numattr)
{
	ike_xform_t	xf = { 0 };
	ptrdiff_t	len = pkt->pkt_ptr - ptr;

	VERIFY3U(len, <=, USHRT_MAX);
	(void) memcpy(&xf, ptr, sizeof (xf));
	xf.xf_more = more;
	xf.xf_len = htons((uint16_t)len);
	(void) memcpy(ptr, &xf, sizeof (xf));
	return (B_TRUE);
}

boolean_t
pkt_add_xform_attr_tv(pkt_t *pkt, uint16_t type, uint16_t val)
{
	ike_xf_attr_t	attr = { 0 };

	VERIFY3U(type, <, 0x8000);
	VERIFY3U(val, <, 0x10000);

	if (pkt_write_left(pkt) < sizeof (attr))
		return (B_FALSE);

	pkt_stack_push(pkt, PSI_XFORM_ATTR, NULL, 0);
	attr.attr_type = htons(IKE_ATTR_TYPE(IKE_ATTR_TV, type));
	attr.attr_len = htons(val);
	PKT_APPEND_STRUCT(pkt, attr);
	return (B_TRUE);
}

boolean_t
pkt_add_xform_attr_tlv(pkt_t *pkt, uint16_t type, const uint8_t *attrp,
    size_t attrlen)
{
	ike_xf_attr_t attr = { 0 };

	VERIFY3U(type, <, 0x8000);
	VERIFY3U(attrlen, <, 0x10000);

	if (pkt_write_left(pkt) < sizeof (attr) + attrlen)
		return (B_FALSE);

	pkt_stack_push(pkt, PSI_XFORM_ATTR, NULL, 0);
	attr.attr_type = htons(IKE_ATTR_TYPE(IKE_ATTR_TLV, type));
	attr.attr_len = htons(attrlen);
	PKT_APPEND_STRUCT(pkt, attr);
	(void) memcpy(pkt->pkt_ptr, attrp, attrlen);
	pkt->pkt_ptr += attrlen;
	return (B_TRUE);
}

boolean_t
pkt_add_cert(pkt_t *restrict pkt, uint8_t encoding, const uint8_t *data,
    size_t datalen)
{
	if (pkt_write_left(pkt) < 1 + datalen)
		return (B_FALSE);

	*(pkt->pkt_ptr++) = encoding;
	(void) memcpy(pkt->pkt_ptr, data, datalen);
	pkt->pkt_ptr += datalen;
	return (B_TRUE);
}

void
pkt_hdr_ntoh(ike_header_t *restrict dest,
    const ike_header_t *restrict src)
{
	ASSERT(IS_P2ALIGNED(dest, sizeof (uint64_t)));
	ASSERT(IS_P2ALIGNED(src, sizeof (uint64_t)));
	ASSERT3P(src, !=, dest);

	dest->initiator_spi = ntohll(src->initiator_spi);
	dest->responder_spi = ntohll(src->responder_spi);
	dest->msgid = ntohl(src->msgid);
	dest->length = ntohl(src->length);
	dest->next_payload = src->next_payload;
	dest->exch_type = src->exch_type;
	dest->flags = src->flags;
	dest->version = src->version;
}

void
pkt_hdr_hton(ike_header_t *restrict dest,
    const ike_header_t *restrict src)
{
	ASSERT(IS_P2ALIGNED(dest, sizeof (uint64_t)));
	ASSERT(IS_P2ALIGNED(src, sizeof (uint64_t)));
	ASSERT3P(src, !=, dest);

	dest->initiator_spi = htonll(src->initiator_spi);
	dest->responder_spi = htonll(src->responder_spi);
	dest->msgid = htonl(src->msgid);
	dest->length = htonl(src->length);
	dest->next_payload = src->next_payload;
	dest->exch_type = src->exch_type;
	dest->flags = src->flags;
	dest->version = src->version;
}

/*
 * Move all the payloads over amt to insert a payload at the front of the
 * packet.  Currently used for IKEV2 cookies.
 */
boolean_t
pkt_pay_shift(pkt_t *pkt, uint8_t type, size_t num, ssize_t amt)
{
	uint8_t *start = pkt_start(pkt) + sizeof (ike_header_t);
	pkt_payload_t *pay = NULL;

	if (amt > 0 && pkt_write_left(pkt) < amt)
		return (B_FALSE);

	if (num > 0) {
		VERIFY3S(amt, >, 0);
		if (!pkt_add_index(pkt, type, start, (uint16_t)amt))
			return (B_FALSE);
	}

	/* Shift the data in the packet */
	(void) memmove(start + amt, start, pkt_len(pkt));

	/* Adjust index pointers, except for the one we just added */
	for (uint16_t i = 0; i < pkt->pkt_payload_count - 1; i++) {
		pay = pkt_payload(pkt, i);
		pay->pp_ptr += amt;
	}
	pkt->pkt_ptr += amt;

	if (num == 0 || pkt->pkt_payload_count == 1)
		return (B_TRUE);

	pkt_payload_t save = { 0 };
	pay = pkt_payload(pkt, pkt->pkt_payload_count - 1);
	save = *pay;

	/* Move indexes over to make room */
	if (pkt->pkt_payload_count > PKT_PAYLOAD_NUM) {
		(void) memmove(pkt->pkt_payload_extra + 1,
		    pkt->pkt_payload_extra,
		    sizeof (pkt_payload_t) *
		    (pkt->pkt_payload_count - PKT_PAYLOAD_NUM - 1));
		(void) memcpy(pkt->pkt_payload_extra,
		    &pkt->pkt_payloads[PKT_PAYLOAD_NUM - 1],
		    sizeof (pkt_payload_t));
	}
	(void) memmove(pkt->pkt_payloads + 1, pkt->pkt_payloads,
	    (PKT_PAYLOAD_NUM - 1) * sizeof (pkt_payload_t));
	pkt->pkt_payloads[0] = save;

	/* Keep the two in sync for sanity's sake */
	ike_header_t *hdr = (ike_header_t *)pkt_start(pkt);
	ike_payload_t pld = {
		.pay_next = pkt->pkt_header.next_payload,
		.pay_length = (uint16_t)amt
	};
	pkt->pkt_header.next_payload = hdr->next_payload = type;

	(void) memcpy(start, &pld, sizeof (pld));
	pkt->pkt_ptr += amt;
	return (B_TRUE);
}

/*
 * The packet structure of both IKEv1 and IKEv2 consists of a packet with
 * a header that contains a possibly arbitrary number of payloads.  Certain
 * payloads can contain an arbitrary number of sub structures.  Some of those
 * substructures can themselves contain a potentially arbitrary number of
 * sub-sub structures.
 *
 * One of the vexing aspects of the IKE specification is that the design of
 * these structures makes it cumbersome to know a priori what some of the values
 * should be until all the embedded structures have been added.  For example
 * the payload header looks like this (taken from RFC 7296):
 *
 *                    1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * | Next Payload  |C|  RESERVED   |         Payload Length        |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 * The 'next payload' field (the type of payload in the payload structure
 * that immediately follows this payload)  cannot be set until it is known
 * what the * next payload will be (if any).  Similarly, the length of the
 * current payload cannot be easily calculated until all embedded structures
 * for this payload are known.  As Bruce Schneier et. al. have pointed out,
 * this design is overly complicated and does not provide any improvement in
 * security.  However, we are (sadly) stuck with it.
 *
 * To keep the code involved in a given exchange from being buried in
 * loads of complicated tedium dealing with this, we have created a
 * hopefully not too clever way to handle setting those fields so
 * the exhanging handling code rarely needs to worry about it.  It allows
 * for code similar to:
 *
 * ikev2_add_sa(pkt, ...);
 * ikev2_add_proposal(pkt, IKEV2_PROTO_ESP, ...);
 * ikev2_add_xform(pkt, IKEV2_XF_ENCR, IKEV2_ENCR_AES_CBC);
 * ikev2_add_xform_attr(pkt, IKEV2_XF_ATTR_KEYLEN, 256)
 * ikev2_add_nonce(pkt, ....)
 * ...
 * ikev2_send(pkt, ...);
 *
 * For any of the IKE structures, generally one or more of the following
 * questions cannot be answered until subsequent structures are added:
 *
 * 	1. Some sort of information about the next structure of the same
 * 	type (e.g. type of the next payload, if another proposal is present
 * 	after the current proposal, etc).
 * 	2. What is the size of this structure (with all embedded structures)?
 * 	3. How many substructures are present in this structure?
 *
 * To be able to answer these questions, the general approach is that
 * information about the state of the datagram at the time a structure is
 * appeneded is saved in the pkt_t, and a post-processing function/callback is
 * invoked after any embedded structures have been added.  This callback
 * is given the number of embedded structures that have been added, as well as
 * the position of the start of the structure this callback is invoked for.
 * This allows the callback to determine both the size of the structure
 * as well as the number of substructures.  In addition, an argument given
 * while pushing a subsequent structure of the same type (payload, xform, etc)
 * is passed to the callback -- this allows the callback to answer question
 * #1 e.g. when pushing a new payload, it's type is the argument that's
 * given to the callback invoked for the previous payload.
 *
 * To make this all work, each type of structure is assigned a 'rank' for
 * lack of a better term (suggestions welcome).  Lower ranked structures can
 * embed compatible higher ranked structures.  Since IKE structures cannot
 * embed themselves, when we attempt to append a structure of equal or lower
 * rank to the last structure appended, we know we are done embedding
 * structures into the previous structure of equal or lower rank. If we are
 * adding a structure of higher rank than the last structure added, we know we
 * are embedding a structure.  If it's the same rank, we are pushing a simiar
 * type of object and should bump the count of objects.
 */

static size_t
pkt_item_rank(pkt_stack_item_t type)
{
	switch (type) {
	case PSI_NONE:
		return (0);
	case PSI_PACKET:
		return (1);
	case PSI_SK:
		return (2);
	/*
	 * same rank, but distinct to allow verification that SA payloads
	 * can only occur either at the start of a datagram, or as the
	 * first item inside an SK payload
	 */
	case PSI_SA:
	case PSI_PAYLOAD:
		return (3);
	case PSI_DEL:
	case PSI_TSP:
	case PSI_PROP:
		return (4);
	case PSI_TS:
	case PSI_XFORM:
		return (5);
	case PSI_XFORM_ATTR:
		return (6);
	}
	/*NOTREACHED*/
	return (SIZE_MAX);
}

static boolean_t
pkt_stack_empty(pkt_t *pkt)
{
	return (pkt->stksize == 0 ? B_TRUE : B_FALSE);
}

static pkt_stack_t *
pkt_stack_top(pkt_t *pkt)
{
	if (pkt_stack_empty(pkt))
		return (NULL);
	return (&pkt->stack[pkt->stksize - 1]);
}

static pkt_stack_t *
pkt_stack_pop(pkt_t *pkt)
{
	if (pkt_stack_empty(pkt))
		return (NULL);
	return (&pkt->stack[--pkt->stksize]);
}

static int
pkt_stack_rank(pkt_t *pkt)
{
	pkt_stack_t *stk = pkt_stack_top(pkt);
	pkt_stack_item_t type = (stk != NULL) ? stk->stk_type : PSI_NONE;

	return (pkt_item_rank(type));
}

static size_t pkt_stack_unwind(pkt_t *, pkt_stack_item_t, uintptr_t);

/*
 * Save structure information as we append a new payload
 * Args:
 * 	pkt	The packet in question
 * 	type	The type of structure being added
 * 	finish	The post-processing callback to run for this structure
 * 	swaparg	The argument passed to the callback function of the previous
 * 		post-processing callback for the same type of structure.
 */
void
pkt_stack_push(pkt_t *pkt, pkt_stack_item_t type, pkt_finish_fn finish,
    uintptr_t swaparg)
{
	pkt_stack_t	*stk;
	size_t		count;
	pkt_stack_item_t top_type = PSI_NONE;

	if (pkt_stack_top(pkt) != NULL)
		top_type = pkt_stack_top(pkt)->stk_type;

	/*
	 * If we're adding stuff in the wrong spot, that's a very egregious
	 * bug, so die if we do
	 */
	switch (type) {
	case PSI_PACKET:
		VERIFY3S(top_type, ==, PSI_NONE);
		break;
	case PSI_SK:
		VERIFY3S(top_type, ==, PSI_PACKET);
		break;
	case PSI_SA:
		VERIFY(top_type == PSI_PACKET || top_type == PSI_SK);
		break;
	case PSI_PAYLOAD:
		VERIFY(top_type != PSI_PACKET && top_type != PSI_NONE);
		break;
	case PSI_PROP:
		VERIFY(top_type == PSI_SA || top_type == PSI_PROP ||
		    top_type == PSI_XFORM || top_type == PSI_XFORM_ATTR);
		break;
	case PSI_XFORM:
		VERIFY(top_type == PSI_XFORM || top_type == PSI_PROP ||
		    top_type == PSI_XFORM_ATTR);
		break;
	case PSI_XFORM_ATTR:
		VERIFY(top_type == PSI_XFORM || top_type == PSI_XFORM_ATTR);
		break;
	case PSI_DEL:
		VERIFY(top_type == PSI_SA || top_type == PSI_DEL);
		break;
	case PSI_TSP:
		VERIFY3U(top_type, ==, PSI_SA);
		break;
	case PSI_TS:
		VERIFY(top_type == PSI_TSP || top_type == PSI_TS);
		break;
	case PSI_NONE:
		INVALID("type");
		break;
	}

	count = pkt_stack_unwind(pkt, type, swaparg);

	ASSERT3U(pkt_stack_rank(pkt), <, pkt_item_rank(type));
	ASSERT3U(pkt->stksize, <, PKT_STACK_DEPTH);

	stk = &pkt->stack[pkt->stksize++];

	stk->stk_finish = finish;
	stk->stk_ptr = pkt->pkt_ptr;
	stk->stk_count = count + 1;
	stk->stk_type = type;
}

/*
 * This is where the magic happens.  Pop off what's saved in pkt->stack
 * and run all the post processing until the rank of the top item in
 * the stack is lower than the rank of what we're about to add (contained in
 * type).  Return the running count of structures of the same rank as type.
 */
static size_t
pkt_stack_unwind(pkt_t *pkt, pkt_stack_item_t type, uintptr_t swaparg)
{
	pkt_stack_t	*stk = NULL;
	size_t		count = 0;
	size_t		rank = pkt_item_rank(type);
	size_t		stk_rank = 0;

	while (!pkt_stack_empty(pkt) &&
	    (stk_rank = pkt_stack_rank(pkt)) >= rank) {
		stk = pkt_stack_pop(pkt);
		if (stk->stk_finish != NULL) {
			boolean_t ret;

			ret = stk->stk_finish(pkt, stk->stk_ptr,
			    (stk_rank == rank) ? swaparg : 0, count);
			pkt->pkt_stk_error |= !ret;
		}

		/*
		 * This was initialized to 0, and is deliberately set after
		 * calling the post-processing callback so that the
		 * post-processing callback called in the next iteration
		 * of the loop (if it happens) gets the count of embedded
		 * structures (e.g. proposal post-processing function gets
		 * the count of embedded transform structures).
		 */
		count = stk->stk_count;
	}

	ASSERT3U(pkt_stack_rank(pkt), <, rank);

	if (stk != NULL && stk_rank == rank)
		return (stk->stk_count);
	return (0);
}

/* pops off all the callbacks in preparation for sending */
boolean_t
pkt_done(pkt_t *pkt)
{
	(void) pkt_stack_unwind(pkt, PSI_NONE, 0);
	return (pkt->pkt_stk_error);
}

/*
 * Call cb on each encountered payload.
 * data - the first payload to walk
 * len - total size of the buffer to walk (should end on payload boundary)
 * cb - callback function to invoke on each payload
 * first - payload type of the first payload
 * cookie - data passed to callback
 */
pkt_walk_ret_t
pkt_payload_walk(uint8_t *restrict data, size_t len, pkt_walk_fn_t cb,
    uint8_t first, void *restrict cookie, bunyan_logger_t *restrict l)
{
	uint8_t			*ptr = data;
	uint8_t			paytype = first;
	pkt_walk_ret_t		ret = PKT_WALK_OK;

	/* 0 is used for both IKEv1 and IKEv2 to indicate last payload */
	while (len > 0 && paytype != 0) {
		ike_payload_t pay = { 0 };

		if (len < sizeof (pay)) {
			bunyan_info(l, "Payload header is truncated",
			    BUNYAN_T_END);
			return (PKT_WALK_ERROR);
		}

		(void) memcpy(&pay, ptr, sizeof (pay));

		/* this length includes the size of the header */
		pay.pay_length = ntohs(pay.pay_length);

		if (pay.pay_length > len) {
			bunyan_info(l, "Payload size overruns end of packet",
			    BUNYAN_T_UINT32, "paylen", (uint32_t)pay.pay_length,
			    BUNYAN_T_END);
			return (PKT_WALK_ERROR);
		}

		if (cb != NULL) {
			ret = cb(paytype, pay.pay_reserved, ptr + sizeof (pay),
			    pay.pay_length - sizeof (pay), cookie);
			if (ret != PKT_WALK_OK)
				break;
		}

		paytype = pay.pay_next;
		ptr += pay.pay_length;
		len -= pay.pay_length;
	}

	if (ret == PKT_WALK_OK && len > 0) {
		bunyan_info(l, "Packet contains extranenous data",
		    BUNYAN_T_UINT32, "amt", (uint32_t)len,
		    BUNYAN_T_END);
		return (PKT_WALK_ERROR);
	}

	return ((ret != PKT_WALK_OK) ? PKT_WALK_ERROR : PKT_WALK_OK);
}

static size_t
pay_to_idx(pkt_t *pkt, pkt_payload_t *pay)
{
	if (pay == NULL)
		return (0);

	size_t idx = 0;
	if (pay >= pkt->pkt_payloads &&
	    pay < &pkt->pkt_payloads[PKT_PAYLOAD_NUM]) {
		idx = (size_t)(pay - pkt->pkt_payloads);
		VERIFY3U(idx, <, pkt->pkt_payload_count);
		return (idx);
	}

	VERIFY3P(pay, >=, pkt->pkt_payload_extra);
	VERIFY3P(pay, <, pkt->pkt_payload_extra + pkt->pkt_payload_count -
	    PKT_PAYLOAD_NUM);
	idx = (size_t)(pay - pkt->pkt_payload_extra);
	return (idx);
}

pkt_payload_t *
pkt_get_payload(pkt_t *pkt, int type, pkt_payload_t *start)
{
	size_t idx = pay_to_idx(pkt, start);

	VERIFY3S(type, >=, 0);
	VERIFY3S(type, <, 0xff);

	if (start != NULL)
		idx++;

	for (size_t i = idx; i < pkt->pkt_payload_count; i++) {
		pkt_payload_t *pay = pkt_payload(pkt, i);

		if (pay->pp_type == (uint8_t)type)
			return (pay);
	}
	return (NULL);
}

static size_t
notify_to_idx(pkt_t *pkt, pkt_notify_t *n)
{
	if (n == NULL)
		return (0);

	size_t idx = 0;

	if (n >= pkt->pkt_notify &&
	    n < &pkt->pkt_notify[PKT_NOTIFY_NUM]) {
		idx = (size_t)(n - pkt->pkt_notify);
		VERIFY3U(idx, <, pkt->pkt_notify_count);
		return (idx);
	}

	VERIFY3P(n, >=, pkt->pkt_notify_extra);
	VERIFY3P(n, <, pkt->pkt_notify_extra + pkt->pkt_notify_count -
	    PKT_NOTIFY_NUM);

	idx = (size_t)(n - pkt->pkt_notify_extra);
	return (idx);
}

pkt_notify_t *
pkt_get_notify(pkt_t *pkt, int type, pkt_notify_t *start)
{
	size_t idx = notify_to_idx(pkt, start);

	VERIFY3S(type, >=, 0);
	VERIFY3S(type, <=, USHRT_MAX);

	if (start != NULL)
		idx++;

	for (size_t i = idx; i < pkt->pkt_notify_count; i++) {
		pkt_notify_t *n = pkt_notify(pkt, i);

		if (n->pn_type == (uint16_t)type)
			return (n);
	}
	return (NULL);
}

static int
pkt_ctor(void *buf, void *ignore, int flags)
{
	_NOTE(ARGUNUSUED(ignore, flags))

	pkt_t *pkt = buf;
	(void) memset(pkt, 0, sizeof (pkt_t));
	pkt->pkt_ptr = pkt_start(pkt);
	return (0);
}

void
pkt_free(pkt_t *pkt)
{
	if (pkt == NULL)
		return;

	size_t len = 0;
	if (pkt->pkt_payload_extra != NULL) {
		len = pkt->pkt_payload_alloc * sizeof (pkt_payload_t);
		umem_free(pkt->pkt_payload_extra, len);
	}

	if (pkt->pkt_notify_extra != NULL) {
		len = pkt->pkt_notify_alloc * sizeof (pkt_notify_t);
		umem_free(pkt->pkt_notify_extra, len);
	}

	pkt_ctor(pkt, NULL, 0);
	umem_cache_free(pkt_cache, pkt);
}

void
pkt_init(void)
{
	pkt_cache = umem_cache_create("pkt cache", sizeof (pkt_t),
	    sizeof (uint64_t), pkt_ctor, NULL, NULL, NULL, NULL, 0);
	if (pkt_cache == NULL)
		err(EXIT_FAILURE, "Unable to create pkt umem cache");
}

void
pkt_fini(void)
{
	umem_cache_destroy(pkt_cache);
}

void
put32(pkt_t *pkt, uint32_t val)
{
	ASSERT3U(pkt_write_left(pkt), >=, sizeof (uint32_t));
	*(pkt->pkt_ptr++) = (uint8_t)((val >> 24) & (uint32_t)0xff);
	*(pkt->pkt_ptr++) = (uint8_t)((val >> 16) & (uint32_t)0xff);
	*(pkt->pkt_ptr++) = (uint8_t)((val >> 8) & (uint32_t)0xff);
	*(pkt->pkt_ptr++) = (uint8_t)(val & (uint32_t)0xff);
}

void
put64(pkt_t *pkt, uint64_t val)
{
	ASSERT3U(pkt_write_left(pkt), >=, sizeof (uint64_t));
	*(pkt->pkt_ptr++) = (uint8_t)((val >> 56) & 0xffULL);
	*(pkt->pkt_ptr++) = (uint8_t)((val >> 48) & 0xffULL);
	*(pkt->pkt_ptr++) = (uint8_t)((val >> 40) & 0xffULL);
	*(pkt->pkt_ptr++) = (uint8_t)((val >> 32) & 0xffULL);
	*(pkt->pkt_ptr++) = (uint8_t)((val >> 24) & 0xffULL);
	*(pkt->pkt_ptr++) = (uint8_t)((val >> 16) & 0xffULL);
	*(pkt->pkt_ptr++) = (uint8_t)((val >> 8) & 0xffULL);
	*(pkt->pkt_ptr++) = (uint8_t)(val & 0xffULL);
}

extern uint8_t *pkt_start(pkt_t *);
extern size_t pkt_len(const pkt_t *);
extern size_t pkt_write_left(const pkt_t *);
extern size_t pkt_read_left(const pkt_t *, const uint8_t *);
extern pkt_payload_t *pkt_payload(pkt_t *, uint16_t);
extern pkt_notify_t *pkt_notify(pkt_t *, uint16_t);
