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
 * Copyright 2014 Jason King.  All rights reserved.
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
#include "ikev2.h"
#include "ikev2_sa.h"
#include "pkt.h"
#include "pkcs11.h"

#define	DEPTH_NONE		(0)
#define	DEPTH_SK		(1)
#define	DEPTH_PAYLOAD		(2)
#define	DEPTH_PROP		(3)
#define	DEPTH_XFORM		(4)
#define	DEPTH_XFORM_ATTR	(5)

static umem_cache_t	*pkt_cache;

static void pkt_finish(pkt_t *restrict, buf_t *restrict, uintptr_t);

pkt_t *
pkt_out_alloc(uint64_t i_spi, uint64_t r_spi, uint8_t version,
    uint8_t exch_type, uint32_t msgid)
{
	pkt_t *pkt = umem_cache_alloc(pkt_cache, UMEM_DEFAULT);

	if (pkt == NULL)
		return (NULL);

	pkt->header.initiator_spi = i_spi;
	pkt->header.responder_spi = r_spi;
	pkt->header.version = version;
	pkt->header.exch_type = exch_type;
	pkt->msgid = msgid;
	pkt->length = sizeof (ike_header_t);

	ASSERT(pkt->buf.ptr == (uchar_t *)&pkt->raw);

	/*
	 * Skip over bytes in pkt->raw for the header -- we keep
	 * pkt->header (the local byte order copy) updated and then
	 * write out the final version (in network byte order) in this
	 * space once we're done building the packet by stacking a
	 * finish callback before anything else.
	 */
	BUF_ADVANCE(&pkt->buf, sizeof (ike_header_t));
	pkt_stack_push(pkt, DEPTH_NONE, pkt_finish);
	return (pkt);
}

static void
pkt_finish(pkt_t *restrict pkt, buf_t *restrict buf, uintptr_t swaparg,
    size_t numpay)
{
	NOTE(ARGUNUSED(swaparg, numpay))

	ike_header_t *rawhdr;

	ASSERT(pkt->buf.len > buf.len);

	rawhdr = (ike_header_t *)&pkt->raw;
	pkt->header.length = (uint32_t)(pkt->buf.ptr - buf->ptr);
	pkt_hdr_hton(rawhdr, &pkt->header);
}

/*
 * Allocate an pkt_t for an inbound packet, populate the local byte order
 * header, and cache the location of the payloads in the payload field.
 */
pkt_t *
pkt_in_alloc(const buf_t *buf)
{
	pkt_t *pkt;

	if (buf->len > sizeof (pkt->raw)) {
		/* XXX: msg */
		return (NULL);
	}

	if ((pkt = umem_cache_alloc(pkt_cache, UMEM_DEFAULT)) == NULL) {
		/* XXX: msg */
		return (NULL);
	}

	(void) memcpy(&pkt->raw, buf->ptr, buf->len);

	/* Make pkt->buf point to valid portion of raw */
	ASSERT(pkt->buf.ptr == (uchar_t *)&pkt->raw);
	pkt->buf.len = buf->len;

	pkt_hdr_ntoh(&pkt->header, (const ike_header_t *)&pkt->raw);
	return (pkt);
}

void
pkt_free(pkt_t *pkt)
{
	if (pkt == NULL)
		return;

	pkt_reset(pkt);
	umem_cache_free(pkt_cache, pkt);
}

static void
payload_finish(pkt_t *restrict pkt, buf_t *restrict buf, uintptr_t arg,
    size_t numsub)
{
	NOTE(ARGUNUSED(numsub))
	ike_payload_t pay = { 0 };
	buf_t paybuf = STRUCT_TO_BUF(pay);
	uint8_t *pay;
	uint16_t len;

	ASSERT3U(pkt->buf.ptr, >, buf->ptr);
	ASSERT3U(pkt->buf.ptr - buf->ptr, <, USHORT_MAX);

	buf_copy(&paybuf, buf, paybuf.len);
	pay.next = (uint8_t)arg;
       	pay.len = htons((uint16_t)(pkt->buf.ptr - buf->ptr));
	buf_copy(buf, &paybuf);
}

boolean_t
pkt_add_payload(pkt_t *pkt, ike_payload_type_t ptype, uint8_t resv)
{
	ike_payload_t pay = { 0 };
	buf_t buf = STRUCT_TO_BUF(&pay);

	if (pkt->buf.len < sizeof (pay))
		return (B_FALSE);

	/* Special case for first payload */
	if (pkt->buf.ptr == &(uchar_t *)pkt->raw + sizeof (ike_header_t))
		pkt->header.next_payload = (uint8_t)ptype;

	/*
	 * Otherwise we'll set it when we replace the current top of
	 * the stack
	 */
	pkt_stack_push(pkt, DEPTH_PAYLOAD, payload_finish, (uintptr_t)ptype);
	pay.pld_reserved = resv;
	APPEND_STRUCT(pkt, pay);
	return (B_TRUE);
}

static void prop_finish(pkt_t *restrict, buf_t *restrict, uintptr_t, size_t);
boolean_t
pkt_add_prop(pkt_t *pkt, uint8_t propnum, ike_proto_t proto, size_t spilen,
    uint64_t spi)
{
	ike_prop_t	prop = { 0 };
	buf_t		prop_buf = STRUCT_TO_BUF(prop);

	if (pkt->len < sizeof (prop) + spilen)
		return (B_FALSE);

	pkt_stack_push(pkt, DEPTH_PROP, prop_finish, (uintptr_t)IKE_PROTO_MORE);

	prop.prop_num = propnum;
	prop.proto = (uint8_t)proto;
	prop.spilen = spilen;
	APPEND_STRUCT(pkt, prop);

	switch (spilen) {
	case sizeof (uint32_t):
		ASSERT3U(spi, <, UINT_MAX);
		VERIFY(buf_put32(&pkt->buf, (uint32_t)spi));
		break;
	case sizeof (uint64_t):
		VERIFY(buf_put64(&pkt->buf, spi));
		break;
	case 0:
		break;
	default:
		INVALID(spilen);
	}
	va_end(ap);

	return (B_TRUE);
}

static void
prop_finish(pkt_t *restrict pkt, buf_t *restrict buf, uintptr_t more,
    size_t numxform)
{
	ike_prop_t	prop = { 0 };
	buf_t		prop_buf = STRUCT_TO_BUF(prop);

	ASSERT3U(pkt->buf.ptr, >, buf->ptr);
	ASSERT3U(pkt->buf.ptr - buf->ptr, <, 0x10000);

	buf_copy(&prop_buf, buf, prop_buf.len);
	prop.prop_more = (uint8_t)more;
	prop.prop_len = htons((uint16_t)(pkt->buf.ptr - buf->ptr));
	prop.prop_numxform = (uint8_t)numxform;
	buf_copy(buf, &prop_buf);
}

static void xf_finish(pkt_t *restrict, buf_t *restrict, uintptr_t, size_t);
boolean_t
pkt_add_xform(pkt_t *pkt, int xftype, int xfid)
{
	ike_xform_t	xf = { 0 };

	if (pkt->buf.len < sizeof (xf))
		return (B_FALSE);

	pkt_stack_push(pkt, DEPTH_XFORM, xf_finish, (uintptr_t)IKE_XFORM_MORE);
	ASSERT(xfid < USHORT_MAX);
	xf.xf_type = xftype;
	xf.xf_type = htons((uint16_t) xfid);
	APPEND_STRUCT(pkt, xf);
}

static void
pkt_xf_finish(pkt_t *restrict pkt, buf_t *restrict buf,
    uintptr_t more, size_t numattr)
{
	ike_xform_t	xf = { 0 };
	buf_t		xfbuf = STRUCT_TO_BUF(xf);

	ASSERT3U(pkt->buf.ptr, >, buf->ptr);
	ASSERT3U(pkt->buf.ptr - buf->ptr, <, USHORT_MAX);

	buf_copy(&xfbuf, buf);
	xf.xf_more = more;
	xf.xf_len = htons((uint16_t)(pkt->buf.ptr - buf->ptr));
	buf_copy(buf, &xfbuf);
}

boolean_t
pkt_add_xf_attr_tv(pkt_t *pkt, uint_t type, uint_t val)
{
	ike_xf_attr_t	attr;

	ASSERT3U(type, <, 0x8000);
	ASSERT3U(val, <, 0x10000);

	pkt_stack_push(pkt, DEPTH_XFORM_ATTR, NULL, 0);
	attr.attr_type = htons(IKE_ATTR_TYPE(IKE_ATTR_TV, type));
	attr.attr_len = htons(val);
	APPEND_STRUCT(pkt, attr);
}

boolean_t
pkt_add_xf_attr_tlv(pkt_t *pkt, uint_t type, const buf_t *attrval)
{
	ike_xf_attr_t addr;

	ASSERT3U(type, <, 0x8000);
	ASSERT3U(attrval.len, <, 0x10000);

	if (pkt->buf.len < sizeof (attr) + attrval.len)
		return (B_FALSE);

	pkt_stack_push(pkt, PREC_XFORM_ATTR, NULL, 0);
	attr.attr_type = htons(IKE_ATTR_TYPE(IKE_ATTR_TLV, type));
	attr.attr_len = htons(attrval.len);
	APPEND_STRUCT(pkt, attr);
	APPEND_BUF(pkt, attrval);
	return (B_TRUE);
}

boolean_t
pkt_add_cert(pkt_t *restrict pkt, uint8_t encoding, const buf_t *data)
{
	if (pkt->buf.len < 1 + data.len)
		return (B_FALSE);

	buf_put8(&pkt->buf, encoding);
	APPEND_BUF(pkt, data);
	return (B_TRUE);
}

void
pkt_hdr_ntoh(ike_header_t *restrict dest,
    const ike_header_t *restrict src)
{
	ASSERT(IS_P2ALIGNED(dest, sizeof (uint64_t)));
	ASSERT(IS_P2ALIGNED(src, sizeof (uint64_t)));
	ASSERT(src != dest);

	dest->initiator_spi = ntohll(src->initiator_spi);
	dest->responder_spi = ntohll(src->responder_spi);
	dest->msgid = ntohl(src->msgid);
	dest->length = ntohl(src->length);
	dest->first_payload = src->first_payload;
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
	ASSERT(src != dest);

	dest->initiator_spi = htonll(src->initiator_spi);
	dest->responder_spi = htonll(src->responder_spi);
	dest->msgid = htonl(src->msgid);
	dest->length = htonl(src->length);
	dest->first_payload = src->first_payload;
	dest->exch_type = src->exch_type;
	dest->flags = src->flags;
	dest->version = src->version;
}

/*
 * The packet structure of both IKEv1 and IKEv2 consists of a packet with
 * a header that contains a possibly arbitrary number of payloads.  Certain
 * payloads can contain an arbitrary number of sub structures.  Some of those
 * substructures can themselves contain a potentially arbitrary number of
 * sub-sub structures.
 *
 * Due to the format of the headers for payloads and the various sub-*
 * structures, their value cannot be known a priori (e.g. the next payload
 * header value cannot be known until a subsequent payload is added).  In
 * other cases, certain values could be known a priori, but due to the
 * presense of substructures, it might be cumbersome to calculate (many of
 * the length fields fall into this category).
 *
 * To keep the API for constructing packets simple and straightforward,
 * for each type of structure (packet, payload, proposal, etc.) we push
 * a pkt_stack_t onto pkt->stack which contains the location within pkt->raw
 * of the start of the particular structure, and a function to invoke
 * once we are finished constructing the particular structure.
 *
 * To distinguish between different substructures, each sort of structure
 * is assigned a depth.  Every time we begin to construct a structure, we
 * unwind the stack until we are at a lower depth than the structure we
 * are constructing.  As the stack unwinds, the finish functions for each
 * depth are called, and can then utilize the save position of the start
 * of the structure along with the current position (in pkt->buf) to
 * populate any required fields.
 *
 * In addition, when we pop an entry off the stack of the same depth
 * of the structure we are constructing (in effect swapping it's entry
 * with our own), we can pass an argument to the finish function of the
 * entry we are popping.  For example, when constructing payloads,
 * we pop off any entries for substructures, and if one of the entries we
 * popped was for the previous payload, we call it's finish function with
 * an argument containing the type of our payload, which allows it to set
 * it's next payload field.
 *
 * Since we often also need to know the number of immediate substructures
 * we've created when constructing a superstructure (is that a word?),
 * when we are effectively swapping an entry on the stack for one of
 * the same depth, we keep count of the number of swaps until we unwind
 * past it.  As we unwind, we also pass the number of swaps (which ends up
 * being the number of immediate substructures we've created) to the
 * finish function of the immediate enclosing structure.
 */

static boolean_t
pkt_stack_empty(pkt_t *pkt)
{
	return (pkt->stksize == 0 ? B_TRUE : B_FALSE);
}

static int
pkt_stack_depth(pkt_t *pkt)
{
	if (pkt_stack_empty(pkt))
		return (0);
	return (pkt->stack[pkt->stksize - 1].stk_depth);
}

static pkt_stack_t *
pkt_stack_pop(pkt_t *pkt)
{
	if (pkt_stack_empty(pkt))
		return (NULL);
	return (&pkt->stack[--pkt->stksize]);
}

static size_t
pkt_stack_unwind(pkt_t *pkt, int depth, uintptr_t swaparg)
{
	pkt_stack_t	*stk = NULL;
	size_t		count = 0;

	while (!pkt_stack_empty(pkt) && pkt_stack_depth(pkt) >= depth) {
		stk = pkt_stack_pop(pkt);
		if (stk->finish != NULL)
			stk->finish(pkt, stk->stk_buf,
			    (stk->stk_depth == depth) ? swaparg : 0, count);
		count = stk->count;
	}

	ASSERT(pkt_stack_empty(pkt) || pkt_stack_depth(pkt) < depth);

	/* if there was an entry of the same depth (i.e. we are going to
	 * swap it out with our own), return it's swap count + 1 for the
	 * swap we're about to do
	 */
	if (stk != NULL && stk->depth == depth)
		return (stk->count + 1);
	return (0);
}

void
pkt_stack_push(pkt_t *pkt, int depth, uintptr_t swaparg, pkt_finish_fn finish)
{
	pkt_stack_t	*stk;
	size_t		count;

	count = pkt_stack_unwind(pkt, depth, swaparg);

	ASSERT(pkt_stack_depth(pkt) < depth);
	ASSERT(pkt->stksize < PKT_STACK_DEPTH);

	stk = &pkt->stack[pkt->stksize++];

	stk->stk_finish = finish;
	BUF_DUP(&stk->stk_buf, &pkt->buf);
	stk->stk_count = count;
	stk->stk_depth = depth;
}

static int
pkt_reset(void *buf)
{
	pkt_t *pkt = (pkt_t *)buf;
	(void) memset(pkt, 0, sizeof (pkt_t));
	pkt->buf.ptr = (uchar_t *)&pkt->raw;
	pkt->buf.len = sizeof (pkt->raw);
}

static int
pkt_ctor(void *buf, void *ignore, int flags)
{
	_NOTE(ARGUNUSUED(ignore, flags))
	pkt_reset(buf);
	return (0);
}

void
pkt_init(void)
{
}

void
pkt_fini(void)
{
}
