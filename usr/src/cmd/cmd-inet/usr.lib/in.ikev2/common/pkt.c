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

static int pkt_reset(void *);

pkt_t *
pkt_out_alloc(uint64_t i_spi, uint64_t r_spi, uint8_t version,
    uint8_t exch_type, uint32_t msgid, uint8_t flags)
{
	pkt_t *pkt = umem_cache_alloc(pkt_cache, UMEM_DEFAULT);

	if (pkt == NULL)
		return (NULL);

	pkt->pkt_header.initiator_spi = i_spi;
	pkt->pkt_header.responder_spi = r_spi;
	pkt->pkt_header.version = version;
	pkt->pkt_header.exch_type = exch_type;
	pkt->pkt_header.msgid = msgid;
	pkt->pkt_header.flags = flags;

	pkt->pkt_ptr += sizeof (ike_header_t);
	return (pkt);
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

	if ((pkt = umem_cache_alloc(pkt_cache, UMEM_DEFAULT)) == NULL) {
		STDERR(error, l, "umem_cache_alloc failed");
		return (NULL);
	}

	(void) bunyan_trace(l, "Allocated new pkt_t",
	    BUNYAN_T_POINTER, "pkt", pkt,
	    BUNYAN_T_END);

	(void) memcpy(pkt->pkt_raw, buf, buflen);
	pkt_hdr_ntoh(&pkt->pkt_header, (const ike_header_t *)&pkt->pkt_raw);
	pkt->pkt_ptr += buflen;

	if (!pkt_index_payloads(pkt, pkt_start(pkt) + sizeof (ike_header_t),
	    pkt_len(pkt) - sizeof (ike_header_t), first, l)) {
		pkt_free(pkt);
		return (NULL);
	}

	(void) bunyan_trace(l, "Finished indexing payloads",
	    BUNYAN_T_POINTER, "pkt", pkt,
	    BUNYAN_T_UINT32, "num_payloads", pkt->pkt_payload_count,
	    BUNYAN_T_END);

	return (pkt);
}

struct index_data {
	pkt_t		*id_pkt;
	bunyan_logger_t	*id_log;
};

static pkt_walk_ret_t
pkt_index_cb(uint8_t paytype, uint8_t resv, uint8_t *restrict ptr, size_t len,
    void *restrict cookie)
{
	struct index_data *data = cookie;
	pkt_t *pkt = data->id_pkt;
	
	if (!pkt_add_index(pkt, paytype, ptr, len)) {
		(void) bunyan_info(data->id_log,
		    "Could not add index to packet",
		    BUNYAN_T_POINTER, "pkt", pkt,
		    BUNYAN_T_END);
		return (PKT_WALK_ERROR);
	}

	if (paytype != IKEV1_PAYLOAD_NOTIFY && paytype != IKEV2_PAYLOAD_NOTIFY)
		return (PKT_WALK_OK);

	ikev2_notify_t ntfy = { 0 };
	uint64_t spi = 0;
	uint32_t doi = 0;

	if (len < sizeof (ikev2_notify_t)) {
		bunyan_warn(data->id_log, "Notify payload is truncated",
		    BUNYAN_T_END);
		return (PKT_WALK_ERROR);
	}

	if (pkt->pkt_header.version == IKEV1_VERSION) {
		/*
		 * The IKEv1 notification payload is identical to the IKEv2
		 * with the exception of the 32-bit DOI field at the begining
		 * of the struct.
		 */
	 	if (len < sizeof (ikev2_notify_t) + sizeof (uint32_t)) {
			(void) bunyan_warn(data->id_log,
			    "Notify payload is truncated",
			    BUNYAN_T_END);
			return (PKT_WALK_ERROR);
		}

		(void) memcpy(&doi, ptr, sizeof (doi));
		doi = ntohl(doi);
		ptr += sizeof (uint32_t);
		len -= sizeof (uint32_t);
	}

	(void) memcpy(&ntfy, ptr, sizeof (ntfy));
	ptr -= sizeof (ntfy);
	len -= sizeof (ntfy);

	/* This is a single byte, so don't need to worry about byte order */
	if (ntfy.n_spisize > 0) {
		if (len < ntfy.n_spisize)
			return (PKT_WALK_ERROR);

		if (ntfy.n_spisize == sizeof (uint32_t)) {
			uint32_t val = 0;

			(void) memcpy(&val, ptr, sizeof (uint32_t));
			spi = ntohl(val);
		} else if (ntfy.n_spisize == sizeof (uint64_t)) {
			(void) memcpy(&spi, ptr, sizeof (uint64_t));
			spi = ntohll(spi);
		} else {
			(void) bunyan_warn(data->id_log,
			    "Invalid SPI length in notify payload",
			    BUNYAN_T_UINT32, "spilen", (uint32_t)ntfy.n_spisize,
			    BUNYAN_T_END);
			return (PKT_WALK_ERROR);
		}

		ptr += ntfy.n_spisize;
		len -= ntfy.n_spisize;
	}

	if (!pkt_add_nindex(pkt, spi, doi, ntfy.n_protoid, ntohs(ntfy.n_type),
	    ptr, len))
		return (PKT_WALK_ERROR);

	return (PKT_WALK_OK);
}

/*
 * Add entries to pkt->pkt_payloads and pkt->pkt_notify.
 * NOTE: buf points to the ike_payload_t where it should start.  This
 * allows embedded encrypted IKEv2 payloads to be able to be indexed
 * after decryption by running this after decryption with the address of the
 * first embedded encrypted payload.
 */
boolean_t
pkt_index_payloads(pkt_t *pkt, uint8_t *buf, size_t buflen, uint8_t first,
    bunyan_logger_t *restrict l)
{
	VERIFY3P(pkt_start(pkt), <=, buf);
	VERIFY3P(pkt->pkt_ptr, >=, buf + buflen);

	struct index_data data = {
		.id_pkt = pkt,
		.id_log = l
	};

	if (pkt_payload_walk(buf, buflen, pkt_index_cb, first,
	    &data, l) != PKT_WALK_OK)
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
pkt_add_nindex(pkt_t *pkt, uint64_t spi, uint32_t doi, uint8_t proto,
    uint16_t type, uint8_t *buf, size_t buflen)
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
	n->pn_doi = doi;
	n->pn_spi = spi;
	n->pn_proto = proto;
	return (B_TRUE);
}

boolean_t
pkt_add_payload(pkt_t *pkt, uint8_t ptype, uint8_t resv, uint16_t len)
{
	ike_payload_t pld = {
		.pay_next = 0,
		.pay_reserved = resv,
		.pay_length = htons(len + sizeof (ike_payload_t))
	};

	VERIFY(!pkt->pkt_done);

	if (pkt_write_left(pkt) < len + sizeof (ike_payload_t))
		return (B_FALSE);

	/* Special case for first payload */
	if (pkt->pkt_payload_count == 0) {
		VERIFY3U(pkt_len(pkt), ==, sizeof (ike_header_t));
		pkt->pkt_header.next_payload = (uint8_t)ptype;
		((ike_header_t *)&pkt->pkt_raw)->next_payload = ptype;
	} else {
		pkt_payload_t *pp =
		    pkt_payload(pkt, pkt->pkt_payload_count - 1);
		ike_payload_t *payp = ((ike_payload_t *)pp->pp_ptr) - 1;
		payp->pay_next = ptype;
	}

	PKT_APPEND_STRUCT(pkt, pld);
	return (pkt_add_index(pkt, ptype, pkt->pkt_ptr, len));
}

boolean_t
pkt_add_sa(pkt_t *restrict pkt, pkt_sa_state_t *restrict pss)
{
	ike_payload_t *payp = (ike_payload_t *)pkt->pkt_ptr;
	boolean_t ok;

	if (pkt->pkt_header.version == IKEV1_VERSION)
		ok = pkt_add_payload(pkt, IKEV1_PAYLOAD_SA, 0, 0);
	else
		ok = pkt_add_payload(pkt, IKEV2_PAYLOAD_SA, 0, 0);

	if (!ok)
		return (B_FALSE);

	(void) memset(pss, 0, sizeof (*pss));
	pss->pss_pkt = pkt;
	pss->pss_lenp = &payp->pay_length;
	pss->pss_pld = pkt_payload(pkt, pkt->pkt_payload_count - 1);

	return (B_TRUE);
}

boolean_t
pkt_add_prop(pkt_sa_state_t *pss, uint8_t propnum, uint8_t proto, size_t spilen,
    uint64_t spi)
{
	ike_prop_t	prop = { 0 };
	uint16_t	val = 0, amt = sizeof (prop) + spilen;

	VERIFY(!pss->pss_pkt->pkt_done);

	if (pkt_write_left(pss->pss_pkt) < amt)
		return (B_FALSE);

	if (pss->pss_prop != NULL)
		pss->pss_prop->prop_more = IKE_PROP_MORE;

	pss->pss_prop = (ike_prop_t *)pss->pss_pkt->pkt_ptr;

	prop.prop_len = htons(amt);
	prop.prop_more = IKE_PROP_NONE;
	prop.prop_num = propnum;
	prop.prop_proto = (uint8_t)proto;
	prop.prop_spilen = spilen;
	PKT_APPEND_STRUCT(pss->pss_pkt, prop);
	VERIFY(pkt_add_spi(pss->pss_pkt, spilen, spi));

	pss->pss_pld->pp_len += amt;
	pss->pss_xf = NULL;

	val = BE_IN16(pss->pss_lenp);
	val += amt;
	BE_OUT16(pss->pss_lenp, val);

	return (B_TRUE);
}

boolean_t
pkt_add_xform(pkt_sa_state_t *pss, uint8_t xftype, uint16_t xfid)
{
	ike_xform_t	xf = { 0 };
	uint16_t	len = 0;

	VERIFY(!pss->pss_pkt->pkt_done);

	if (pkt_write_left(pss->pss_pkt) < sizeof (xf))
		return (B_FALSE);

	if (pss->pss_xf != NULL)
		pss->pss_xf->xf_more = IKE_XFORM_MORE;

	pss->pss_xf = (ike_xform_t *)pss->pss_pkt->pkt_ptr;

	xf.xf_len = htons(sizeof (xf));
	xf.xf_more = IKE_XFORM_NONE;
	xf.xf_type = xftype;
	xf.xf_id = htons(xfid);
	PKT_APPEND_STRUCT(pss->pss_pkt, xf);

	/* This is uint8_t */
	pss->pss_prop->prop_numxform++;

	len = BE_IN16(&pss->pss_prop->prop_len);
	len += sizeof (xf);
	BE_OUT16(&pss->pss_prop->prop_len, len);

	len = BE_IN16(pss->pss_lenp);
	len += sizeof (xf);
	BE_OUT16(pss->pss_lenp, len);

	pss->pss_pld->pp_len += sizeof (xf);
	return (B_TRUE);
}

boolean_t
pkt_add_xform_attr_tv(pkt_sa_state_t *pss, uint16_t type, uint16_t val)
{
	ike_xf_attr_t	attr = { 0 };
	uint16_t len = 0;

	VERIFY3U(type, <, 0x8000);
	VERIFY3U(val, <, 0x10000);

	VERIFY(!pss->pss_pkt->pkt_done);

	if (pkt_write_left(pss->pss_pkt) < sizeof (attr))
		return (B_FALSE);

	attr.attr_type = htons(IKE_ATTR_TYPE(IKE_ATTR_TV, type));
	attr.attr_len = htons(val);
	PKT_APPEND_STRUCT(pss->pss_pkt, attr);

	len = BE_IN16(&pss->pss_xf->xf_len);
	len += sizeof (attr);
	BE_OUT16(&pss->pss_xf->xf_len, len);

	len = BE_IN16(&pss->pss_prop->prop_len);
	len += sizeof (attr);
	BE_OUT16(&pss->pss_prop->prop_len, len);

	len = BE_IN16(pss->pss_lenp);
	len += sizeof (attr);
	BE_OUT16(pss->pss_lenp, len);

	pss->pss_pld->pp_len += sizeof (attr);
	return (B_TRUE);
}

boolean_t
pkt_add_xform_attr_tlv(pkt_sa_state_t *pss, uint16_t type, const uint8_t *attrp,
    size_t attrlen)
{
	ike_xf_attr_t attr = { 0 };
	size_t len = 0, amt = sizeof (attr) + attrlen;

	VERIFY3U(type, <, 0x8000);
	VERIFY3U(attrlen, <, 0x10000);

	VERIFY(!pss->pss_pkt->pkt_done);

	if (pkt_write_left(pss->pss_pkt) < amt)
		return (B_FALSE);

	attr.attr_type = htons(IKE_ATTR_TYPE(IKE_ATTR_TLV, type));
	attr.attr_len = htons(attrlen);
	PKT_APPEND_STRUCT(pss->pss_pkt, attr);
	PKT_APPEND_DATA(pss->pss_pkt, attrp, attrlen);

	len = BE_IN16(&pss->pss_xf->xf_len);
	len += sizeof (attr);
	BE_OUT16(&pss->pss_xf->xf_len, len);

	len = BE_IN16(&pss->pss_prop->prop_len);
	len += sizeof (attr);
	BE_OUT16(&pss->pss_prop->prop_len, len);

	len = BE_IN16(pss->pss_lenp);
	len += sizeof (attr);
	BE_OUT16(pss->pss_lenp, len);

	pss->pss_pld->pp_len += sizeof (attr);
	return (B_TRUE);
}

boolean_t
pkt_add_notify(pkt_t *restrict pkt, uint32_t doi, uint8_t proto,
    uint8_t spilen, uint64_t spi, uint16_t type, const void *restrict data,
    size_t datalen)
{
	union {
		ikev1_notify_t n1;
		ikev2_notify_t n2;
	} n;
	uint8_t *ptr = NULL;
	size_t len = spilen + datalen;

	if (pkt->pkt_header.version == IKEV1_VERSION) {
		len += sizeof (ikev1_notify_t);

		if (!pkt_add_payload(pkt, IKEV1_PAYLOAD_NOTIFY, 0, len))
			return (B_FALSE);

		n.n1.n_doi = htonl(doi);
		n.n1.n_protoid = proto;
		n.n1.n_type = htons(type);
		n.n1.n_spisize = spilen;
		n.n1.n_type = htons(type);
		PKT_APPEND_STRUCT(pkt, n.n1);
	} else if (pkt->pkt_header.version == IKEV2_VERSION) {
		len += sizeof (ikev2_notify_t);

		if (!pkt_add_payload(pkt, IKEV2_PAYLOAD_NOTIFY, 0, len))
			return (B_FALSE);

		n.n2.n_protoid = proto;
		n.n2.n_type = htons(type);
		n.n2.n_spisize = spilen;
		n.n2.n_type = htons(type);
		PKT_APPEND_STRUCT(pkt, n.n2);
	}

	VERIFY(pkt_add_spi(pkt, spilen, spi));
	ptr = pkt->pkt_ptr;
	PKT_APPEND_DATA(pkt, data, datalen);

	return (pkt_add_nindex(pkt, spi, doi, proto, type, ptr, datalen));
}

boolean_t
pkt_add_cert(pkt_t *restrict pkt, uint8_t paytype, uint8_t encoding,
    const void *data, size_t datalen)
{
	if (!pkt_add_payload(pkt, paytype, 0, datalen + 1))
		return (B_FALSE);

	pkt->pkt_ptr[0] = encoding;
	pkt->pkt_ptr += 1;
	PKT_APPEND_DATA(pkt, data, datalen);
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

/* pops off all the callbacks in preparation for sending */
boolean_t
pkt_done(pkt_t *pkt)
{
	pkt->pkt_header.length = pkt_len(pkt);
	pkt_hdr_hton((ike_header_t *)&pkt->pkt_raw, &pkt->pkt_header);
	pkt->pkt_done = B_TRUE;
	return (B_TRUE);
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

boolean_t
pkt_add_spi(pkt_t *pkt, size_t spilen, uint64_t spi)
{
	if (pkt_write_left(pkt) < spilen)
		return (B_FALSE);

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

extern void put32(pkt_t *, uint32_t);
extern void put64(pkt_t *, uint64_t);
extern uint8_t *pkt_start(pkt_t *);
extern size_t pkt_len(const pkt_t *);
extern size_t pkt_write_left(const pkt_t *);
extern size_t pkt_read_left(const pkt_t *, const uint8_t *);
extern pkt_payload_t *pkt_payload(pkt_t *, uint16_t);
extern pkt_notify_t *pkt_notify(pkt_t *, uint16_t);
extern ike_payload_t *pkt_idx_to_payload(pkt_payload_t *);
