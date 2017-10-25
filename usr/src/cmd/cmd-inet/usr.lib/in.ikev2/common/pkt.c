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
#include <note.h>
#include <security/cryptoki.h>
#include <errno.h>
#include <sys/socket.h>
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
#include "worker.h"

static umem_cache_t	*pkt_cache;

static int pkt_reset(void *);

pkt_t *
pkt_out_alloc(uint64_t i_spi, uint64_t r_spi, uint8_t version,
    uint8_t exch_type, uint32_t msgid, uint8_t flags)
{
	pkt_t *pkt = umem_cache_alloc(pkt_cache, UMEM_DEFAULT);
	ike_header_t *hdr = pkt_header(pkt);

	if (pkt == NULL)
		return (NULL);

	hdr->initiator_spi = i_spi;
	hdr->responder_spi = r_spi;
	hdr->version = version;
	hdr->exch_type = exch_type;
	hdr->msgid = htonl(msgid);
	hdr->flags = flags;

	pkt->pkt_ptr += sizeof (ike_header_t);
	return (pkt);
}

/*
 * Allocate an pkt_t for an inbound packet, populate the local byte order
 * header, and cache the location of the payloads in the payload field.
 */
pkt_t *
pkt_in_alloc(void *restrict buf, size_t buflen)
{
	ike_header_t *hdr = (ike_header_t *)buf;
	pkt_t *pkt = NULL;
	uint8_t first;

	VERIFY(IS_WORKER);

	/* If inbound checks didn't catch these, it's a bug */
	VERIFY3U(buflen, >=, sizeof (ike_header_t));
	VERIFY3U(buflen, ==, ntohl(hdr->length));
	VERIFY3U(buflen, <=, MAX_PACKET_SIZE);

	first = hdr->next_payload;

	if ((pkt = umem_cache_alloc(pkt_cache, UMEM_DEFAULT)) == NULL) {
		STDERR(error, "umem_cache_alloc failed");
		return (NULL);
	}

	(void) bunyan_trace(log, "Allocated new pkt_t",
	    BUNYAN_T_POINTER, "pkt", pkt, BUNYAN_T_END);

	(void) memcpy(pkt->pkt_raw, buf, buflen);
	pkt->pkt_ptr += buflen;

	if (!pkt_index_payloads(pkt, pkt_start(pkt) + sizeof (ike_header_t),
	    pkt_len(pkt) - sizeof (ike_header_t), first)) {
		pkt_free(pkt);
		return (NULL);
	}

	(void) bunyan_trace(log, "Finished indexing payloads",
	    BUNYAN_T_UINT32, "num_payloads", pkt->pkt_payload_count,
	    BUNYAN_T_END);

	return (pkt);
}

struct index_data {
	pkt_t		*id_pkt;
};

static boolean_t
pkt_index_cb(uint8_t paytype, uint8_t resv, uint8_t *restrict ptr, size_t len,
    void *restrict cookie)
{
	NOTE(ARGUNUSED(resv))

	struct index_data *restrict data = cookie;
	pkt_t *pkt = data->id_pkt;

	if (!pkt_add_index(pkt, paytype, ptr, len)) {
		(void) bunyan_info(log,
		    "Could not add index to packet",
		    BUNYAN_T_END);
		return (B_FALSE);
	}

	if (paytype != IKEV1_PAYLOAD_NOTIFY && paytype != IKEV2_PAYLOAD_NOTIFY)
		return (B_TRUE);

	ikev2_notify_t ntfy = { 0 };
	uint64_t spi = 0;
	uint32_t doi = 0;

	if (len < sizeof (ikev2_notify_t)) {
		(void) bunyan_warn(log, "Notify payload is truncated",
		    BUNYAN_T_END);
		return (B_FALSE);
	}

	if (pkt_header(pkt)->version == IKEV1_VERSION) {
		/*
		 * The IKEv1 notification payload is identical to the IKEv2
		 * with the exception of the 32-bit DOI field at the begining
		 * of the struct.
		 */
		if (len < sizeof (ikev2_notify_t) + sizeof (uint32_t)) {
			(void) bunyan_warn(log,
			    "Notify payload is truncated",
			    BUNYAN_T_END);
			return (B_FALSE);
		}

		doi = BE_IN32(ptr);
		ptr += sizeof (uint32_t);
		len -= sizeof (uint32_t);
	}

	(void) memcpy(&ntfy, ptr, sizeof (ntfy));
	ptr += sizeof (ntfy);
	len -= sizeof (ntfy);

	if (ntfy.n_spisize > 0) {
		if (len < ntfy.n_spisize) {
			(void) bunyan_warn(log,
			    "Notify payload SPI length overruns payload",
			    BUNYAN_T_UINT32, "spilen", (uint32_t)ntfy.n_spisize,
			    BUNYAN_T_UINT32, "len", (uint32_t)len,
			    BUNYAN_T_END);
			return (B_FALSE);
		}

		/* This advances ptr for us */
		if (!pkt_get_spi(&ptr, ntfy.n_spisize, &spi)) {
			(void) bunyan_warn(log,
			    "Invalid SPI length in notify payload",
			    BUNYAN_T_UINT32, "spilen", (uint32_t)ntfy.n_spisize,
			    BUNYAN_T_END);
			return (B_FALSE);
		}

		len -= ntfy.n_spisize;
	}

	if (!pkt_add_nindex(pkt, spi, doi, ntfy.n_protoid, ntohs(ntfy.n_type),
	    ptr, len))
		return (B_FALSE);

	return (B_TRUE);
}

/*
 * Add entries to pkt->pkt_payloads and pkt->pkt_notify.
 * NOTE: buf points to the ike_payload_t where it should start.  This
 * allows embedded encrypted IKEv2 payloads to be able to be indexed
 * after decryption by running this after decryption with the address of the
 * first embedded encrypted payload.
 */
boolean_t
pkt_index_payloads(pkt_t *pkt, uint8_t *buf, size_t buflen, uint8_t first)
{
	VERIFY3P(pkt_start(pkt), <=, buf);
	VERIFY3P(pkt->pkt_ptr, >=, buf + buflen);

	struct index_data data = {
		.id_pkt = pkt,
	};

	return (pkt_payload_walk(buf, buflen, pkt_index_cb, first, &data));
}

#define	PKT_CHUNK_SZ	(8)
boolean_t
pkt_add_index(pkt_t *pkt, uint8_t type, uint8_t *buf, uint16_t buflen)
{
	pkt_payload_t *pay = NULL;
	ssize_t idx = pkt->pkt_payload_count - PKT_PAYLOAD_NUM;

	VERIFY(!pkt->pkt_done);

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

	VERIFY(!pkt->pkt_done);

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

/*
 * Add a payload header to pkt as the first step in adding a payload.
 * NOTE: len is the amount of data that will be added by subsequent operations
 * not including the payload header itself -- the function will add that itself.
 * If there is not enough space left for 'len + sizeof (ike_payload_t)' bytes
 * of data (i.e. header + size of data), the function will return B_FALSE.
 *
 * It is permissible to pass a length of 0 for complex payloads where it can
 * be cumbersome or tedious to calculate the length a priori (e.g. an IKEv1 or
 * IKEv2 SA payload).  In such instances, the functions constructing the
 * payload must perform their own checks, and are responsible for updating
 * the payload length value.  However such callers should still examine
 * the return value of pkt_add_payload() as it will still check that there's
 * at least enough space for the payload header.
 */
boolean_t
pkt_add_payload(pkt_t *pkt, uint8_t ptype, uint8_t resv, size_t len)
{
	VERIFY(!pkt->pkt_done);

	if (len + sizeof (ike_payload_t) > UINT16_MAX) {
		errno = ERANGE;
		return (B_FALSE);
	}
	if (pkt_write_left(pkt) < len + sizeof (ike_payload_t)) {
		errno = ENOSPC;
		return (B_FALSE);
	}

	ike_payload_t pld = {
		.pay_next = 0,
		.pay_reserved = resv,
		.pay_length = htons(len + sizeof (ike_payload_t))
	};

	/* Special case for first payload */
	if (pkt->pkt_payload_count == 0) {
		VERIFY3U(pkt_len(pkt), ==, sizeof (ike_header_t));
		pkt_header(pkt)->next_payload = ptype;
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

	if (pkt_header(pkt)->version == IKEV1_VERSION)
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

	if (pkt_write_left(pss->pss_pkt) < amt) {
		errno = ENOSPC;
		return (B_FALSE);
	}

	if (pss->pss_prop != NULL)
		pss->pss_prop->prop_more = IKE_PROP_MORE;

	pss->pss_prop = (ike_prop_t *)pss->pss_pkt->pkt_ptr;

	prop.prop_len = htons(amt);
	prop.prop_more = IKE_PROP_NONE;
	prop.prop_num = propnum;
	prop.prop_proto = proto;
	prop.prop_spilen = spilen;
	PKT_APPEND_STRUCT(pss->pss_pkt, prop);
	/*
	 * We've already checked there's enough room for the SPI with the
	 * pkt_write_left() check above, so this better succeed.
	 */
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
	size_t		proplen = BE_IN16(&pss->pss_prop->prop_len);
	size_t		paylen = BE_IN16(pss->pss_lenp);

	VERIFY(!pss->pss_pkt->pkt_done);
	VERIFY3U(paylen, ==, pss->pss_pld->pp_len + sizeof (ike_payload_t));

	proplen += sizeof (xf);
	paylen += sizeof (xf);

	if (pkt_write_left(pss->pss_pkt) < sizeof (xf)) {
		errno = ENOSPC;
		return (B_FALSE);
	}
	if (proplen > UINT16_MAX || paylen > UINT16_MAX) {
		errno = ERANGE;
		return (B_FALSE);
	}
	if (pss->pss_prop->prop_numxform == UINT8_MAX) {
		errno = ERANGE;
		return (B_FALSE);
	}

	if (pss->pss_xf != NULL)
		pss->pss_xf->xf_more = IKE_XFORM_MORE;

	pss->pss_xf = (ike_xform_t *)pss->pss_pkt->pkt_ptr;

	xf.xf_len = htons(sizeof (xf));
	xf.xf_more = IKE_XFORM_NONE;
	xf.xf_type = xftype;
	xf.xf_id = htons(xfid);
	PKT_APPEND_STRUCT(pss->pss_pkt, xf);

	/* prop_numxform is uint8_t so it can be derefenced directly */
	pss->pss_prop->prop_numxform++;

	BE_OUT16(&pss->pss_prop->prop_len, proplen);
	BE_OUT16(pss->pss_lenp, paylen);
	pss->pss_pld->pp_len += sizeof (xf);

	return (B_TRUE);
}

boolean_t
pkt_add_xform_attr_tv(pkt_sa_state_t *pss, uint16_t type, uint16_t val)
{
	ike_xf_attr_t	attr = { 0 };
	size_t		xflen = BE_IN16(&pss->pss_xf->xf_len);
	size_t		proplen = BE_IN16(&pss->pss_prop->prop_len);
	size_t		paylen = BE_IN16(pss->pss_lenp);

	VERIFY3U(type, <=, IKE_ATTR_MAXTYPE);
	VERIFY(!pss->pss_pkt->pkt_done);
	VERIFY3U(paylen, ==, pss->pss_pld->pp_len + sizeof (ike_payload_t));

	xflen += sizeof (attr);
	proplen += sizeof (attr);
	paylen += sizeof (attr);

	if (pkt_write_left(pss->pss_pkt) < sizeof (attr)) {
		errno = ENOSPC;
		return (B_FALSE);
	}
	if (xflen > UINT16_MAX || proplen > UINT16_MAX || paylen > UINT16_MAX) {
		errno = ERANGE;
		return (B_FALSE);
	}

	attr.attr_type = htons(IKE_ATTR_TYPE(IKE_ATTR_TV, type));
	attr.attr_len = htons(val);
	PKT_APPEND_STRUCT(pss->pss_pkt, attr);

	BE_OUT16(&pss->pss_xf->xf_len, xflen);
	BE_OUT16(&pss->pss_prop->prop_len, proplen);
	BE_OUT16(pss->pss_lenp, paylen);
	pss->pss_pld->pp_len += sizeof (attr);

	return (B_TRUE);
}

boolean_t
pkt_add_xform_attr_tlv(pkt_sa_state_t *pss, uint16_t type, const uint8_t *attrp,
    size_t attrlen)
{
	ike_xf_attr_t attr = { 0 };
	size_t		xflen = BE_IN16(&pss->pss_xf->xf_len);
	size_t		proplen = BE_IN16(&pss->pss_prop->prop_len);
	size_t		paylen = BE_IN16(pss->pss_lenp);
	size_t		len = sizeof (attr) + attrlen;

	VERIFY3U(type, <=, IKE_ATTR_MAXTYPE);

	VERIFY(!pss->pss_pkt->pkt_done);
	VERIFY3U(paylen, ==, pss->pss_pld->pp_len + sizeof (ike_payload_t));

	/*
	 * IKE_ATTR_MAXLEN is < UINT16_MAX, so if attrlen <= IKE_ATTR_MAXLEN,
	 * len cannot have overflowed
	 */
	if (pkt_write_left(pss->pss_pkt) < len) {
		errno = ENOSPC;
		return (B_FALSE);
	}
	if (attrlen > IKE_ATTR_MAXLEN || paylen > UINT16_MAX ||
	    proplen > UINT16_MAX || xflen > UINT16_MAX) {
		errno = ERANGE;
		return (B_FALSE);
	}

	attr.attr_type = htons(IKE_ATTR_TYPE(IKE_ATTR_TLV, type));
	attr.attr_len = htons(len);
	PKT_APPEND_STRUCT(pss->pss_pkt, attr);
	VERIFY(pkt_append_data(pss->pss_pkt, attrp, attrlen));

	BE_OUT16(&pss->pss_xf->xf_len, xflen);
	BE_OUT16(&pss->pss_prop->prop_len, proplen);
	BE_OUT16(pss->pss_lenp, paylen);
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

	VERIFY3U(spilen, <, UINT16_MAX);
	VERIFY3U(datalen, <, UINT16_MAX);

	if (pkt_header(pkt)->version == IKEV1_VERSION) {
		len += sizeof (ikev1_notify_t);
		VERIFY3U(len, <=, UINT16_MAX);

		if (!pkt_add_payload(pkt, IKEV1_PAYLOAD_NOTIFY, 0, len))
			return (B_FALSE);

		n.n1.n_doi = htonl(doi);
		n.n1.n_protoid = proto;
		n.n1.n_spisize = spilen;
		n.n1.n_type = htons(type);
		PKT_APPEND_STRUCT(pkt, n.n1);
	} else if (pkt_header(pkt)->version == IKEV2_VERSION) {
		len += sizeof (ikev2_notify_t);
		VERIFY3U(len, <=, UINT16_MAX);

		if (!pkt_add_payload(pkt, IKEV2_PAYLOAD_NOTIFY, 0, len))
			return (B_FALSE);

		n.n2.n_protoid = proto;
		n.n2.n_spisize = spilen;
		n.n2.n_type = htons(type);
		PKT_APPEND_STRUCT(pkt, n.n2);
	}

	VERIFY(pkt_add_spi(pkt, spilen, spi));
	ptr = pkt->pkt_ptr;
	pkt_append_data(pkt, data, datalen);

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
	VERIFY(pkt_append_data(pkt, data, datalen));
	return (B_TRUE);
}

/* pops off all the callbacks in preparation for sending */
boolean_t
pkt_done(pkt_t *pkt)
{
	ike_header_t *hdr = pkt_header(pkt);
	hdr->length = htonl(pkt_len(pkt));
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
boolean_t
pkt_payload_walk(uint8_t *restrict data, size_t len, pkt_walk_fn_t cb,
    uint8_t first, void *restrict cookie)
{
	uint8_t			*ptr = data;
	uint8_t			paytype = first;
	boolean_t		ret = B_TRUE;

	/* 0 is used for both IKEv1 and IKEv2 to indicate last payload */
	while (len > 0 && paytype != 0) {
		ike_payload_t pay = { 0 };

		if (len < sizeof (pay)) {
			(void) bunyan_info(log, "Payload header is truncated",
			    BUNYAN_T_UINT32, "paylen", (uint32_t)len,
			    BUNYAN_T_END);
			return (B_FALSE);
		}

		(void) memcpy(&pay, ptr, sizeof (pay));

		/* this length includes the size of the header */
		pay.pay_length = ntohs(pay.pay_length);

		if (pay.pay_length > len) {
			(void) bunyan_info(log,
			    "Payload size overruns end of packet",
			    BUNYAN_T_UINT32, "paylen", (uint32_t)pay.pay_length,
			    BUNYAN_T_END);
			return (B_FALSE);
		}

		if (cb != NULL && !(ret = cb(paytype, pay.pay_reserved,
		    ptr + sizeof (pay), pay.pay_length - sizeof (pay),
		    cookie)))
				break;

		paytype = pay.pay_next;
		ptr += pay.pay_length;
		len -= pay.pay_length;
	}

	if (ret && len > 0) {
		(void) bunyan_info(log, "Packet contains extranenous data",
		    BUNYAN_T_UINT32, "amt", (uint32_t)len,
		    BUNYAN_T_END);
		return (B_FALSE);
	}

	return (ret);
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

/*
 * Return the first payload of a given type after 'start'.  If start is NULL,
 * the first payload of the given type will be returned.  This allows for
 * iteration through payloads of a given type in a packet using code
 * similar to:
 *	pkt_payload_t *pay;
 *	...
 *	for (pay = pkt_get_payload(pkt, IKEV2_PAYLOAD_CERT, NULL);
 *	    pay != NULL;
 *	    pay = pkt_get_payload(pkt, IKEV2_PAYLOAD_CERT, pay)) {
 *		...
 *	}
 *
 * It is a fatal error to pass a value in start that is not an existing
 * payload in pkt.
 */
pkt_payload_t *
pkt_get_payload(pkt_t *pkt, uint8_t type, pkt_payload_t *start)
{
	size_t idx = (start == NULL) ? 0 : pay_to_idx(pkt, start);

	/*
	 * If we're searching for the next payload of 'type', we want to
	 * being searching after 'start'.
	 */
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

/*
 * Return the first payload of type 'type' after 'start'.  If start is
 * NULL, return the first notify payload of type 'type'.  This allows one
 * to iterate through multiple instances of a given notify type using something
 * such as:
 * 	pkt_notify_t *n;
 * 	...
 * 	for (n = pkt_get_notify(pkt, IKEV2_N_NAT_DETECTION_SOURCE_IP, NULL);
 * 	    n != NULL;
 * 	    n = pkt_get_notify(pkt, IKEV2_N_NAT_DETECTION_SOURCE_IP, n)) {
 * 		....
 * 	}
 *
 * It is a fatal error to pass in a notify in 'start' that does not exist
 * in pkt.
 */
pkt_notify_t *
pkt_get_notify(pkt_t *pkt, uint16_t type, pkt_notify_t *start)
{
	size_t idx = notify_to_idx(pkt, start);

	/*
	 * If we're looking for the next instance of 'type', we need to
	 * begin our search after the previous value returned (start).
	 */
	if (start != NULL)
		idx++;

	for (uint16_t i = idx; i < pkt->pkt_notify_count; i++) {
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
		VERIFY(put32(pkt, (uint32_t)spi));
		break;
	case sizeof (uint64_t):
		VERIFY(put64(pkt, spi));
		break;
	case 0:
		break;
	default:
		INVALID(spilen);
	}
	return (B_TRUE);
}

boolean_t
pkt_get_spi(uint8_t *restrict *pptr, size_t len, uint64_t *restrict spip)
{
	*spip = 0;

	/*
	 * When writing an SPI, we only support 3 sizes -- 0, 4 (32-bits),
	 * and 8 (64-bits) corresponding to the IKE SPI and AH/ESP SPI sizes.
	 * Thus, trying to write an unsupported value is a programming error.
	 * However it is possible we might encounter an unsupported SPI length
	 * on inbound packets (it would need to be for something other than
	 * IKE, AH, or ESP however).  In such a situation, we return
	 * an error to let the caller decide what to do.
	 */
	switch (len) {
	case 0:
		return (B_TRUE);
	case sizeof (uint32_t):
		*spip = BE_IN32(*pptr);
		*pptr += sizeof (uint32_t);
		return (B_TRUE);
	case sizeof (uint64_t):
		*spip = BE_IN64(*pptr);
		*pptr += sizeof (uint64_t);
		return (B_TRUE);
	}

	return (B_FALSE);
}

static int
pkt_ctor(void *buf, void *ignore, int flags)
{
	NOTE(ARGUNUSED(ignore, flags))

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

size_t
pkt_len(const pkt_t *pkt)
{
	const uint8_t *start = (const uint8_t *)&pkt->pkt_raw;
	size_t len = (size_t)(pkt->pkt_ptr - start);

	VERIFY3P(pkt->pkt_ptr, >=, start);
	VERIFY3U(len, <=, MAX_PACKET_SIZE);
	return ((size_t)(pkt->pkt_ptr - start));
}

size_t
pkt_write_left(const pkt_t *pkt)
{
	return (MAX_PACKET_SIZE - pkt_len(pkt));
}

pkt_payload_t *
pkt_payload(pkt_t *pkt, uint16_t idx)
{
	VERIFY3U(idx, <, pkt->pkt_payload_count);
	if (idx < PKT_PAYLOAD_NUM)
		return (&pkt->pkt_payloads[idx]);
	return (pkt->pkt_payload_extra + (idx - PKT_PAYLOAD_NUM));
}

pkt_notify_t *
pkt_notify(pkt_t *pkt, uint16_t idx)
{
	VERIFY3U(idx, <, pkt->pkt_notify_count);
	if (idx < PKT_NOTIFY_NUM)
		return (&pkt->pkt_notify[idx]);
	return (pkt->pkt_notify_extra + (idx - PKT_NOTIFY_NUM));
}

boolean_t
put32(pkt_t *pkt, uint32_t val)
{
	if (pkt_write_left(pkt) < sizeof (uint32_t))
		return (B_FALSE);

	BE_OUT32(pkt->pkt_ptr, val);
	pkt->pkt_ptr += sizeof (uint32_t);
	return (B_TRUE);
}

boolean_t
put64(pkt_t *pkt, uint64_t val)
{
	if (pkt_write_left(pkt) < sizeof (uint64_t))
		return (B_FALSE);

	BE_OUT64(pkt->pkt_ptr, val);
	pkt->pkt_ptr += sizeof (uint64_t);
	return (B_TRUE);
}

ike_payload_t *
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

boolean_t
pkt_append_data(pkt_t *restrict pkt, const void *restrict data, size_t len)
{
	if (len == 0)
		return (B_TRUE);

	if (pkt_write_left(pkt) < len)
		return (B_FALSE);
	(void) memcpy(pkt->pkt_ptr, data, len);
	pkt->pkt_ptr += len;
	return (B_TRUE);
}

uint8_t *
pkt_start(const pkt_t *pkt)
{
	return ((uint8_t *)pkt->pkt_raw);
}

ike_header_t *
pkt_header(const pkt_t *pkt)
{
	return ((ike_header_t *)pkt->pkt_raw);
}
