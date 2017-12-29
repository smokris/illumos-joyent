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
 * Copyright (c) 2017, Joyent, Inc.
 */

#include <stddef.h>
#include <alloca.h>
#include <assert.h>
#include <umem.h>
#include <string.h>
#include <strings.h>
#include <errno.h>
#include <libcmdutils.h> /* for custr_ */
#include <netinet/in.h>
#include <security/cryptoki.h>
#include <errno.h>
#include <sys/byteorder.h>
#include <sys/debug.h>
#include <sys/random.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <note.h>
#include <stdarg.h>
#include "defs.h"
#include "pkt_impl.h"
#include "ikev2.h"
#include "ikev2_sa.h"
#include "ikev2_pkt.h"
#include "ikev2_pkt_check.h"
#include "ikev2_proto.h"
#include "ikev2_enum.h"
#include "pkcs11.h"
#include "worker.h"

/* Allocate an outbound IKEv2 pkt for a new exchange */
pkt_t *
ikev2_pkt_new_exchange(ikev2_sa_t *i2sa, ikev2_exch_t exch_type)
{
	pkt_t *pkt = NULL;
	uint32_t msgid = 0;
	uint8_t flags = 0;
	const char *exchstr = NULL;

	VERIFY(MUTEX_HELD(&i2sa->i2sa_lock));

	msgid = i2sa->outmsgid++;

	if (i2sa->flags & I2SA_INITIATOR)
		flags |= IKEV2_FLAG_INITIATOR;

	(void) bunyan_key_add(log,
	    BUNYAN_T_STRING, LOG_KEY_EXCHTYPE, ikev2_exch_str(exch_type),
	    BUNYAN_T_END);

	pkt = pkt_out_alloc(I2SA_LOCAL_SPI(i2sa),
	    I2SA_REMOTE_SPI(i2sa),
	    IKEV2_VERSION,
	    exch_type, msgid, flags);

	if (pkt == NULL) {
		(void) bunyan_error(log, "No memory for new exchange",
		    BUNYAN_T_END);
		i2sa->outmsgid--;
		return (NULL);
	}

	(void) bunyan_key_add(log,
	    BUNYAN_T_POINTER, LOG_KEY_REQ, pkt,
	    BUNYAN_T_UINT32, LOG_KEY_MSGID, msgid,
	    BUNYAN_T_END);
	(void) bunyan_key_remove(log, LOG_KEY_RESP);

	pkt->pkt_sa = i2sa;

	/*
	 * Every non-IKE_SA_INIT exchange requires the SK payload as it's
	 * first payload (i.e. everything should be encrypted), so go
	 * ahead and add it now
	 */
	if (exch_type != IKEV2_EXCH_IKE_SA_INIT)
		VERIFY(ikev2_add_sk(pkt));

	return (pkt);
}

/* Allocate a ikev2_pkt_t for an IKEv2 outbound response */
pkt_t *
ikev2_pkt_new_response(const pkt_t *init)
{
	pkt_t *pkt;
	ike_header_t *hdr = pkt_header(init);
	uint8_t flags = IKEV2_FLAG_RESPONSE;

	VERIFY3U(IKE_GET_MAJORV(hdr->version), ==,
	    IKE_GET_MAJORV(IKEV2_VERSION));
	VERIFY(MUTEX_HELD(&init->pkt_sa->i2sa_lock));

	if (init->pkt_sa->flags & I2SA_INITIATOR)
		flags |= IKEV2_FLAG_INITIATOR;

	pkt = pkt_out_alloc(hdr->initiator_spi,
	    hdr->responder_spi,
	    IKEV2_VERSION,
	    hdr->exch_type,
	    ntohl(hdr->msgid), flags);
	if (pkt == NULL) {
		(void) bunyan_error(log, "No memory for response packet",
		    BUNYAN_T_END);
		return (NULL);
	}

	/*
	 * The other packet keys should already be set from the initiating
	 * packet.
	 */
	(void) bunyan_key_add(log,
	    BUNYAN_T_POINTER, LOG_KEY_RESP, pkt,
	    BUNYAN_T_END);

	pkt->pkt_sa = init->pkt_sa;

	/*
	 * Every non-IKE_SA_INIT exchange requires the SK payload as it's
	 * first payload (i.e. everything should be encrypted), so go
	 * ahead and add it now
	 */
	if (hdr->exch_type != IKEV2_EXCH_IKE_SA_INIT)
		VERIFY(ikev2_add_sk(pkt));

	return (pkt);
}

/* Allocate a ikev2_pkt_t for an inbound datagram in raw */
pkt_t *
ikev2_pkt_new_inbound(void *restrict buf, size_t buflen)
{
	const char		*pktkey = NULL;
	const ike_header_t	*hdr = NULL;
	pkt_t			*pkt = NULL;
	size_t			i = 0;

	VERIFY(IS_WORKER);

	(void) bunyan_trace(log, "Creating new inbound IKEv2 packet",
	    BUNYAN_T_END);

	VERIFY(IS_P2ALIGNED(buf, sizeof (uint64_t)));

	hdr = (const ike_header_t *)buf;

	VERIFY3U(IKE_GET_MAJORV(hdr->version), ==,
	    IKE_GET_MAJORV(IKEV2_VERSION));

	pktkey = (hdr->flags & IKEV2_FLAG_RESPONSE) ?
	    LOG_KEY_RESP : LOG_KEY_REQ;

	/* These are added early in case there is an error */
	(void) bunyan_key_add(log,
	    BUNYAN_T_STRING, LOG_KEY_EXCHTYPE, ikev2_exch_str(hdr->exch_type),
	    BUNYAN_T_END);
	key_add_ike_spi(LOG_KEY_LSPI, ntohll(INBOUND_LOCAL_SPI(hdr)));
	key_add_ike_spi(LOG_KEY_RSPI, ntohll(INBOUND_REMOTE_SPI(hdr)));

	switch ((ikev2_exch_t)hdr->exch_type) {
	case IKEV2_EXCH_IKE_SA_INIT:
	case IKEV2_EXCH_IKE_AUTH:
	case IKEV2_EXCH_CREATE_CHILD_SA:
	case IKEV2_EXCH_INFORMATIONAL:
		break;
	case IKEV2_EXCH_IKE_SESSION_RESUME:
	case IKEV2_EXCH_GSA_AUTH:
	case IKEV2_EXCH_GSA_REGISTRATION:
	case IKEV2_EXCH_GSA_REKEY:
	default:
		(void) bunyan_info(log, "Unknown/unsupported exchange type",
		    BUNYAN_T_END);
		return (NULL);
	}

	/* pkt_in_alloc() will log any error messages */
	if ((pkt = pkt_in_alloc(buf, buflen, ikev2_pkt_checklen)) == NULL)
		return (NULL);

	(void) bunyan_key_add(log, BUNYAN_T_POINTER, pktkey, pkt, BUNYAN_T_END);

	if (!ikev2_pkt_check_payloads(pkt)) {
		ikev2_pkt_free(pkt);
		return (NULL);
	}

	/*
	 * Since these aren't encrypted or decrypted, once received it's
	 * contents are treated as immutable.
	 */
	if (hdr->exch_type == IKEV2_EXCH_IKE_SA_INIT)
		pkt->pkt_done = B_TRUE;

	return (pkt);
}

void
ikev2_pkt_free(pkt_t *pkt)
{
	if (pkt == NULL)
		return;

	pkt_free(pkt);
}

/*
 * All of the usage and caveats of pkt_add_payload() apply here as well.
 * For detailed information, see comments in pkt.c
 */
static boolean_t
ikev2_add_payload(pkt_t *pkt, ikev2_pay_type_t ptype, boolean_t critical,
    size_t len)
{
	uint8_t *payptr;
	uint8_t resv = 0;

	ASSERT(IKEV2_VALID_PAYLOAD(ptype));

	if (critical)
		resv |= IKEV2_CRITICAL_PAYLOAD;

	return (pkt_add_payload(pkt, ptype, resv, len));
}

boolean_t
ikev2_add_sa(pkt_t *restrict pkt, pkt_sa_state_t *restrict pss)
{
	return (pkt_add_sa(pkt, pss));
}

boolean_t
ikev2_add_prop(pkt_sa_state_t *pss, uint8_t propnum, ikev2_spi_proto_t proto,
    uint64_t spi)
{
	size_t spilen = ikev2_spilen(proto);

	if (proto == IKEV2_PROTO_IKE && spi == 0)
		spilen = 0;

	return (pkt_add_prop(pss, propnum, proto, spilen, spi));
}

boolean_t
ikev2_add_xform(pkt_sa_state_t *pss, ikev2_xf_type_t xftype, int xfid)
{
	return (pkt_add_xform(pss, xftype, xfid));
}

boolean_t
ikev2_add_xf_attr(pkt_sa_state_t *pss, ikev2_xf_attr_type_t xf_attr_type,
    uintptr_t arg)
{
	switch (xf_attr_type) {
	case IKEV2_XF_ATTR_KEYLEN:
		ASSERT3U(arg, <, 0x10000);
		return (pkt_add_xform_attr_tv(pss, IKEV2_XF_ATTR_KEYLEN,
		    (uint16_t)arg));
	}

	return (B_FALSE);
}

boolean_t
ikev2_add_xf_encr(pkt_sa_state_t *pss, ikev2_xf_encr_t encr, uint16_t minbits,
    uint16_t maxbits)
{
	const encr_data_t *ed = encr_data(encr);
	uint16_t incr = 0;
	boolean_t ok = B_TRUE;

	if (encr == IKEV2_ENCR_NONE || encr == IKEV2_ENCR_NULL) {
		INVALID("encr");
		/*NOTREACHED*/
		return (B_FALSE);
	}

	if (!encr_keylen_allowed(ed)) {
		VERIFY3U(minbits, ==, 0);
		VERIFY3U(maxbits, ==, 0);
		return (ikev2_add_xform(pss, IKEV2_XF_ENCR, encr));
	}

	if (minbits == 0 && maxbits == 0 && !encr_keylen_req(ed))
		return (ikev2_add_xform(pss, IKEV2_XF_ENCR, encr));

	VERIFY3U(minbits, >=, ed->ed_keymin);
	VERIFY3U(maxbits, <=, ed->ed_keymax);

	if (ed->ed_keyincr == 1) {
		/*
		 * For encryption methods that allow arbitrary key sizes,
		 * instead of adding a transform with every key length
		 * between the minimum and maximum values, we just add the
		 * minimum and maximum values.
		 */
		if (minbits != maxbits) {
			ok &= ikev2_add_xform(pss, IKEV2_XF_ENCR, encr);
			ok &= ikev2_add_xf_attr(pss, IKEV2_XF_ATTR_KEYLEN,
			    minbits);
		}
		ok &= ikev2_add_xform(pss, IKEV2_XF_ENCR, encr);
		ok &= ikev2_add_xf_attr(pss, IKEV2_XF_ATTR_KEYLEN, maxbits);
		return (ok);
	}

	for (size_t bits = minbits; bits <= maxbits; bits += ed->ed_keyincr) {
		ok &= ikev2_add_xform(pss, IKEV2_XF_ENCR, encr);
		ok &= ikev2_add_xf_attr(pss, IKEV2_XF_ATTR_KEYLEN, bits);
	}

	return (ok);
}

boolean_t
ikev2_add_ke(pkt_t *restrict pkt, ikev2_dh_t group, CK_OBJECT_HANDLE key)
{
	ikev2_ke_t		ke = { 0 };
	CK_SESSION_HANDLE	h = p11h();
	CK_ULONG		keylen = 0;
	CK_ATTRIBUTE		template = {
		.type = CKA_VALUE,
		.pValue = NULL_PTR,
		.ulValueLen = 0
	};
	CK_RV			rc = CKR_OK;

	rc = C_GetAttributeValue(h, key, &template, 1);
	if (rc != CKR_OK) {
		PKCS11ERR(error, "C_GetAttributeValue", rc);
		return (B_FALSE);
	}
	keylen = template.ulValueLen;

	if (!ikev2_add_payload(pkt, IKEV2_PAYLOAD_KE, B_FALSE,
	    sizeof (ke) + keylen)) {
		(void) bunyan_error(log,
		    "Not enough space in packet for DH pubkey",
		    BUNYAN_T_UINT64, "keylen", (uint64_t)keylen,
		    BUNYAN_T_END);
		return (B_FALSE);
	}

	ke.kex_dhgroup = htons((uint16_t)group);
	PKT_APPEND_STRUCT(pkt, ke);

	template.type = CKA_VALUE;
	template.pValue = pkt->pkt_ptr;
	template.ulValueLen = pkt_write_left(pkt);

	rc = C_GetAttributeValue(h, key, &template, 1);
	if (rc != CKR_OK) {
		PKCS11ERR(error, "C_GetAttributeValue", rc);
		return (B_FALSE);
	}
	pkt->pkt_ptr += keylen;

	return (B_TRUE);
}

static boolean_t
ikev2_add_id_common(pkt_t *restrict pkt, boolean_t id_i, ikev2_id_type_t idtype,
    va_list ap)
{
	ikev2_id_t		id = { 0 };
	ikev2_pay_type_t	paytype =
	    (id_i) ? IKEV2_PAYLOAD_IDi : IKEV2_PAYLOAD_IDr;
	const uint8_t		*data;
	size_t			len = 0;

	data = va_arg(ap, const uint8_t *);

	switch (idtype) {
	case IKEV2_ID_IPV4_ADDR:
		len = sizeof (in_addr_t);
		break;
	case IKEV2_ID_FQDN:
	case IKEV2_ID_RFC822_ADDR:
		len = strlen((const char *)data);
		break;
	case IKEV2_ID_IPV6_ADDR:
		len = sizeof (in6_addr_t);
		break;
	case IKEV2_ID_DER_ASN1_DN:
	case IKEV2_ID_DER_ASN1_GN:
	case IKEV2_ID_KEY_ID:
		len = va_arg(ap, size_t);
		break;
	case IKEV2_ID_FC_NAME:
		INVALID("idtype");
		break;
	}

	if (!ikev2_add_payload(pkt, paytype, B_FALSE, sizeof (id) + len))
		return (B_FALSE);	/* XXX: log? */

	id.id_type = (uint8_t)idtype;
	PKT_APPEND_STRUCT(pkt, id);
	VERIFY(pkt_append_data(pkt, data, len));
	return (B_TRUE);
}

boolean_t
ikev2_add_id(pkt_t *restrict pkt, boolean_t initiator, ikev2_id_type_t idtype,
    ...)
{
	va_list ap;
	boolean_t ret;

	va_start(ap, idtype);
	ret = ikev2_add_id_common(pkt, initiator, idtype, ap);
	va_end(ap);

	return (ret);
}

boolean_t
ikev2_add_id_i(pkt_t *restrict pkt, ikev2_id_type_t idtype, ...)
{
	va_list ap;
	boolean_t ret;

	va_start(ap, idtype);
	ret = ikev2_add_id_common(pkt, B_TRUE, idtype, ap);
	va_end(ap);
	return (ret);
}

boolean_t
ikev2_add_id_r(pkt_t *restrict pkt, ikev2_id_type_t idtype, ...)
{
	va_list ap;
	boolean_t ret;

	va_start(ap, idtype);
	ret = ikev2_add_id_common(pkt, B_FALSE, idtype, ap);
	va_end(ap);
	return (ret);
}

boolean_t
ikev2_add_cert(pkt_t *restrict pkt, ikev2_cert_t cert_type, const uint8_t *cert,
    size_t len)
{
	return (pkt_add_cert(pkt, IKEV2_PAYLOAD_CERT, cert_type, cert, len));
}

boolean_t
ikev2_add_certreq(pkt_t *restrict pkt, ikev2_cert_t cert_type,
    const uint8_t *cert, size_t len)
{
	return (pkt_add_cert(pkt, IKEV2_PAYLOAD_CERTREQ, cert_type, cert, len));
}

boolean_t
ikev2_add_auth(pkt_t *restrict pkt, ikev2_auth_type_t auth_method,
    const uint8_t *restrict data, size_t len)
{
	ikev2_auth_t auth = { 0 };

	if (!ikev2_add_payload(pkt, IKEV2_PAYLOAD_AUTH, B_FALSE,
	    sizeof (auth) + len))
		return (B_FALSE);

	auth.auth_method = (uint8_t)auth_method;
	PKT_APPEND_STRUCT(pkt, auth);
	VERIFY(pkt_append_data(pkt, data, len));
	return (B_TRUE);
}

boolean_t
ikev2_add_nonce(pkt_t *restrict pkt, uint8_t *restrict nonce, size_t len)
{
	VERIFY3U(len, <=, IKEV2_NONCE_MAX);
	VERIFY3U(len, >=, IKEV2_NONCE_MIN);

	if (!ikev2_add_payload(pkt, IKEV2_PAYLOAD_NONCE, B_FALSE, len))
		return (B_FALSE);

	VERIFY(pkt_append_data(pkt, nonce, len));
	return (B_TRUE);
}

boolean_t
ikev2_add_notify_full(pkt_t *restrict pkt, ikev2_spi_proto_t proto,
    uint64_t spi, ikev2_notify_type_t type, const void *restrict data,
    size_t len)
{
	size_t spisize = (spi == 0) ? 0 : ikev2_spilen(proto);

	return (pkt_add_notify(pkt, 0, proto, spisize, spi, type, data, len));
}

boolean_t
ikev2_add_notify(pkt_t *restrict pkt, ikev2_notify_type_t type)
{
	return (ikev2_add_notify_full(pkt, IKEV2_PROTO_NONE, 0, type, NULL, 0));
}

static boolean_t delete_finish(pkt_t *restrict, uint8_t *restrict, uintptr_t,
    size_t);

boolean_t
ikev2_add_delete(pkt_t *restrict pkt, ikev2_spi_proto_t proto,
    uint64_t *restrict spis, size_t nspi)
{
	ikev2_delete_t del = { 0 };
	size_t len = sizeof (del);

	VERIFY(proto != IKEV2_PROTO_IKE || nspi == 0);

	del.del_protoid = (uint8_t)proto;
	del.del_spisize = (proto == IKEV2_PROTO_IKE) ? 0 : ikev2_spilen(proto);

	len += del.del_spisize * nspi;
	if (!ikev2_add_payload(pkt, IKEV2_PAYLOAD_DELETE, B_FALSE, len))
		return (B_FALSE);

	PKT_APPEND_STRUCT(pkt, del);
	for (size_t i = 0; i < nspi; i++)
		VERIFY(pkt_add_spi(pkt, del.del_spisize, spis[i]));

	return (B_TRUE);
}

boolean_t
ikev2_add_vendor(pkt_t *restrict pkt, const void *restrict vid, size_t len)
{
	if (!ikev2_add_payload(pkt, IKEV2_PAYLOAD_VENDOR, B_FALSE, len))
		return (B_FALSE);
	VERIFY(pkt_append_data(pkt, vid, len));
	return (B_TRUE);
}

static boolean_t add_ts_common(pkt_t *restrict, ikev2_pkt_ts_state_t *restrict,
    boolean_t);

boolean_t
ikev2_add_ts_i(pkt_t *restrict pkt, ikev2_pkt_ts_state_t *restrict tstate)
{
	return (add_ts_common(pkt, tstate, B_TRUE));
}

boolean_t
ikev2_add_ts_r(pkt_t *restrict pkt, ikev2_pkt_ts_state_t *restrict tstate)
{
	return (add_ts_common(pkt, tstate, B_FALSE));
}

static boolean_t
add_ts_common(pkt_t *restrict pkt, ikev2_pkt_ts_state_t *restrict tstate,
    boolean_t ts_i)
{
	ikev2_tsp_t *tsp = NULL;
	ikev2_payload_t *payp = (ikev2_payload_t *)pkt->pkt_ptr;
	ikev2_pay_type_t ptype;

	ptype = ts_i ? IKEV2_PAYLOAD_TSi : IKEV2_PAYLOAD_TSr;

	if (!ikev2_add_payload(pkt, ptype, B_FALSE, sizeof (*tsp)))
		return (B_FALSE);
	tsp = (ikev2_tsp_t *)pkt->pkt_ptr;

	tstate->i2ts_pkt = pkt;
	tstate->i2ts_len = sizeof (ikev2_payload_t);
	tstate->i2ts_lenp = &payp->pld_length;
	tstate->i2ts_idx = pkt_get_payload(pkt, ptype, NULL);
	tstate->i2ts_countp = &tsp->tsp_count;

	VERIFY3P(tstate->i2ts_idx, !=, NULL);

	/* Skip over the TS header -- we update the count as we add TSes */
	pkt->pkt_ptr += sizeof (*tsp);
	tstate->i2ts_len += sizeof (*tsp);
	tstate->i2ts_idx->pp_len += sizeof (*tsp);
	BE_OUT16(tstate->i2ts_lenp, tstate->i2ts_len);

	return (B_TRUE);
}

boolean_t
ikev2_add_ts(ikev2_pkt_ts_state_t *restrict tstate, uint8_t ip_proto,
    const struct sockaddr *restrict start, const struct sockaddr *restrict end)
{
	ikev2_ts_t ts = { 0 };
	const void *startptr = NULL;
	const void *endptr = NULL;
	size_t len = 0;
	size_t addrlen = 0;
	uint32_t start_port = 0, end_port = 0;

	VERIFY3U(start->sa_family, ==, end->sa_family);

	if (*tstate->i2ts_countp == UINT8_MAX) {
		(void) bunyan_error(log,
		    "Tried to add >255 traffic selectors in packet",
		    BUNYAN_T_END);
		return (B_FALSE);
	}

	ts.ts_protoid = ip_proto;

	startptr = ss_addr(start);
	endptr = ss_addr(end);
	addrlen = ss_addrlen(start);

	start_port = ss_port(start);
	end_port = ss_port(end);

	ts.ts_startport = htons((uint16_t)start_port);
	ts.ts_endport = htons((uint16_t)end_port);

	switch (start->sa_family) {
	case AF_INET:
		ts.ts_type = IKEV2_TS_IPV4_ADDR_RANGE;
		break;
	case AF_INET6:
		ts.ts_type = IKEV2_TS_IPV6_ADDR_RANGE;
		break;
	default:
		INVALID(start->sa_family);
	}

	len = sizeof (ts) + 2 * addrlen;

	ts.ts_protoid = ip_proto;
	ts.ts_length = htons(len);

	if (pkt_write_left(tstate->i2ts_pkt) < len ||
	    tstate->i2ts_len + len > UINT16_MAX) {
		(void) bunyan_error(log,
		    "Ran out of space to write traffic selectors",
		    BUNYAN_T_END);
		return (B_FALSE);
	}

	PKT_APPEND_STRUCT(tstate->i2ts_pkt, ts);
	VERIFY(pkt_append_data(tstate->i2ts_pkt, startptr, addrlen));
	VERIFY(pkt_append_data(tstate->i2ts_pkt, endptr, addrlen));

	tstate->i2ts_len += len;

	/* Update TS count in payload */
	(*tstate->i2ts_countp)++;

	/* Update payload index length */
	tstate->i2ts_idx->pp_len += len;

	/* Update payload length in packet */
	BE_OUT16(tstate->i2ts_lenp, tstate->i2ts_len);

	return (B_TRUE);
}

static void
ts_get_addrs(ikev2_ts_t *restrict ts, struct sockaddr_storage *restrict start,
    struct sockaddr_storage *restrict end)
{
	uint8_t *startp = NULL, *endp = NULL, *addrp = NULL;
	size_t len = 0, port_offset = 0;

	bzero(start, sizeof (*start));
	bzero(end, sizeof (*end));

	switch (ts->ts_type) {
	case IKEV2_TS_IPV4_ADDR_RANGE:
		len = sizeof (in_addr_t);
		start->ss_family = end->ss_family = AF_INET;
		port_offset = offsetof(struct sockaddr_in, sin_port);
		break;
	case IKEV2_TS_IPV6_ADDR_RANGE:
		len = sizeof (in6_addr_t);
		start->ss_family = end->ss_family = AF_INET;
		port_offset = offsetof(struct sockaddr_in6, sin6_port);
		break;
	case IKEV2_TS_FC_ADDR_RANGE:
		break;
	}

	addrp = (uint8_t *)(ts + 1);
	startp = (uint8_t *)ss_addr(SSTOSA(start));
	endp = (uint8_t *)ss_addr(SSTOSA(end));

	bcopy(addrp, startp, len);
	bcopy(addrp + len, endp, len);
	bcopy(&ts->ts_startport, startp + port_offset, sizeof (uint16_t));
	bcopy(&ts->ts_endport, endp + port_offset, sizeof (uint16_t));
}

static boolean_t
ts_type_is_supported(ikev2_ts_type_t type)
{
	/*
	 * We avoid having a default case so that any new TS types that are
	 * defined but unhandled here will trigger a compilation error instead
	 * of potentially cause runtime problems.
	 */
	switch (type) {
	case IKEV2_TS_IPV4_ADDR_RANGE:
	case IKEV2_TS_IPV6_ADDR_RANGE:
		return (B_TRUE);
	case IKEV2_TS_FC_ADDR_RANGE:
		return (B_FALSE);
	}
	return (B_FALSE);
}

ikev2_ts_t *
ikev2_ts_iter(pkt_payload_t *restrict tsp, ikev2_ts_iter_t *restrict iter,
    struct sockaddr_storage *restrict start,
    struct sockaddr_storage *restrict end)
{
	iter->i2ti_tsp = (ikev2_tsp_t *)tsp->pp_ptr;
	iter->i2ti_ts = (ikev2_ts_t *)(iter->i2ti_tsp + 1);
	iter->i2ti_n = 0;

	if (iter->i2ti_n >= iter->i2ti_tsp->tsp_count)
		return (NULL);

	/*
	 * RFC7296 2.9 -- Unknown TS types should be skipped.
	 * We also skip unsupported TS types
	 */
	if (!ts_type_is_supported(iter->i2ti_ts->ts_type))
		return (ikev2_ts_iter_next(iter, start, end));

	ts_get_addrs(iter->i2ti_ts, start, end);
	return (iter->i2ti_ts);
}

ikev2_ts_t *
ikev2_ts_iter_next(ikev2_ts_iter_t *restrict iter,
    struct sockaddr_storage *restrict start,
    struct sockaddr_storage *restrict end)
{
	boolean_t known = B_FALSE;

	/*
	 * RFC7296 2.9 -- Unknown TS types should be skipped.
	 * We also skip unsupported TS types.
	 */
	do {
		if (++iter->i2ti_n > iter->i2ti_tsp->tsp_count)
			return (NULL);

		uint8_t *p = (uint8_t *)iter->i2ti_ts;

		p += BE_IN16(&iter->i2ti_ts->ts_length);
		iter->i2ti_ts = (ikev2_ts_t *)p;
		known = ts_type_is_supported(iter->i2ti_ts->ts_type);
	} while (!known);

	ts_get_addrs(iter->i2ti_ts, start, end);
	return (iter->i2ti_ts);
}

static boolean_t add_iv(pkt_t *restrict pkt);

boolean_t
ikev2_add_sk(pkt_t *restrict pkt)
{
	ikev2_sa_t *sa = pkt->pkt_sa;
	ikev2_payload_t *payp = (ikev2_payload_t *)pkt->pkt_ptr;

	if (!ikev2_add_payload(pkt, IKEV2_PAYLOAD_SK, B_FALSE, 0))
		return (B_FALSE);

	return (add_iv(pkt));
}

/*
 * Add the IV to the packet.  It should be noted that the packet
 * buffer is always zero-filled to start, and we never shift data around
 * in the packet buffer, so anywhere we skip over a section and fill in later,
 * any untouched bytes will be zero.
 */
static boolean_t
add_iv(pkt_t *restrict pkt)
{
	ikev2_sa_t *sa = pkt->pkt_sa;
	const encr_data_t *ed = encr_data(sa->encr);
	size_t len = ed->ed_blocklen;

	if (pkt_write_left(pkt) < len)
		return (B_FALSE);

	switch (ed->ed_mode) {
	case MODE_CCM:
	case MODE_GCM: {
		uint32_t msgid = ntohl(pkt_header(pkt)->msgid);
		/*
		 * For these modes, it's sufficient that the IV + key
		 * is unique.  The packet message id satisifies these
		 * requirements.
		 */
		VERIFY(put32(pkt, msgid));
		pkt->pkt_ptr += (len - sizeof (msgid));
		return (B_TRUE);
	}
	case MODE_CTR:
		/* TODO */
		return (B_FALSE);
	case MODE_CBC:
		/* Done below */
		break;
	case MODE_NONE:
		INVALID("mode");
		break;
	}

	/*
	 * NIST 800-38A, Appendix C indicates that encrypting a counter
	 * should be acceptable to produce a unique, unpredictable IV.
	 */
	CK_SESSION_HANDLE h = p11h();
	CK_MECHANISM mech;
	CK_OBJECT_HANDLE key;
	CK_ULONG blocklen = ed->ed_blocklen;
	CK_RV rc = CKR_OK;
	uint32_t msgid = ntohl(pkt_header(pkt)->msgid);

	if (sa->flags & I2SA_INITIATOR)
		key = sa->sk_ei;
	else
		key = sa->sk_er;

	switch (sa->encr) {
	case IKEV2_ENCR_AES_CBC:
		mech.mechanism = CKM_AES_ECB;
		mech.pParameter = NULL_PTR;
		mech.ulParameterLen = 0;
		break;
	case IKEV2_ENCR_CAMELLIA_CBC:
		mech.mechanism = CKM_CAMELLIA_ECB;
		mech.pParameter = NULL_PTR;
		mech.ulParameterLen = 0;
		break;
	default:
		INVALID(sa->encr);
		/*NOTREACHED*/
		return (B_FALSE);
	}
	CK_BYTE buf[blocklen];

	bzero(buf, blocklen);
	bcopy(&msgid, buf, sizeof (msgid));

	rc = C_EncryptInit(h, &mech, key);
	if (rc != CKR_OK) {
		PKCS11ERR(error, "C_EncryptInit", rc);
		return (B_FALSE);
	}

	rc = C_Encrypt(h, buf, blocklen, buf, &blocklen);
	if (rc != CKR_OK) {
		PKCS11ERR(error, "C_Encrypt", rc);
		return (B_FALSE);
	}

	bcopy(buf, pkt->pkt_ptr, MIN(len, blocklen));
	explicit_bzero(buf, blocklen);
	pkt->pkt_ptr += MIN(len, blocklen);
	return (B_TRUE);
}

boolean_t
ikev2_add_config(pkt_t *pkt, ikev2_cfg_type_t cfg_type)
{
	/* TODO */
	return (B_FALSE);
}

boolean_t
ikev2_add_config_attr(pkt_t *restrict pkt,
    ikev2_cfg_attr_type_t cfg_attr_type, const void *restrict data)
{
	/* TODO */
	return (B_FALSE);
}

boolean_t
ikev2_pkt_encryptdecrypt(pkt_t *pkt, boolean_t encrypt)
{
	ikev2_sa_t *sa = pkt->pkt_sa;
	const encr_data_t *ed = encr_data(sa->encr);
	pkt_payload_t *sk = pkt_get_payload(pkt, IKEV2_PAYLOAD_SK, NULL);
	const char *fn = NULL;
	CK_SESSION_HANDLE h = p11h();
	CK_MECHANISM mech;
	CK_OBJECT_HANDLE key;
	union {
		CK_AES_CTR_PARAMS	aes_ctr;
		CK_CAMELLIA_CTR_PARAMS	cam_ctr;
		CK_GCM_PARAMS		gcm;
		CK_CCM_PARAMS		ccm;
	} params;
	CK_BYTE_PTR salt = NULL, iv = NULL, data = NULL, icv = NULL;
	CK_ULONG ivlen = ed->ed_blocklen;
	CK_ULONG icvlen = ikev2_auth_icv_size(sa->encr, sa->auth);
	CK_ULONG blocklen = ed->ed_blocklen;
	CK_ULONG noncelen = ivlen + SADB_1TO8(sa->saltlen);
	CK_ULONG datalen = 0, outlen = 0;
	CK_BYTE nonce[noncelen];
	CK_RV rc = CKR_OK;
	encr_modes_t mode = ed->ed_mode;
	uint8_t padlen = 0;

	VERIFY(IS_WORKER);
	VERIFY(MUTEX_HELD(&sa->i2sa_lock));

	if (pkt_header(pkt)->flags & IKEV2_FLAG_INITIATOR) {
		key = sa->sk_ei;
		salt = sa->salt_i;
	} else {
		key = sa->sk_er;
		salt = sa->salt_r;
	}

	outlen = pkt_write_left(pkt) + icvlen;
	iv = sk->pp_ptr;
	data = iv + ivlen;

	if (encrypt) {
		datalen = (CK_ULONG)(pkt->pkt_ptr - data) - icvlen;
		/* If we're creating it, lengths should match */
		VERIFY3U(sk->pp_len, ==, ivlen + datalen + icvlen);
	} else if (sk->pp_len > ivlen + icvlen) {
		datalen = sk->pp_len - ivlen - icvlen;
	} else {
		(void) bunyan_info(log,
		    "Encrypted payload invalid length",
		    BUNYAN_T_UINT32, "paylen", (uint32_t)sk->pp_len,
		    BUNYAN_T_UINT32, "ivlen", (uint32_t)ivlen,
		    BUNYAN_T_UINT32, "datalen", (uint32_t)datalen,
		    BUNYAN_T_UINT32, "icvlen", (uint32_t)icvlen,
		    BUNYAN_T_END);
		return (B_FALSE);
	}

	icv = data + datalen;

	bcopy(iv, nonce, ivlen);
	if (sa->saltlen > 0)
		bcopy(salt, nonce + ivlen, SADB_1TO8(sa->saltlen));

	mech.mechanism = ed->ed_p11id;
	switch (mode) {
	case MODE_NONE:
		break;
	case MODE_CBC:
		mech.pParameter = nonce;
		mech.ulParameterLen = noncelen;
		break;
	case MODE_CTR:
		/* TODO */
		break;
	case MODE_CCM:
		params.ccm.pAAD = pkt_start(pkt);
		params.ccm.ulAADLen = (CK_ULONG)(iv - pkt_start(pkt));
		params.ccm.ulMACLen = icvlen;
		params.ccm.pNonce = nonce;
		params.ccm.ulNonceLen = noncelen;
		mech.pParameter = &params.ccm;
		mech.ulParameterLen = sizeof (CK_CCM_PARAMS);
		break;
	case MODE_GCM:
		params.gcm.pIv = nonce;
		params.gcm.ulIvLen = noncelen;
		/*
		 * There is a 'ulIvBits' field in CK_GCM_PARAMS.  This is from
		 * the pkcs11t.h file published from OASIS.  However, it does
		 * not appear to actually be used for anything, and looks to
		 * be a leftover from the unpublished PKCS#11 v2.30 standard.
		 * It is currently not set and ignored.
		 */
		params.gcm.pAAD = pkt_start(pkt);
		params.gcm.ulAADLen = (CK_ULONG)(iv - params.gcm.pAAD);
		params.gcm.ulTagBits = icvlen * 8;
		mech.pParameter = &params.gcm;
		mech.ulParameterLen = sizeof (CK_GCM_PARAMS);
		break;
	}

	/*
	 * As nice as it would be, it appears the combined mode functions
	 * (e.g. C_SignEncrypt) both operate on the plaintext.  However
	 * we must sign the encrypted text, so must do it in different
	 * operations.
	 */
	if (encrypt) {
		fn = "C_EncryptInit";
		rc = C_EncryptInit(h, &mech, key);
	} else {
		fn = "C_DecryptInit";
		rc = C_DecryptInit(h, &mech, key);
	}
	if (rc != CKR_OK) {
		PKCS11ERR(error, fn, rc);
		return (B_FALSE);
	}

	if (encrypt) {
		fn = "C_Encrypt";
		rc = C_Encrypt(h, data, datalen, data, &outlen);
	} else {
		fn = "C_Decrypt";
		rc = C_Decrypt(h, data, datalen, data, &outlen);
	}
	if (rc != CKR_OK) {
		PKCS11ERR(error, "C_Encrypt", rc,
		    BUNYAN_T_UINT64, "outlen", (uint64_t)outlen,
		    BUNYAN_T_END);
		return (B_FALSE);
	}

	if (encrypt)
		return (B_TRUE);

	/*
	 * As described in ikev2_pkt_done(), we choose to use PKCS#7 style
	 * padding, however our peer can use arbitrary values for padding.
	 * When we know we are communicating with another illumos peer, we
	 * explicity verify the padding.  This is due to the lessons learned
	 * from exploits from TLS, etc. that exploit lack of padding checks.
	 */
	if (sa->vendor == VENDOR_ILLUMOS_1) {
		uint8_t *pad;

		padlen = icv[-1];
		pad = icv - padlen - 1;

		for (size_t i = 0; i <= padlen; i++) {
			if (pad[i] == padlen)
				continue;

			(void) bunyan_warn(log,
			    "Padding validation failed",
			    BUNYAN_T_UINT32, "padlen", (uint32_t)padlen,
			    BUNYAN_T_UINT32, "offset", (uint32_t)i,
			    BUNYAN_T_END);
			return (B_FALSE);
		}
	}
	datalen -= padlen + 1;
	pkt->pkt_decrypted = B_TRUE;

	ike_payload_t *skpay = pkt_idx_to_payload(sk);

	if (!pkt_check_payloads(skpay->pay_next, data, datalen,
	    ikev2_pkt_checklen))
		return (B_FALSE);
	if (!pkt_index_payloads(pkt, data, datalen, skpay->pay_next))
		return (B_FALSE);

	/* Indicate packet contents is now treated immutable */
	pkt->pkt_done = B_TRUE;
	return (B_TRUE);
}

boolean_t
ikev2_pkt_signverify(pkt_t *pkt, boolean_t sign)
{
	ikev2_sa_t *sa = pkt->pkt_sa;
	const encr_data_t *ed = encr_data(sa->encr);
	const auth_data_t *ad = auth_data(sa->auth);

	if (MODE_IS_COMBINED(ed->ed_mode))
		return (B_TRUE);

	const char *fn = NULL;
	pkt_payload_t *sk = pkt_get_payload(pkt, IKEV2_PAYLOAD_SK, NULL);
	CK_SESSION_HANDLE h = p11h();
	CK_OBJECT_HANDLE key;
	CK_MECHANISM mech = {
		.mechanism = ad->ad_p11id,
		.pParameter = NULL_PTR,
		.ulParameterLen = 0
	};
	CK_BYTE_PTR icv;
	CK_ULONG signlen, icvlen;
	CK_ULONG outlen = ad->ad_outlen;
	CK_BYTE outbuf[outlen];
	CK_RV rc;

	if (pkt_header(pkt)->flags & IKEV2_FLAG_INITIATOR)
		key = sa->sk_ai;
	else
		key = sa->sk_ar;

	icvlen = ikev2_auth_icv_size(sa->encr, sa->auth);
	if (sizeof (ike_header_t) + sizeof (ikev2_payload_t) + icvlen >
	    pkt_len(pkt)) {
		(void) bunyan_warn(log, "SK payload is truncated",
		    BUNYAN_T_END);
		return (B_FALSE);
	}

	signlen = pkt_len(pkt) - icvlen;
	icv = pkt->pkt_ptr - icvlen;

	VERIFY3U(icvlen, <=, outlen);

	rc = C_SignInit(h, &mech, key);
	if (rc != CKR_OK) {
		PKCS11ERR(error, "C_SignInit", rc);
		return (B_FALSE);
	}

	rc = C_Sign(h, pkt_start(pkt), signlen, outbuf, &outlen);
	if (rc != CKR_OK) {
		PKCS11ERR(error, "C_Sign", rc);
		explicit_bzero(outbuf, outlen);
		return (B_FALSE);
	}

	if (sign) {
		bcopy(outbuf, icv, icvlen);
		explicit_bzero(outbuf, outlen);
		return (B_TRUE);
	} else if (memcmp(icv, outbuf, icvlen) == 0) {
		explicit_bzero(outbuf, outlen);
		return (B_TRUE);
	}

	(void) bunyan_warn(log, "Payload signature validation failed",
	    BUNYAN_T_END);

	explicit_bzero(outbuf, outlen);
	return (B_FALSE);
}

boolean_t
ikev2_pkt_done(pkt_t *pkt)
{
	if (pkt->pkt_done)
		return (B_TRUE);

	pkt_payload_t *sk = pkt_get_payload(pkt, IKEV2_PAYLOAD_SK, NULL);

	if (pkt_header(pkt)->exch_type == IKEV2_EXCH_IKE_SA_INIT) {
		VERIFY3P(sk, ==, NULL);
		return (pkt_done(pkt));
	}

	VERIFY3P(sk, !=, NULL);

	ike_payload_t *skpay = pkt_idx_to_payload(sk);
	ikev2_sa_t *sa = pkt->pkt_sa;
	const encr_data_t *ed = encr_data(sa->encr);
	CK_ULONG datalen = (CK_ULONG)(pkt->pkt_ptr - sk->pp_ptr);
	CK_ULONG icvlen = ikev2_auth_icv_size(sa->encr, sa->auth);
	CK_ULONG blocklen = ed->ed_blocklen;
	uint16_t sklen = 0;
	boolean_t ok = B_TRUE;
	uint8_t padlen = 0;

	/*
	 * Per RFC7296 3.14, the sender can choose any value for the padding.
	 * We elect to use PKCS#7 style padding (repeat the pad value as the
	 * padding).  This is well studied and appears to work.
	 */
	if ((datalen + 1) % blocklen != 0)
		padlen = blocklen - ((datalen + 1) % blocklen);

	if (pkt_write_left(pkt) < padlen + 1 + icvlen) {
		(void) bunyan_info(log, "Not enough space for packet",
		    BUNYAN_T_END);
		goto done;
	}

	/*
	 * Since we are writing out pad length as the padding value, and
	 * the pad length field is immediately after the padding, we
	 * can just write padlen + 1 bytes of data whose value is padlen
	 */
	for (size_t i = 0; i <= padlen; i++)
		pkt->pkt_ptr[i] = padlen;
	pkt->pkt_ptr += padlen + 1;

	/*
	 * Skip over the space for the ICV.  This is necessary so that all
	 * the lengths (packet, payload) are updated with the final values
	 * prior to encryption and signing.
	 */
	pkt->pkt_ptr += icvlen;

	sklen = (uint16_t)(pkt->pkt_ptr - sk->pp_ptr);
	sk->pp_len = sklen;
	BE_OUT16(&skpay->pay_length, sklen + sizeof (ike_payload_t));

	ok = pkt_done(pkt);
	ok &= ikev2_pkt_encryptdecrypt(pkt, B_TRUE);
	ok &= ikev2_pkt_signverify(pkt, B_TRUE);

done:
	return (ok);
}

/*
 * Create a abbreviated string listing the payload types (in order).
 * Mostly for diagnostic purposes.
 *
 * Example: 'N(COOKIE), SA, KE, No'
 */
custr_t *
ikev2_pkt_desc(pkt_t *pkt)
{
	custr_t *cstr = NULL;
	uint16_t i;
	uint16_t j;

	if (custr_alloc(&cstr) != 0)
		return (NULL);

	for (i = j = 0; i < pkt->pkt_payload_count; i++) {
		pkt_payload_t *pay = pkt_payload(pkt, i);
		const char *paystr =
		    ikev2_pay_short_str((ikev2_pay_type_t)pay->pp_type);

		if (i > 0 && custr_appendc(cstr, ',') != 0 &&
		    custr_appendc(cstr, ' ') != 0)
			goto fail;

		if (custr_append(cstr, paystr) != 0)
			goto fail;

		if (pay->pp_type == IKEV2_PAYLOAD_NOTIFY) {
			pkt_notify_t *n = pkt_notify(pkt, j++);
			const char *nstr =
			    ikev2_notify_str((ikev2_notify_type_t)n->pn_type);

			if (custr_appendc(cstr, '(') != 0)
				goto fail;
			if (custr_append(cstr, nstr) != 0)
				goto fail;
			if (custr_appendc(cstr, ')') != 0)
				goto fail;
		}
	}

	return (cstr);

fail:
	custr_free(cstr);
	return (NULL);
}

static struct {
	const char *str;
	uint8_t val;
} flagtbl[] = {
	{ "RESPONSE", IKEV2_FLAG_RESPONSE },
	{ "VERSION", IKEV2_FLAG_VERSION },
	{ "INITIATOR", IKEV2_FLAG_INITIATOR }
};

void
ikev2_pkt_log(pkt_t *restrict pkt, bunyan_level_t level, const char *msg)
{
	ike_header_t *hdr = pkt_header(pkt);
	custr_t *desc = ikev2_pkt_desc(pkt);
	char ispi[19];
	char rspi[19];
	char flag[30];

	(void) snprintf(ispi, sizeof (ispi), "0x%" PRIX64,
	    ntohll(hdr->initiator_spi));
	(void) snprintf(rspi, sizeof (rspi), "0x%" PRIX64,
	    ntohll(hdr->responder_spi));
	(void) snprintf(flag, sizeof (flag), "0x%" PRIx8, hdr->flags);

	if (hdr->flags != 0) {
		size_t count = 0;

		(void) strlcat(flag, "<", sizeof (flag));
		for (size_t i = 0; i < ARRAY_SIZE(flagtbl); i++) {
			if (hdr->flags & flagtbl[i].val) {
				if (count > 0) {
					(void) strlcat(flag, ",",
					    sizeof (flag));
				}
				(void) strlcat(flag, flagtbl[i].str,
				    sizeof (flag));
				count++;
			}
		}
		(void) strlcat(flag, ">", sizeof (flag));
	}

	getlog(level)(log, msg,
	    BUNYAN_T_POINTER, "pkt", pkt,
	    BUNYAN_T_STRING, "initiator_spi", ispi,
	    BUNYAN_T_STRING, "responder_spi", rspi,
	    BUNYAN_T_STRING, "exch_type", ikev2_exch_str(hdr->exch_type),
	    BUNYAN_T_UINT32, "msgid", ntohl(pkt_header(pkt)->msgid),
	    BUNYAN_T_UINT32, "msglen", ntohl(pkt_header(pkt)->length),
	    BUNYAN_T_STRING, "flags", flag,
	    BUNYAN_T_UINT32, "nxmit", (uint32_t)pkt->pkt_xmit,
	    BUNYAN_T_STRING, "payloads", (desc != NULL) ? custr_cstr(desc) : "",
	    BUNYAN_T_END);
	custr_free(desc);
}

ikev2_sa_proposal_t *
ikev2_prop_first(pkt_payload_t *sapay)
{
	VERIFY3U(sapay->pp_type, ==, IKEV2_PAYLOAD_SA);
	return ((ikev2_sa_proposal_t *)sapay->pp_ptr);
}

ikev2_sa_proposal_t *
ikev2_prop_end(pkt_payload_t *sapay)
{
	VERIFY3U(sapay->pp_type, ==, IKEV2_PAYLOAD_SA);
	return ((ikev2_sa_proposal_t *)(sapay->pp_ptr + sapay->pp_len));
}

ikev2_sa_proposal_t *
ikev2_prop_next(ikev2_sa_proposal_t *prop)
{
	uint16_t len = BE_IN16(&prop->proto_length);
	return ((ikev2_sa_proposal_t *)((uint8_t *)prop + len));
}

uint64_t
ikev2_prop_spi(ikev2_sa_proposal_t *prop)
{
	uint8_t *addr = (uint8_t *)(prop + 1);
	uint64_t spi = 0;

	if (!pkt_get_spi(&addr, prop->proto_spisize, &spi))
		return (0);
	return (spi);
}

ikev2_transform_t *
ikev2_xf_first(ikev2_sa_proposal_t *prop)
{
	uint8_t *p = (uint8_t *)(prop + 1) + prop->proto_spisize;
	return ((ikev2_transform_t *)p);
}

ikev2_transform_t *
ikev2_xf_next(ikev2_transform_t *xf)
{
	uint16_t len = BE_IN16(&xf->xf_length);
	return ((ikev2_transform_t *)((uint8_t *)xf + len));
}

ikev2_transform_t *
ikev2_xf_end(ikev2_sa_proposal_t *prop)
{
	return ((ikev2_transform_t *)ikev2_prop_next(prop));
}

ikev2_attribute_t *
ikev2_attr_first(ikev2_transform_t *xf)
{
	return ((ikev2_attribute_t *)(xf + 1));
}

ikev2_attribute_t *
ikev2_attr_end(ikev2_transform_t *xf)
{
	return ((ikev2_attribute_t *)ikev2_xf_next(xf));
}

ikev2_attribute_t *
ikev2_attr_next(ikev2_attribute_t *attr)
{
	uint16_t type = BE_IN16(&attr->attr_type);
	uint16_t len = BE_IN16(&attr->attr_length);

	if (type & IKEV2_ATTRAF_TV)
		return (attr + 1);
	return ((ikev2_attribute_t *)((uint8_t *)attr + len));
}

/* Retrieve the DH group value from a key exchange payload */
ikev2_dh_t
ikev2_get_dhgrp(pkt_t *pkt)
{
	pkt_payload_t *ke = pkt_get_payload(pkt, IKEV2_PAYLOAD_KE, NULL);
	uint16_t val = 0;

	if (ke == NULL)
		return (IKEV2_DH_NONE);

	VERIFY3U(ke->pp_len, >, sizeof (val));
	return (BE_IN16(ke->pp_ptr));
}

size_t
ikev2_spilen(ikev2_spi_proto_t proto)
{
	switch (proto) {
	case IKEV2_PROTO_NONE:
		return (0);
	case IKEV2_PROTO_AH:
	case IKEV2_PROTO_ESP:
	case IKEV2_PROTO_FC_ESP_HEADER:
	case IKEV2_PROTO_FC_CT_AUTH:
		return (sizeof (uint32_t));
	case IKEV2_PROTO_IKE:
		return (sizeof (uint64_t));
	}

	/*NOTREACHED*/
	return (0);
}

boolean_t
ikev2_invalid_ke(pkt_t *resp, ikev2_dh_t dh)
{
	uint16_t val = htons(dh);

	/* This notification can only appear in a response */
	VERIFY(I2P_RESPONSE(resp));

	if (!ikev2_add_notify_full(resp, IKEV2_PROTO_NONE, 0,
	    IKEV2_N_INVALID_KE_PAYLOAD, &val, sizeof (val)))
		return (B_FALSE);

	return (B_TRUE);
}
