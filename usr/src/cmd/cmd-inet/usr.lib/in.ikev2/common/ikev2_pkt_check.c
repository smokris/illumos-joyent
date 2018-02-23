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
 * Copyright 2018, Joyent, Inc.
 */

#include <inttypes.h>
#include <bunyan.h>
#include <note.h>
#include <netinet/in.h>
#include <strings.h>
#include <sys/debug.h>
#include "defs.h"
#include "ikev2.h"
#include "ikev2_enum.h"
#include "ikev2_pkt.h"
#include "ikev2_pkt_check.h"
#include "pkt.h"
#include "pkt_impl.h"

extern __thread bunyan_logger_t *log;

/*
 * All the payload checks take a pointer and length to the payload data i.e.
 * they exclude the payload header.  Though to (hopefully) be less confusing,
 * we report sizes including the payload header to reflect the value seen
 * or expected in the payload header.  We use size_t's so that we can
 * perform addition on any payload sizes without fear of overflow.
 */

/* Cast to uint32_t so bunyan logging isn't full of casts */
#define	L(_len)	((uint32_t)((_len) + sizeof (ikev2_payload_t)))

static boolean_t
check_payload_size(const char *name, size_t buflen, size_t min, size_t max)
{
	char msg[128] = { 0 };

	/*
	 * The IKEv2 wire format only allows 16 bits for the length of a
	 * payload, so it is impossible for a user-supplied datagram to
	 * contain a length > UINT16_MAX.  If we encounter such a value, it
	 * indicates a programming error, hence the VERIFY check instead of
	 * merely returning B_FALSE.
	 */
	VERIFY3U(buflen, <=, UINT16_MAX);

	if (buflen < min) {
		(void) snprintf(msg, sizeof (msg),
		    "%s payload is smaller than minimum required", name);
		(void) bunyan_warn(log, msg,
		    BUNYAN_T_UINT32, "buflen", L(buflen),
		    BUNYAN_T_UINT32, "minimum", L(min),
		    BUNYAN_T_END);
		return (B_FALSE);
	}

	if (max > 0 && buflen > max) {
		(void) snprintf(msg, sizeof (msg),
		    "%s payload is larger than maximum allowed", name);
		(void) bunyan_warn(log, msg,
		    BUNYAN_T_UINT32, "buflen", L(buflen),
		    BUNYAN_T_UINT32, "maximum", L(max),
		    BUNYAN_T_END);
		return (B_FALSE);
	}
	return (B_TRUE);
}

static boolean_t
ikev2_checklen_xfattr(const uint8_t *buf, size_t buflen)
{
	const uint8_t *end = buf + buflen;

	while (buf < end) {
		const ikev2_attribute_t *attr = (const ikev2_attribute_t *)buf;
		size_t attr_len = 0;
		uint16_t attr_type;

		if (buf + sizeof (*attr) > end)
			goto truncated;

		attr_type = BE_IN16(&attr->attr_type);
		if (attr_type & IKEV2_ATTRAF_TV) {
			attr_len = sizeof (*attr);
		} else {
			attr_len = BE_IN16(&attr->attr_length);
		}

		if (buf + attr_len > end)
			goto truncated;

		buf += attr_len;
	}

	return (B_TRUE);

truncated:
	(void) bunyan_warn(log, "SA transform attribute is truncated",
	    BUNYAN_T_END);
	return (B_FALSE);
}

static boolean_t
ikev2_checklen_prop(const uint8_t *buf, size_t buflen)
{
	const ikev2_sa_proposal_t *propp = (const ikev2_sa_proposal_t *)buf;
	const uint8_t *ptr = buf;
	const uint8_t *end = buf + buflen;

	ptr += sizeof (*propp) + propp->proto_spisize;
	for (uint32_t i = 0; i < propp->proto_transforms; i++) {
		const ikev2_transform_t *xf = (const ikev2_transform_t *)ptr;
		const uint8_t *attrp;
		uint32_t xflen = 0, attrlen = 0;

		if (ptr + sizeof (*xf) > end) {
			(void) bunyan_warn(log, "Transform header truncated",
			    BUNYAN_T_END);
			return (B_FALSE);
		}

		xflen = BE_IN16(&xf->xf_length);
		if (xflen < sizeof (*xf)) {
			(void) bunyan_warn(log, "Transform length mismatch",
			    BUNYAN_T_UINT32, "xflen", xflen,
			    BUNYAN_T_UINT32, "minlen", (uint32_t)sizeof (*xf),
			    BUNYAN_T_END);
			return (B_FALSE);
		}

		if (ptr + xflen > end) {
			(void) bunyan_warn(log,
			    "Transform overruns end of SA payload",
			    BUNYAN_T_UINT32, "proposal_num",
			    (uint32_t)propp->proto_proposalnr,
			    BUNYAN_T_UINT32, "xfnum", i,
			    BUNYAN_T_UINT32, "overrun_amt",
			    (uint32_t)(end - ptr) - xflen,
			    BUNYAN_T_END);
			return (B_FALSE);
		}

		attrp = ptr + sizeof (*xf);
		attrlen = xflen - sizeof (*xf);

		if ((attrlen > 0) && !ikev2_checklen_xfattr(attrp, attrlen))
			return (B_FALSE);

		ptr += xflen;
	}

	if (ptr < end) {
		(void) bunyan_warn(log, "SA payload has trailing data after "
		    "proposal",
		    BUNYAN_T_UINT32, "amt", (uint32_t)(end - ptr),
		    BUNYAN_T_END);
		return (B_FALSE);
	}

	return (B_TRUE);
}

static boolean_t
ikev2_checklen_sa(const uint8_t *buf, size_t buflen)
{
	const uint8_t *end = buf + buflen;
	const uint8_t *saptr = buf;
	uint32_t propcnt = 0;

	while (saptr < end) {
		const ikev2_sa_proposal_t *prop =
		    (const ikev2_sa_proposal_t *)saptr;
		size_t proplen = 0;

		if ((const uint8_t *)(prop + 1) > end) {
			(void) bunyan_warn(log, "Proposal header truncated",
			    /* propcnt + 1 to match expected proposal num */
			    BUNYAN_T_UINT32, "propnum", propcnt + 1,
			    BUNYAN_T_END);
			return (B_FALSE);
		}

		proplen = BE_IN16(&prop->proto_length);
		if (saptr + proplen > end) {
			(void) bunyan_warn(log,
			    "Proposal overruns end of SA payload",
			    BUNYAN_T_UINT32, "amt",
			    (uint32_t)(end - saptr) - proplen,
			    BUNYAN_T_END);
			return (B_FALSE);
		}

		if (!ikev2_checklen_prop(saptr, proplen))
			return (B_FALSE);

		saptr += proplen;
	}

	return (B_TRUE);
}

#define	IKEV2_KE_MIN	((uint32_t)(sizeof (ikev2_ke_t) + 1))
static boolean_t
ikev2_checklen_ke(const uint8_t *buf __unused, size_t buflen)
{
	NOTE(ARGUNUSED(buf))
	return (check_payload_size("KE", buflen, IKEV2_KE_MIN, 0));
}

static boolean_t
ikev2_checklen_id(const char *name, const uint8_t *buf, size_t buflen)
{
	const ikev2_id_t *id = (const ikev2_id_t *)buf;
	size_t min = sizeof (ikev2_id_t);
	size_t max = 0;

	/* Make sure the ID header is present */
	if (!check_payload_size(name, buflen, min, max))
		return (B_FALSE);

	/* id_type is 8 bits, so it is always safe to deference */
	switch ((ikev2_id_type_t)id->id_type) {
	case IKEV2_ID_IPV4_ADDR:
		min += sizeof (in_addr_t);
		max = min;
		break;
	case IKEV2_ID_FQDN:
	case IKEV2_ID_RFC822_ADDR:
		/* These are just non-NUL terminated ASCII strings */
		min++;
		break;
	case IKEV2_ID_IPV6_ADDR:
		min += sizeof (in6_addr_t);
		max = min;
		break;
	case IKEV2_ID_DER_ASN1_DN:
	case IKEV2_ID_DER_ASN1_GN:
	case IKEV2_ID_KEY_ID:
	case IKEV2_ID_FC_NAME:
		min++;
		break;
	}
	return (check_payload_size(name, buflen, min, max));
}

static boolean_t
ikev2_checklen_idi(const uint8_t *buf, size_t buflen)
{
	return (ikev2_checklen_id("IDi", buf, buflen));
}

static boolean_t
ikev2_checklen_idr(const uint8_t *buf, size_t buflen)
{
	return (ikev2_checklen_id("IDr", buf, buflen));
}

#define	IKEV2_CERT_MIN 1
static boolean_t
ikev2_checklen_cert(const uint8_t *buf __unused, size_t buflen)
{
	NOTE(ARGUNUSED(buf))
	return (check_payload_size("CERT", buflen, IKEV2_CERT_MIN, 0));
}

static boolean_t
ikev2_checklen_certreq(const uint8_t *buf __unused, size_t buflen)
{
	NOTE(ARGUNUSED(buf))
	return (check_payload_size("CERTREQ", buflen, IKEV2_CERT_MIN, 0));
}

static boolean_t
ikev2_checklen_auth(const uint8_t *buf __unused, size_t buflen)
{
	NOTE(ARGUNUSED(buf))
	return (check_payload_size("AUTH", buflen, sizeof (ikev2_auth_t), 0));
}

static boolean_t
ikev2_checklen_nonce(const uint8_t *buf __unused, size_t buflen)
{
	NOTE(ARGUNUSED(buf))
	return (check_payload_size("NONCE", buflen, IKEV2_NONCE_MIN,
	    IKEV2_NONCE_MAX));
}

static boolean_t
ikev2_checklen_ts(const char *name, const uint8_t *buf, size_t buflen)
{
	char msg[128] = { 0 };
	const ikev2_tsp_t *tsp = (const ikev2_tsp_t *)buf;
	const uint8_t *end = buf + buflen;
	const uint8_t *ts_ptr = (const uint8_t *)(tsp + 1);
	uint32_t len = sizeof (ikev2_tsp_t);

	if (!check_payload_size(name, buflen, sizeof (ikev2_tsp_t), 0))
		return (B_FALSE);

	for (size_t i = 0; i < tsp->tsp_count; i++) {
		/* LINTED E_PAD_PTR_CAST_ALIGN */
		const ikev2_ts_hdr_t *tsh = (const ikev2_ts_hdr_t *)ts_ptr;
		uint32_t ts_len;

		if (ts_ptr + sizeof (ikev2_ts_hdr_t) > end)
			goto overrun;

		/*
		 * Both the IPv4/IPv6 traffic selectors consist of the fields
		 * of ikev2_ts_t followed by two addresses (start/stop) of
		 * their respective type
		 */
		switch ((ikev2_ts_type_t)tsh->tsh_type) {
		case IKEV2_TS_IPV4_ADDR_RANGE:
			len = sizeof (ikev2_ts_t) + 2 * sizeof (in_addr_t);
			break;
		case IKEV2_TS_IPV6_ADDR_RANGE:
			len = sizeof (ikev2_ts_t) + 2 * sizeof (in6_addr_t);
			break;
		case IKEV2_TS_FC_ADDR_RANGE:
			/* We don't support this, so just ignore it */
			break;
		}

		ts_len = BE_IN16(&tsh->tsh_length);
		if (ts_len < len) {
			(void) snprintf(msg, sizeof (msg),
			    "Traffic selector length in %s payload smaller "
			    "than required", name);
			(void) bunyan_warn(log, msg,
			    BUNYAN_T_UINT32, "tslen", ts_len,
			    BUNYAN_T_UINT32, "expectedlen", len,
			    BUNYAN_T_END);
			return (B_FALSE);
		}
		if (ts_ptr + ts_len > end)
			goto overrun;

		ts_ptr += ts_len;
	}

	if (ts_ptr != end) {
		(void) snprintf(msg, sizeof (msg),
		    "%s payload has trailing bytes", name);
		(void) bunyan_warn(log, msg,
		    BUNYAN_T_UINT32, "buflen", L(buflen),
		    BUNYAN_T_UINT32, "trailing_amt", (uint32_t)(end - ts_ptr),
		    BUNYAN_T_END);
		return (B_FALSE);
	}

	return (B_TRUE);

overrun:
	(void) snprintf(msg, sizeof (msg),
	   "Traffic selector in %s payload overruns end of payload", name);
	(void) bunyan_warn(log, msg, BUNYAN_T_END);
	return (B_FALSE);
}

static boolean_t
ikev2_checklen_tsi(const uint8_t *buf, size_t buflen)
{
	return (ikev2_checklen_ts("TSi", buf, buflen));
}

static boolean_t
ikev2_checklen_tsr(const uint8_t *buf, size_t buflen)
{
	return (ikev2_checklen_ts("TSr", buf, buflen));
}

static boolean_t
ikev2_checklen_notify(const uint8_t *buf, size_t buflen)
{
	char name[] = "N";
	ikev2_notify_t ntfy = { 0 };
	size_t min = sizeof (ntfy);
	size_t max = 0;

	if (!check_payload_size(name, buflen, min, max))
		return (B_FALSE);

	bcopy(buf, &ntfy, sizeof (ntfy));

	min += ntfy.n_spisize;
	return (check_payload_size(name, buflen, min, max));
}

static boolean_t
ikev2_checklen_delete(const uint8_t *buf, size_t buflen)
{
	const char name[] = "DELETE";
	ikev2_delete_t del = { 0 };
	size_t len = sizeof (del);

	if (!check_payload_size(name, buflen, len, 0))
		return (B_FALSE);

	bcopy(buf, &del, sizeof (del));
	if (del.del_spisize == 0)
		return (check_payload_size(name, buflen, len, len));

	len += del.del_spisize * ntohs(del.del_nspi);
	return (check_payload_size(name, buflen, len, len));
}

boolean_t
ikev2_pkt_checklen(uint8_t type, const uint8_t *buf, size_t len)
{
	switch ((ikev2_pay_type_t)type) {
        case IKEV2_PAYLOAD_NONE:
		/* This is never valid for a payload */
		return (B_FALSE);
	case IKEV2_PAYLOAD_SA:
		return (ikev2_checklen_sa(buf, len));
	case IKEV2_PAYLOAD_KE:
		return (ikev2_checklen_ke(buf, len));
	case IKEV2_PAYLOAD_IDi:
		return (ikev2_checklen_idi(buf, len));
	case IKEV2_PAYLOAD_IDr:
		return (ikev2_checklen_idr(buf, len));
	case IKEV2_PAYLOAD_CERT:
		return (ikev2_checklen_cert(buf, len));
	case IKEV2_PAYLOAD_CERTREQ:
		return (ikev2_checklen_certreq(buf, len));
	case IKEV2_PAYLOAD_AUTH:
		return (ikev2_checklen_auth(buf, len));
	case IKEV2_PAYLOAD_NONCE:
		return (ikev2_checklen_nonce(buf, len));
	case IKEV2_PAYLOAD_NOTIFY:
		return (ikev2_checklen_notify(buf, len));
	case IKEV2_PAYLOAD_DELETE:
		return (ikev2_checklen_delete(buf, len));
	case IKEV2_PAYLOAD_VENDOR:
		/* Contents are completely arbitrary */
		break;
	case IKEV2_PAYLOAD_TSi:
		return (ikev2_checklen_tsi(buf, len));
	case IKEV2_PAYLOAD_TSr:
		return (ikev2_checklen_tsr(buf, len));
	case IKEV2_PAYLOAD_SK:
		/*
		 * Validating the size here is heavily dependent
		 * on the algs in use, so we defer to the actual
		 * decrypt code
		 */
		break;
	case IKEV2_PAYLOAD_CP:
		/* TODO once we implement remote-access VPNs */
		break;
	case IKEV2_PAYLOAD_EAP:
	case IKEV2_PAYLOAD_GSPM:
	case IKEV2_PAYLOAD_IDg:
	case IKEV2_PAYLOAD_GSA:
	case IKEV2_PAYLOAD_KD:
	case IKEV2_PAYLOAD_SKF:
	case IKEV2_PAYLOAD_PS:
		/* not currently supported, ignored */
		break;
	}

	return (B_TRUE);
}

/*
 * For protected exchanges (i.e. anything not IKE_SA_INIT), the packets
 * should consist of a single payload (SK) that contains the encrypted and
 * signed payloads.  If there any unprotected payloads in addition to the SK
 * payload, we ignore them by removing them from pkt->pkt_payloads.
 */
static boolean_t
ikev2_pkt_check_predecrypt(pkt_t *pkt)
{
	pkt_payload_t *sk = NULL;
	size_t idx = 0;

	VERIFY(!pkt->pkt_decrypted);

	for (idx = 0; idx < pkt->pkt_payload_count; idx++) {
		sk = pkt_payload(pkt, idx);
		if (sk->pp_type == IKEV2_PAYLOAD_SK)
			break;
	}

	if (sk == NULL || sk->pp_type != IKEV2_PAYLOAD_SK) {
		(void) bunyan_warn(log, "Packet is missing an SK payload",
		    BUNYAN_T_END);
		return (B_FALSE);
	}

	if (idx == 0)
		return (B_TRUE);

	pkt_payload_t *first = &pkt->pkt_payloads[0];
	pkt_payload_t *pay = NULL;

	*first = *sk;
	for (size_t i = 1; i < pkt->pkt_payload_count; i++) {
		pay = pkt_payload(pkt, idx);
		bzero(pay, sizeof (*pay));
	}
	pkt->pkt_payload_count = 1;

	return (B_TRUE);
}

#define	PAYIDX(type) ((type) - IKEV2_PAYLOAD_MIN)
static void
ikev2_count_payloads(pkt_t *restrict pkt, size_t *restrict count)
{
	for (size_t i = 0; i < pkt->pkt_payload_count; i++) {
		pkt_payload_t *pay = pkt_payload(pkt, i);

		if (!IKEV2_VALID_PAYLOAD(pay->pp_type))
			continue;

		count[PAYIDX(pay->pp_type)]++;
	}
}

static boolean_t
check_count(ikev2_pay_type_t type, size_t min, size_t max, size_t *count)
{
	size_t val = count[PAYIDX(type)];

	if (val >= min && val <= max)
		return (B_TRUE);

	char msg[128] = { 0 };

	(void) snprintf(msg, sizeof (msg), "Packet %s payload %s",
	    ikev2_pay_short_str(type),
	    (val < min) ? "is missing" : "defined multiple times");

	(void) bunyan_warn(log, msg, BUNYAN_T_END);
	return (B_FALSE);
}

boolean_t
ikev2_pkt_has_nerror(pkt_t *pkt)
{
	for (size_t i = 0; i < pkt->pkt_notify_count; i++) {
		pkt_notify_t *n = pkt_notify(pkt, i);

		if (IKEV2_NOTIFY_ERROR(n->pn_type))
			return (B_TRUE);
	}
	return (B_FALSE);
}

static boolean_t
ikev2_pkt_check_ike_sa_init(pkt_t *pkt)
{
	/*
	 * While not a notification error, like notification errors, it's
	 * presence means the expected payloads may not be present.
	 */
	static const ikev2_notify_type_t errors[] = {
		IKEV2_N_COOKIE,
	};
	size_t paycount[IKEV2_NUM_PAYLOADS] = { 0 };
	uint32_t msgid = ntohl(pkt_header(pkt)->msgid);
	boolean_t ok = B_TRUE;

	if (msgid != 0) {
		(void) bunyan_warn(log,
		    "Message id is not zero on IKE_SA_INIT exchange",
		    BUNYAN_T_END);
		return (B_FALSE);
	}

	if (ikev2_pkt_has_nerror(pkt))
		return (B_TRUE);

	ikev2_count_payloads(pkt, paycount);

	if (I2P_RESPONSE(pkt)) {
		for (size_t i = 0; i < ARRAY_SIZE(errors); i++) {
			if (pkt_get_notify(pkt, errors[i], NULL) != NULL)
				return (B_TRUE);
		}
	}

	ok &= check_count(IKEV2_PAYLOAD_SA, 1, 1, paycount);
	ok &= check_count(IKEV2_PAYLOAD_KE, 1, 1, paycount);
	ok &= check_count(IKEV2_PAYLOAD_NONCE, 1, 1, paycount);

	return (ok);
}

static boolean_t ikev2_pkt_check_create_child_sa(pkt_t *);

static boolean_t
ikev2_pkt_check_ike_auth(pkt_t *pkt)
{
	if (!pkt->pkt_decrypted)
		return (ikev2_pkt_check_predecrypt(pkt));

	size_t paycount[IKEV2_NUM_PAYLOADS] = { 0 };
	boolean_t ok = B_TRUE;

	if (pkt_get_notify(pkt, IKEV2_N_AUTHENTICATION_FAILED, NULL) != NULL)
		return (B_TRUE);

	if (!ikev2_pkt_check_create_child_sa(pkt))
		return (B_FALSE);

	ikev2_count_payloads(pkt, paycount);

	if (I2P_RESPONSE(pkt)) {
		ok &= check_count(IKEV2_PAYLOAD_IDr, 1, 1, paycount);
	} else {
		ok &= check_count(IKEV2_PAYLOAD_IDi, 1, 1, paycount);
		ok &= check_count(IKEV2_PAYLOAD_IDr, 0, 1, paycount);
	}

	ok &= check_count(IKEV2_PAYLOAD_AUTH, 1, 1, paycount);

	if (!ok)
		return (B_FALSE);

	return (ikev2_pkt_check_create_child_sa(pkt));
}

static boolean_t
ikev2_pkt_check_create_child_sa(pkt_t *pkt)
{
	if (!pkt->pkt_decrypted)
		return (ikev2_pkt_check_predecrypt(pkt));

	size_t paycount[IKEV2_NUM_PAYLOADS] = { 0 };
	boolean_t ok = B_TRUE;

	if (ikev2_pkt_has_nerror(pkt))
		return (B_TRUE);

	ikev2_count_payloads(pkt, paycount);

	ok &= check_count(IKEV2_PAYLOAD_SA, 1, 1, paycount);
	ok &= check_count(IKEV2_PAYLOAD_TSi, 1, 1, paycount);
	ok &= check_count(IKEV2_PAYLOAD_TSr, 1, 1, paycount);

	ok &= check_count(IKEV2_PAYLOAD_KE, 0, 1, paycount);
	return (ok);
}

static boolean_t
ikev2_pkt_check_informational(pkt_t *pkt)
{
	if (!pkt->pkt_decrypted)
		return (ikev2_pkt_check_predecrypt(pkt));

	/*
	 * There's no well defined list of things that can appear in an
	 * informational exchange, so we rely on the processing there to
	 * handle them properly.
	 */
	return (B_TRUE);
}
#undef	PAYIDX

boolean_t
ikev2_pkt_check_payloads(pkt_t *pkt)
{
	ikev2_exch_t exch_type = pkt_header(pkt)->exch_type;

	switch (exch_type) {
	case IKEV2_EXCH_IKE_SA_INIT:
		return (ikev2_pkt_check_ike_sa_init(pkt));
	case IKEV2_EXCH_IKE_AUTH:
		return (ikev2_pkt_check_ike_auth(pkt));
	case IKEV2_EXCH_CREATE_CHILD_SA:
		return (ikev2_pkt_check_create_child_sa(pkt));
	case IKEV2_EXCH_INFORMATIONAL:
		return (ikev2_pkt_check_informational(pkt));
	case IKEV2_EXCH_IKE_SESSION_RESUME:
	case IKEV2_EXCH_GSA_AUTH:
	case IKEV2_EXCH_GSA_REGISTRATION:
	case IKEV2_EXCH_GSA_REKEY:
		/*
		 * ikev2_pkt_new_inbound() should discard unsupported
		 * exchanges before we're ever called
		 */
		INVALID(exch_type);
		break;
	}

	abort();
	/*NOTREACHED*/
	return (B_FALSE);
}

uint8_t
ikev2_pkt_check_critical(pkt_t *pkt)
{
	pkt_payload_t *pay = NULL;
	ike_payload_t *payhdr = NULL;

	for (size_t i = 0; i < pkt->pkt_payload_count; i++) {
		pay = pkt_payload(pkt, i);

		/* XXX: Maybe change to IKEV2_KNOWN_PAYLOAD? */
		if (IKEV2_VALID_PAYLOAD(pay->pp_type))
			continue;

		payhdr = pkt_idx_to_payload(pay);
		if (!(payhdr->pay_reserved & IKEV2_CRITICAL_PAYLOAD))
			continue;

		(void) bunyan_info(log,
		    "Packet contains unsupported critical payload",
		    BUNYAN_T_UINT32, "paytype", (uint32_t)pay->pp_type,
		    BUNYAN_T_END);
		return (pay->pp_type);
	}

	return (IKEV2_PAYLOAD_NONE);
}
