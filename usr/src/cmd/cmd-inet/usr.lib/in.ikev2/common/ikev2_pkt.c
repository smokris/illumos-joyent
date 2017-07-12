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
#include <netinet/in.h>
#include <security/cryptoki.h>
#include <errno.h>
#include <sys/socket.h>
#include <pthread.h>
#include <sys/debug.h>
#include <note.h>
#include <stdarg.h>
#include "defs.h"
#include "pkt_impl.h"
#include "ikev2.h"
#include "ikev2_sa.h"
#include "ikev2_pkt.h"

#define	PKT_IS_V2(p) \
	(IKE_GET_MAJORV((p)->header.version) == IKE_GET_MAJORV(IKEV2_VERSION))

/* Allocate an outbound IKEv2 pkt for an initiator of the given exchange type */
pkt_t *
ikev2_pkt_new_initiator(ikev2_sa_t *i2sa, ikev2_exch_t exch_type)
{
	pkt_t *pkt;

	pkt = pkt_out_alloc(I2SA_LOCAL_SPI(i2sa),
	    I2SA_REMOTE_SPI(i2sa),
	    IKEV2_VERSION,
	    exch_type, 0);
	if (pkt == NULL)
		return (NULL);

	pkt->pkt_header.flags = IKEV2_FLAG_INITIATOR;
	return (pkt);
}

/* Allocate a ikev2_pkt_t for an IKEv2 outbound response */
pkt_t *
ikev2_pkt_new_response(const pkt_t *init)
{
	pkt_t *pkt;

	ASSERT(PKT_IS_V2(init));

	pkt = pkt_out_alloc(init->pkt_header.initiator_spi,
	    init->pkt_header.responder_spi,
	    IKEV2_VERSION,
	    init->pkt_header.exch_type,
	    init->pkt_header.msgid);
	if (pkt == NULL)
		return (NULL);

	pkt->pkt_header.flags = IKEV2_FLAG_RESPONSE;
	return (pkt);
}

struct validate_data {
	pkt_t		*pkt;
	size_t		notify_count;
	size_t		payload_count[IKEV2_NUM_PAYLOADS];
	boolean_t	initiator;
	uint8_t		exch_type;
};

static pkt_walk_ret_t check_payload(uint8_t, uint8_t, uchar_t *restrict,
    size_t, void *restrict);
static boolean_t check_sa_init_payloads(boolean_t, const size_t *);

/* Allocate a ikev2_pkt_t for an inbound datagram in raw */
pkt_t *
ikev2_pkt_new_inbound(uchar_t *buf, size_t buflen)
{
	const ike_header_t	*hdr = NULL;
	pkt_t			*pkt = NULL;
	struct validate_data	arg = { 0 };

	ASSERT(IS_P2ALIGNED(buf, sizeof (uint64_t)));

	hdr = (const ike_header_t *)buf;

	ASSERT(IKE_GET_MAJORV(hdr->version) == IKE_GET_MAJORV(IKEV2_VERSION));

	/*
	 * Make sure either the initiator or response flag is set, but
	 * not both.
	 */
	uint8_t flags = hdr->flags & (IKEV2_FLAG_INITIATOR|IKEV2_FLAG_RESPONSE);
	if ((flags ^ (IKEV2_FLAG_INITIATOR|IKEV2_FLAG_RESPONSE)) == 0) {
		/* XXX: log msg? */
		return (NULL);
	}

	if ((pkt = pkt_in_alloc(buf, buflen)) == NULL) {
		/* XXX: log msg */
		return (NULL);
	}

	arg.pkt = pkt;
	arg.exch_type = hdr->exch_type;
	arg.initiator = !!(hdr->flags & IKEV2_FLAG_INITIATOR);

	if (pkt_payload_walk(buf, buflen, check_payload, &arg) != PKT_WALK_OK)
		return (NULL);


	return (pkt);
}

/*
 * Cache the payload offsets and do some minimal checking.
 * By virtue of walking the payloads, we also validate the payload
 * lengths do not overflow or underflow
 */
static pkt_walk_ret_t
check_payload(uint8_t paytype, uint8_t resv, uchar_t *restrict buf,
    size_t buflen, void *restrict cookie)
{
	struct validate_data *arg = (struct validate_data *)cookie;
	boolean_t critical = !!(resv & IKEV2_CRITICAL_PAYLOAD);

	/* Skip unknown payloads.  We will check the critical bit later */
	if (paytype < IKEV2_PAYLOAD_MIN || paytype > IKEV2_PAYLOAD_MAX)
		return (PKT_WALK_OK);

	switch (arg->exch_type) {
	case IKEV2_EXCH_IKE_AUTH:
	case IKEV2_EXCH_CREATE_CHILD_SA:
	case IKEV2_EXCH_INFORMATIONAL:
		/*
		 * All payloads in these exchanges should be encrypted
		 * at this early stage.  RFC 5996 isn't quite clear
		 * what to do.  There seem to be three possibilities:
		 *
		 * 1. Drop the packet with no further action.
		 * 2. IFF the encrypted payload's integrity check passes,
		 *    and the packet is an initiator, send an INVALID_SYNTAX
		 *    notification in response.  Otherwise, drop the packet
		 * 3. Ignore the unencrypted payloads and only process the
		 *    payloads that passed the integrity check.
		 *
		 * As RFC5996 suggests committing minimal CPU state until
		 * a valid request is present (to help mitigate DOS attacks),
		 * option 2 would still commit us to performing potentially
		 * expensive decryption and authentication calculations.
		 * Option 3 would require us to track which payloads were
		 * authenticated and which were not.  Since some payloads
		 * (e.g. notify) can appear multiple times in a packet
		 * (requiring some sort of iteration to deal with them),
		 * this seems potentially complicated and prone to potential
		 * exploit.  Thus we opt for the simple solution of dropping
		 * the packet.
		 *
		 * NOTE: if we successfully authenticate and decrypt a
		 * packet for one of these exchanges and the decrypted
		 * and authenticated payloads have range or value issues,
		 * we may opt at that point to send an INVALID_SYNTAX
		 * notification, but not here.
		 */
		if (paytype != IKEV2_PAYLOAD_SK) {
			/* XXX: log message? */
			return (PKT_WALK_ERROR);
		}
		return (PKT_WALK_OK);

	case IKEV2_EXCH_IKE_SA_INIT:
		break;

	default:
		/* Unknown exchange, bail */
		/* XXX: log message? */
		return (PKT_WALK_ERROR);
	}

	ASSERT3U(exch_type, ==, IKEV2_EXCH_SA_INIT);

	arg->payload_count[paytype - IKEV2_PAYLOAD_MIN]++;

	if (paytype == IKEV2_PAYLOAD_NOTIFY) {
		uint16_t *ntfyp = pkt_notify(arg->pkt, arg->notify_count++);
		ikev2_notify_t ntfy = { 0 };
		size_t len = sizeof (ntfy);

		if (buflen < len) {
			/* XXX: log */
			return (PKT_WALK_ERROR);
		}
		(void) memcpy(&ntfy, buf, sizeof (ntfy));
		len += ntfy.n_spisize;
		if (buflen < len) {
			/* XXX: log */
			return (PKT_WALK_ERROR);
		}

		*ntfyp = ntfy.n_type;
		return (PKT_WALK_OK);
	}

	return (PKT_WALK_OK);
}

#define	PAYBIT(pay) ((uint32_t)1 << ((pay) - IKEV2_PAYLOAD_MIN))
static const uint32_t multi_payloads =
	PAYBIT(IKEV2_PAYLOAD_NOTIFY) |
	PAYBIT(IKEV2_PAYLOAD_VENDOR) |
	PAYBIT(IKEV2_PAYLOAD_CERTREQ);
#define	IS_MULTI(pay) (!!(multi_payloads & PAYBIT(pay)))

static struct payinfo {
	uint32_t	required;
	uint32_t	optional;
} sa_init_info[] = {
	{
		/* required */
		PAYBIT(IKEV2_PAYLOAD_SA) |
		PAYBIT(IKEV2_PAYLOAD_KE) |
		PAYBIT(IKEV2_PAYLOAD_NONCE),
		/* optional */
		PAYBIT(IKEV2_PAYLOAD_NOTIFY) |
		PAYBIT(IKEV2_PAYLOAD_VENDOR) |
		PAYBIT(IKEV2_PAYLOAD_CERTREQ)
	},
	{
		/* required */
		PAYBIT(IKEV2_PAYLOAD_NOTIFY),
		/* optional */
		PAYBIT(IKEV2_PAYLOAD_VENDOR)
	}
};

void
ikev2_pkt_free(pkt_t *pkt)
{
	pkt_free(pkt);
}

static void
ikev2_add_payload(pkt_t *pkt, ikev2_pay_type_t ptype, boolean_t critical)
{
	uchar_t *payptr;
	uint8_t resv = 0;

	ASSERT(IKEV2_VALID_PAYLOAD(ptype));
	ASSERT3U(pkt_write_left(pkt), >=, sizeof (ikev2_payload_t));

	if (critical)
		resv |= IKEV2_CRITICAL_PAYLOAD;

	pkt_add_payload(pkt, ptype, resv);
}

boolean_t
ikev2_add_sa(pkt_t *pkt)
{
	if (pkt_write_left(pkt) < sizeof (ikev2_payload_t))
		return (B_FALSE);
	ikev2_add_payload(pkt, IKEV2_PAYLOAD_SA, B_FALSE);
	return (B_TRUE);
}

boolean_t
ikev2_add_prop(pkt_t *pkt, uint8_t propnum, ikev2_spi_proto_t proto,
    uint64_t spi)
{
	size_t spilen;

	switch (proto) {
	case IKEV2_PROTO_AH:
	case IKEV2_PROTO_ESP:
		spilen = sizeof (uint32_t);
		break;
	case IKEV2_PROTO_IKE:
		spilen == (spi == 0) ? 0 : sizeof (uint64_t);
		break;
	case IKEV2_PROTO_NONE:
	case IKEV2_PROTO_FC_ESP_HEADER:
	case IKEV2_PROTO_FC_CT_AUTH:
		INVALID("proto");
		break;
	}

	return (pkt_add_prop(pkt, propnum, proto, spilen, spi));
}

boolean_t
ikev2_add_xform(pkt_t *pkt, ikev2_xf_type_t xftype, int xfid)
{
	return (pkt_add_xform(pkt, xftype, xfid));
}

boolean_t
ikev2_add_xf_attr(pkt_t *pkt, ikev2_xf_attr_type_t xf_attr_type,
    uintptr_t arg)
{
	switch (xf_attr_type) {
	case IKEV2_XF_ATTR_KEYLEN:
		ASSERT3U(arg, <, 0x10000);
		return (pkt_add_xform_attr_tv(pkt, IKEV2_XF_ATTR_KEYLEN,
		    (uint16_t)arg));
	}

	return (B_FALSE);
}

boolean_t
ikev2_add_ke(pkt_t *restrict pkt, uint_t group,
    const uchar_t *restrict data, size_t len)
{
	ikev2_ke_t	ke = { 0 };

	ASSERT3U(group, <, 0x10000);
	if (pkt_write_left(pkt) < sizeof (ikev2_payload_t) + sizeof (ke) + len)
		return (B_FALSE);

	ikev2_add_payload(pkt, IKEV2_PAYLOAD_KE, B_FALSE);
	ke.kex_dhgroup = htons((uint16_t)group);
	PKT_APPEND_STRUCT(pkt, ke);
	PKT_APPEND_DATA(pkt, data, len);
	return (B_TRUE);
}

static boolean_t
ikev2_add_id_common(pkt_t *restrict pkt, boolean_t id_i, ikev2_id_type_t idtype,
    va_list ap)
{
	ikev2_id_t		id = { 0 };
	ikev2_pay_type_t 	paytype =
	    (id_i) ? IKEV2_PAYLOAD_IDi : IKEV2_PAYLOAD_IDr;
	const uchar_t		*data;
	size_t			len = 0;

	data = va_arg(ap, const uchar_t *);

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

	if (pkt_write_left(pkt) < sizeof (ikev2_payload_t) + sizeof (id) + len)
		return (B_FALSE);

	ikev2_add_payload(pkt, paytype, B_FALSE);
	id.id_type = (uint8_t)idtype;
	PKT_APPEND_STRUCT(pkt, id);
	PKT_APPEND_DATA(pkt, data, len);
	return (B_TRUE);
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

static boolean_t ikev2_add_cert_common(pkt_t *restrict, boolean_t,
    ikev2_cert_t, const uchar_t *, size_t);

boolean_t
ikev2_add_cert(pkt_t *restrict pkt, ikev2_cert_t cert_type, const uchar_t *cert,
    size_t len)
{
	return (ikev2_add_cert_common(pkt, B_TRUE, cert_type, cert, len));
}

boolean_t
ikev2_add_certreq(pkt_t *restrict pkt, ikev2_cert_t cert_type,
    const uchar_t *cert, size_t len)
{
	return (ikev2_add_cert_common(pkt, B_FALSE, cert_type, cert, len));
}

static boolean_t
ikev2_add_cert_common(pkt_t *restrict pkt, boolean_t cert, ikev2_cert_t type,
    const uchar_t *restrict data, size_t len)
{
	ikev2_pay_type_t ptype =
	    (cert) ? IKEV2_PAYLOAD_CERT : IKEV2_PAYLOAD_CERTREQ;

	if (pkt_write_left(pkt) < sizeof (ikev2_payload_t) + 1 + len)
		return (B_FALSE);

	ikev2_add_payload(pkt, ptype, B_FALSE);
	return (pkt_add_cert(pkt, (uint8_t)type, data, len));
}

boolean_t
ikev2_add_auth(pkt_t *restrict pkt, ikev2_auth_type_t auth_method,
    const uchar_t *restrict data, size_t len)
{
	ikev2_auth_t auth = { 0 };

	if (pkt_write_left(pkt) < sizeof (ikev2_payload_t) + sizeof (auth) +
	    len)
		return (B_FALSE);

	ikev2_add_payload(pkt, IKEV2_PAYLOAD_AUTH, B_FALSE);
	auth.auth_method = (uint8_t)auth_method;
	PKT_APPEND_STRUCT(pkt, auth);
	PKT_APPEND_DATA(pkt, data, len);
	return (B_TRUE);
}

boolean_t
ikev2_add_nonce(pkt_t *restrict pkt, const uchar_t *restrict nonce, size_t len)
{
	if (pkt_write_left(pkt) < sizeof (ikev2_payload_t) + len)
		return (B_FALSE);

	ikev2_add_payload(pkt, IKEV2_PAYLOAD_NONCE, B_FALSE);
	PKT_APPEND_DATA(pkt, nonce, len);
	return (B_TRUE);
}

boolean_t
ikev2_add_notify(pkt_t *restrict pkt, ikev2_spi_proto_t proto, size_t spisize,
    ikev2_notify_type_t ntfy_type, uint64_t spi, const uchar_t *restrict data,
    size_t len)
{
	ikev2_notify_t ntfy = { 0 };

	ASSERT(spisize == sizeof (uint32_t) || spisize == 0);
	ASSERT3U(spi, <, 0x100000000ULL);

	if (pkt_write_left(pkt) < sizeof (ikev2_payload_t) + sizeof (ntfy) +
	    spisize + len)
		return (B_FALSE);

	ikev2_add_payload(pkt, IKEV2_PAYLOAD_NOTIFY, B_FALSE);
	ntfy.n_protoid = proto;
	ntfy.n_spisize = spisize;
	ntfy.n_type = htons((uint16_t)ntfy_type);
	PKT_APPEND_STRUCT(pkt, ntfy);

	switch (spisize) {
	case 0:
		break;
	case sizeof (uint32_t):
		put32(pkt, (uint32_t)spi);
		break;
	default:
		INVALID(spisize);
	}

	if (data != NULL)
		PKT_APPEND_DATA(pkt, data, len);

	return (B_TRUE);
}

static void delete_finish(pkt_t *restrict, uchar_t *restrict, uintptr_t,
    size_t);

boolean_t
ikev2_add_delete(pkt_t *pkt, ikev2_spi_proto_t proto)
{
	ikev2_delete_t del = { 0 };

	if (pkt_write_left(pkt) < sizeof (ikev2_payload_t) +
	    sizeof (ikev2_delete_t))
		return (B_FALSE);

	ikev2_add_payload(pkt, IKEV2_PAYLOAD_DELETE, B_FALSE);
	pkt_stack_push(pkt, PSI_DEL, delete_finish, 0);

	del.del_protoid = (uint8_t)proto;
	switch (proto) {
	case IKEV2_PROTO_IKE:
		del.del_spisize = 0;
		break;
	case IKEV2_PROTO_AH:
	case IKEV2_PROTO_ESP:
		del.del_spisize = sizeof (uint32_t);
		break;
	case IKEV2_PROTO_NONE:
	case IKEV2_PROTO_FC_ESP_HEADER:
	case IKEV2_PROTO_FC_CT_AUTH:
		INVALID("proto");
	}

	PKT_APPEND_STRUCT(pkt, del);
	return (B_TRUE);
}

static void
delete_finish(pkt_t *restrict pkt, uchar_t *restrict buf, uintptr_t swaparg,
    size_t numspi)
{
	ikev2_delete_t	del = { 0 };

	ASSERT3U(numspi, <, 0x10000);

	(void) memcpy(&del, buf, sizeof (del));
	del.del_nspi = htons((uint16_t)numspi);
	(void) memcpy(buf, &del, sizeof (del));
}

boolean_t
ikev2_add_vendor(pkt_t *restrict pkt, const uchar_t *restrict vid, size_t len)
{
	if (pkt_write_left(pkt) < sizeof (ikev2_payload_t) + len)
		return (B_FALSE);

	ikev2_add_payload(pkt, IKEV2_PAYLOAD_VENDOR, B_FALSE);
	PKT_APPEND_DATA(pkt, vid, len);
	return (B_TRUE);
}

static boolean_t add_ts_common(pkt_t *, boolean_t);

boolean_t
ikev2_add_ts_i(pkt_t *restrict pkt)
{
	return (add_ts_common(pkt, B_TRUE));
}

boolean_t
ikev2_add_ts_r(pkt_t *restrict pkt)
{
	return (add_ts_common(pkt, B_FALSE));
}

static void ts_finish(pkt_t *restrict, uchar_t *restrict, uintptr_t, size_t);

static boolean_t
add_ts_common(pkt_t *pkt, boolean_t ts_i)
{
	ikev2_ts_t ts = { 0 };

	if (pkt_write_left(pkt) < sizeof (ikev2_payload_t) +
	    sizeof (ikev2_ts_t))
		return (B_FALSE);

	ikev2_add_payload(pkt, (ts_i) ? IKEV2_PAYLOAD_TSi : IKEV2_PAYLOAD_TSr,
	    B_FALSE);
	pkt_stack_push(pkt, PSI_TSP, ts_finish, 0);
	PKT_APPEND_STRUCT(pkt, ts);
	return (B_TRUE);
}

static void
ts_finish(pkt_t *restrict pkt, uchar_t *restrict buf, uintptr_t swaparg,
    size_t numts)
{
	ikev2_tsp_t	ts = { 0 };

	ASSERT3U(numts, <, 0x100);

	(void) memcpy(&ts, buf, sizeof (ts));
	ts.tsp_count = (uint8_t)numts;
	(void) memcpy(buf, &ts, sizeof (ts));
}

boolean_t
ikev2_add_ts(pkt_t *restrict pkt, ikev2_ts_type_t type, uint8_t ip_proto,
    const sockaddr_u_t *restrict start, const sockaddr_u_t *restrict end)
{
	ikev2_ts_t	ts = { 0 };
	void		*startptr = NULL, *endptr = NULL;
	size_t		len = 0;

	ASSERT3U(ip_proto, <, 0x100);
	ASSERT3U(start->sau_ss->ss_family, ==, end->sau_ss->ss_family);

	pkt_stack_push(pkt, PSI_TS, 0, NULL);

	ts.ts_length = sizeof (ts);
	ts.ts_type = (uint8_t)type;

	switch (type) {
	case IKEV2_TS_IPV4_ADDR_RANGE:
		ASSERT3U(start->sau_ss->ss_family, ==, AF_INET);
		ASSERT3U(end->sau_ss->ss_family, ==, AF_INET);
		ts.ts_startport = start->sau_sin->sin_port;
		ts.ts_endport = end->sau_sin->sin_port;
		startptr = &start->sau_sin->sin_addr;
		endptr = &end->sau_sin->sin_addr;
		len = sizeof (in_addr_t);
		ts.ts_length += 2 * len;
		break;
	case IKEV2_TS_IPV6_ADDR_RANGE:
		ASSERT3U(start->sau_ss->ss_family, ==, AF_INET6);
		ASSERT3U(end->sau_ss->ss_family, ==, AF_INET6);
		ts.ts_startport = start->sau_sin6->sin6_port;
		ts.ts_endport = end->sau_sin6->sin6_port;
		startptr = &start->sau_sin6->sin6_addr;
		endptr = &end->sau_sin6->sin6_addr;
		len = sizeof (in6_addr_t);
		ts.ts_length += 2 * len;
		break;
	case IKEV2_TS_FC_ADDR_RANGE:
		INVALID("type");
	}

	if (pkt_write_left(pkt) < ts.ts_length)
		return (B_FALSE);

	ts.ts_protoid = ip_proto;
	ts.ts_length = htons(ts.ts_length);
	PKT_APPEND_STRUCT(pkt, ts);
	PKT_APPEND_DATA(pkt, startptr, len);
	PKT_APPEND_DATA(pkt, endptr, len);
	return (B_TRUE);
}

static void encrypt_payloads(pkt_t *restrict, buf_t *restrict, uintptr_t,
    size_t);

boolean_t
ikev2_add_sk(pkt_t *restrict pkt)
{
	return (B_FALSE);
	/* TODO */
}

static void
encrypt_payloads(pkt_t *restrict pkt, buf_t *restrict buf, uintptr_t swaparg,
    size_t numencr)
{
	/* TODO */
}

boolean_t
ikev2_add_config(pkt_t *pkt, ikev2_cfg_type_t cfg_type)
{
	return (B_FALSE);
	/* TODO */
}

boolean_t
ikev2_add_config_attr(pkt_t *restrict pkt,
    ikev2_cfg_attr_type_t cfg_attr_type, const void *restrict data)
{
	return (B_FALSE);
	/* TODO */
}
