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

	pkt->header.flags = IKEV2_FLAG_INITIATOR;
	return (pkt);
}

/* Allocate a ikev2_pkt_t for an IKEv2 outbound response */
pkt_t *
ikev2_pkt_new_response(const pkt_t *init)
{
	pkt_t *pkt;

	ASSERT(PKT_IS_V2(init));

	pkt = pkt_out_alloc(init->header.initiator_spi,
	    init->header.responder_spi,
	    IKEV2_VERSION,
	    init->header.exch_type,
	    init->header.msgid);
	if (pkt == NULL)
		return (NULL);

	pkt->header.flags = IKEV2_FLAG_RESPONSE;
	return (pkt);
}

struct validate_data {
	const buf_t	*raw;
	size_t		paycount[IKEV2_NUM_PAYLOADS];
	uchar_t		*payloads[IKEV2_NUM_PAYLOADS];
	boolean_t	initiator;
	uint8_t		exch_type;
};

static pkt_walk_ret_t check_payload(uint8_t, buf_t *restrict, void *restrict);
static boolean_t check_sa_init_payloads(boolean_t, const size_t *);

/* Allocate a ikev2_pkt_t for an inbound datagram in raw */
pkt_t *
ikev2_pkt_new_inbound(const uchar_t *buf, size_t buflen)
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
	if (((hdr->flags & (IKEV2_FLAG_INITIATOR|IKEV2_FLAG_RESPONSE)) ^
	    (IKEV2_FLAG_INITIATOR|IKEV2_FLAG_RESPONSE)) == 0) {
		/* XXX: log msg? */
		return (NULL);
	}

	arg.raw.b_ptr = raw;
	arg.raw.b_len = buflen;
	arg.exch_type = hdr->exch_type;
	arg.initiator = !!(hdr->flags & IKEV2_FLAG_INITIATOR);

	if (pkt_payload_walk((buf_t *)raw, check_payload, &arg) != PKT_WALK_OK)
		return (NULL);

	if (hdr->exch_type == IKEV2_EXCH_IKE_SA_INIT &&
	    !check_sa_init_payloads(arg.initiator,
	    (const size_t *)&arg.paycount))
		return (NULL);

	/* this will also copy raw into pkt->raw */
	if ((pkt = pkt_in_alloc(raw)) == NULL)
		return (NULL);

	ASSERT3U(sizeof (pkt->payloads), ==, sizeof (arg.payloads));
	(void) memcpy(&pkt->payloads, &arg.payloads, sizeof (arg.payloads));

	/* convert offsets into pointers into raw */
	for (int i = 0; i < IKEV2_NUM_PAYLOADS; i++) {
		if (pkt->payloads[i] > 0)
			pkt->payloads += &pkt->raw;
	}

	return (pkt);
}

/*
 * Cache the payload offsets and do some minimal checking.
 * By virtue of walking the payloads, we also validate the payload
 * lengths do not overflow or underflow
 */
static pkt_walk_ret_t
check_payload(uint8_t paytype, const buf_t *restrict pay, void *restrict cookie)
{
	struct validate_data *arg = (struct validate_data *)cookie;

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
		goto done;
	case IKEV2_EXCH_IKE_SA_INIT:
		break;
	default:
		/* Unknown exchange, bail */
		/* XXX: log message? */
		return (PKT_WALK_ERROR);
	}

	ASSERT(exch_type == IKEV2_EXCH_SA_INIT);

done:
	paytype -= IKEV2_PAYLOAD_MIN;
	arg->paycount[paytype]++;

	/* store offset from start of packet */
	if (arg->payloads[paytype] == NULL)
		arg->payloads = pay->b_ptr - arg->raw->b_ptr;

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

/* Perform more stringent checks on IKE_SA_INIT packets */
static boolean_t
check_sa_init_payloads(boolean_t initiator, const size_t *paycount)
{
	uint32_t present;
	int i, pay;
	boolean_t multi_ok, allowed_ok;

	present = 0;
	multi_ok = B_TRUE;
	for (i = 0, pay = IKEV2_PAYLOAD_MIN;
	    i < IKEV2_NUM_PAYLOADS;
	    i++, pay++) {
		if (paycount[i] > 1 && !(IS_MULTI(pay))) {
			/* XXX: log msg? */
			multi_ok = B_FALSE;
		}

		if (paycount[i] > 1)
			present |= PAYBIT(pay);
	}

#define	MATCH(x, y) (((x) & (y)) == (x))
#define	ALLOWED(x, y) (((x) | (y)) == (y))

	allowed_ok = B_FALSE;
	for (i = 0; i < ARRAY_SIZE(sa_init_info); i++) {
		if (MATCH(present, sa_init_info[i].required) &&
		    ALLOWED(present, sa_init_info[i].optional))
			allowed_ok = B_TRUE;
	}

	/* A bit of a special case.. only allowed on responses */
	if (initiator && (present & PAYBIT(IKEV2_PAYLOAD_CERTREQ)))
		allowed_ok = B_FALSE;

	/* XXX: log failure? */

#undef MATCH
#undef ALLOWED

	return (!!(multi_ok && allowed_ok));
}

void
ikev2_pkt_free(ikev2_pkt_t *pkt)
{
	pkt_free(pkt);
}

boolean_t
ikev2_next_payload(int pay, pkt_t *restrict pkt, buf_t *restrict ptr)
{
	ikev2_payload_t pay;

	if (ptr->b_ptr == NULL) {
		ptr->b_ptr = IKEV2_PAYLOAD_PTR(pkt, pay);
		/* XXX: set length */
	}

	/* XXX: finish */
	return (B_FALSE);
}

boolean_t
ikev2_get_notify(int ntfy, pkt_t *restrict pkt, buf_t *restrict ptr)
{
	/* TODO: implement me */
	return (B_FALSE);
}

static void
ikev2_add_payload(pkt_t *pkt, ikev2_pay_type_t ptype, boolean_t critical)
{
	uchar_t *payptr;
	uint8_t resv = 0;

	ASSERT(IKEV2_VALID_PAYLOAD(ptype));
	ASSERT3U(pkt->buf.b_len, >=, sizeof (ikev2_payload_t));

	if (critical)
		resv |= IKEV2_CRITICAL_PAYLOAD;

	/* Only cache the first one */
	if ((payptr = IKEV2_PAYLOAD_PTR(pkt, ptype)) == NULL)
		payptr = pkt->buf.b_ptr;

	pkt_add_payload(pkt, ptype, resv);
}

boolean_t
ikev2_add_sa(pkt_t *pkt)
{
	if (pkt->buf.b_len < sizeof (ikev2_payload_t))
		return (B_FALSE);
	ikev2_add_payload(pkt, IKEV2_PAYLOAD_SA, B_FALSE);
}

boolean_t
ikev2_add_prop(ikev2_pkt_t *pkt, uint8_t propnum, ike_proto_t proto,
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
	default:
		INVALID(proto);
	}

	return (pkt_add_prop(pkt, propnum, proto, spilen, spi));
}

boolean_t
ikev2_add_xform(ike2_pkt_t *pkt, ikev2_xf_type_t xftype, int xfid)
{
	return (pkt_add_xform(pkt, xftype, xfid));
}

boolean_t
ikev2_add_xf_attr(ikev2_pkt_t *pkt, ikev2_xf_attr_type_t xf_attr_type,
    uintptr_t arg)
{
	switch (xf_attr_type) {
	case IKEV2_XF_ATTR_KEYLEN:
		ASSERT3U(arg, <, 0x10000);
		return (pkt_add_xf_attr_tv(pkt, IKEV2_XF_ATTR_KEYLEN,
		    (uint16_t)arg));
	default:
		INVALID(xf_attr_type);
	}

	return (ret);
}

boolean_t
ikev2_add_ke(ikev2_pkt_t *restrict pkt, uint_t group,
    const buf_t *restrict data)
{
	ikev2_ke_t	ke = { 0 };

	ASSERT3U(group, <, 0x10000);
	if (pkt->buf.len < sizeof (ikev2_payload_t) + sizeof (ke) + data->len)
		return (B_FALSE);

	ikev2_add_payload(pkt, IKEV2_PAYLOAD_KE, B_FALSE);
	ke.ke_group = htons((uint16_t)group);
	APPEND_STRUCT(pkt, ke);
	APPEND_BUF(pkt, data);
	return (B_TRUE);
}

static boolean_t
ikev2_add_id_common(pkt_t *restrict pkt, boolean_t id_i, ikev2_id_type_t idtype,
    const void *arg)
{
	ikev2_id_t		id = { 0 };
	ikev2_pay_type_t 	paytype =
	    (id_i) ? IKEV2_PAYLOAD_IDi : IKEV2_PAYLOAD_IDr;
	const buf_t		argbuf;

	switch (idtype) {
	case IKEV2_ID_IPV4_ADDR:
		argbuf.ptr = (const uchar_t *)arg;
		argbuf.len = sizeof (in_addr_t);
		break;
	case IKEV2_ID_IP_FQDN:
	case IKEV2_ID_RFC822_ADDR:
		argbuf.ptr = (const uchar_t *)arg;
		argbuf.len = strlen((const char *)arg);
		break;
	case IKEV2_ID_IPV6_ADDR:
		argbuf.ptr = (const uchar_t *)arg;
		argbuf.len = sizeof (in6_addr_t);
		break;
	case IKEV2_ID_DER_ASN1_DN:
	case IKEV2_ID_DER_ASN1_GN:
	case IKEV2_KEY_ID:
		BUF_DUP(&argbuf, (const buf_t *)arg);
		break;
	default:
		INVALID(idtype);
	}

	if (pkt->buf.len < sizeof (ikev2_payload_t) + sizeof (id) + argbuf.len)
		return (B_FALSE);

	ikev2_add_payload(pkt, paytype, B_FALSE);
	id.id_type = (uint8_t)idtype;
	APPEND_STRUCT(pkt, id);
	APPEND_BUF(pkt, argbuf);
	return (B_TRUE);
}

boolean_t
ikev2_add_id_i(pkt_t *restrict pkt, ikev2_id_type_t idtype, const void *arg)
{
	return (ikev2_add_id_common(pkt, B_TRUE, idtype, arg));
}

boolean_t
ikev2_add_id_r(pkt_t *restrict pkt, ikev2_id_type_t idtype, const void *arg)
{
	return (ikev2_add_id_common(pkt, B_FALSE, idtype, arg));
}

static boolean_t ikev2_add_cert_common(pkt_t *restrict, boolean_t,
    ikev2_cert_t, const buf_t *);

boolean_t
ikev2_add_cert(pkt_t *restrict pkt, ikev2_cert_t cert_type, const buf_t *cert)
{
	return (ikev2_add_cert_common(pkt, B_TRUE, cert_type, cert));
}

boolean_t
ikev2_add_certreq(pkt_t *restrict pkt, ikev2_cert_t cert_type,
    const buf_t *cert)
{
	return (ikev2_add_cert_common(pkt, B_FALSE, cert_type, cert));
}

static boolean_t
ikev2_add_cert_common(pkt_t *restrict pkt, boolean_t cert, ikev2_cert_t type,
    const buf_t *data)
{
	if (pkt->buf.len < sizeof (ikev2_payload_t) + 1 + data->len)
		return (B_FALSE);

	ikev2_add_payload(pkt,
	    (cert) ? IKEV2_PAYLOAD_CERT : IKEV2_PAYLOAD_CERTREQ, B_FALSE);

	return (pkt_add_cert(pkt, (uint8_t)type, data));
}

boolean_t
ikev2_add_auth(pkt_t *restrict pkt, ikev2_auth_t auth_method, const buf_t *data)
{
	ikev2_auth_t auth = { 0 };

	if (pkt->buf.len < sizeof (ikev2_payload_t) + sizeof (auth) + data.len)
		return (B_FALSE);

	ikev2_add_payload(pkt, IKEV2_PAYLOAD_AUTH, B_FALSE);
	auth.auth_method = (uint8_t)auth_method;
	APPEND_STRUCT(pkt, auth);
	APPEND_BUF(pkt, data);
	return (B_TRUE);
}

boolean_t
ikev2_add_nonce(ikev2_pkt_t *restrict pkt, const buf_t *restrict nonce)
{
	if (pkt->buf.len < sizeof (ikev2_payload_t) + nonce->len)
		return (B_FALSE);

	ikev2_add_payload(pkt, IKEV2_PAYLOAD_NONCE, B_FALSE);
	APPEND_BUF(pkt, nonce);
	return (B_TRUE);
}

boolean_t
ikev2_add_notify(ikev2_pkt_t *restrict pkt, ikev2_proto_t proto, size_t spisize,
    ikev2_notify_type_t ntfy_type, uint64_t spi, const buf_t *restrict data)
{
	ikev2_notify_t ntfy = { 0 };

	ASSERT(spisize == sizeof (uint32_t) || spisize == 0);
	ASSERT3U(spi, <, 0x100000000ULL);

	if (pkt->buf.len < sizeof (ikev2_payload_t) + sizeof (ntfy) + spisize +
	    (data != NULL) ? data->len : 0)
		return (B_FALSE);

	ikev2_add_payload(pkt, IKEV2_PAYLOAD_NOTIFY, B_FALSE);
	ntfy.ntfy_proto = proto;
	ntfy.ntfy_spisize = spisize;
	ntfy.ntfy_type = htons((uint16_t)ntfy_type);
	APPEND_STRUCT(pkt, ntfy);

	switch (spisize) {
	case 0:
		break;
	case sizeof (uint32_t):
		VERIFY(buf_put32(&pkt->buf, (uint32_t)spi));
		break;
	default:
		INVALID(spisize);
	}

	if (data != NULL)
		APPEND_BUF(pkt, data);

	return (B_TRUE);
}

static void delete_finish(pkt_t *restrict, buf_t *restrict, uintptr_t, size_t);
boolean_t
ikev2_add_delete(ikev2_pkt_t *pkt, ikev2_proto_t proto)
{
	ikev2_delete_t del = { 0 };

	if (pkt->buf.len < sizeof (ikev2_payload_t) + sizeof (ikev2_delete_t))
		return (B_FALSE);

	ikev2_add_payload(pkt, IKEV2_PAYLOAD_DELETE, B_FALSE);
	pkt_stack_push(pkt, DEPTH_DEL, 0, delete_finish);

	del.del_proto = (uint8_t)proto;
	switch (proto) {
	case IKEV2_PROTO_IKE:
		del.del_spisize = 0;
		break;
	case IKEV2_PROTO_AH:
	case IKEV2_PROTO_ESP:
		del.del_spisize = sizeof (uint32_t);
		break;
	default:
		INVALID(proto);
	}

	APPEND_STRUCT(del);
	return (B_TRUE);
}

static void
delete_finish(pkt_t *restrict pkt, buf_t *restrict buf, uintptr_t swaparg,
    size_t numspi)
{
	ikev2_delete_t	del = { 0 };
	buf_t		delbuf = STRUCT_TO_BUF(del);

	ASSERT3U(numspi, <, 0x10000);

	buf_copy(&delbuf, buf);
	delbuf.del_numspi = htons((uint16_t)numspi);
	buf_copy(&rawbuf, buf);
}

boolean_t
ikev2_add_vendor(ikev2_pkt_t *restrict pkt, const buf_t *restrict vid)
{
	if (pkt->buf.len < sizeof (ikev2_payload_t) + vid->len)
		return (B_FALSE);

	ikev2_add_payload(pkt, IKEV2_PAYLOAD_VENDOR, B_FALSE);
	APPEND_BUF(pkt, vid);
	return (B_TRUE);
}

static boolean_t add_ts_common(ikev2_pkt_t *, boolean_t);

boolean_t
ikev2_add_ts_i(ikev2_pkt_t *restrict pkt)
{
	return (add_ts_common(pkt, B_TRUE));
}

boolean_t
ikev2_add_ts_r(ikev2_pkt_t *restrict pkt)
{
	return (add_ts_common(pkt, B_FALSE));
}

static void ts_finish(pkt_t *restrict, buf_t *restrict, uintptr_t, size_t);

static boolean_t
add_ts_common(ikev2_pkt_t *pkt, boolean_t ts_i)
{
	ikev2_ts_t ts = { 0 };

	if (pkt->buf.len < sizeof (ikev2_payload_t) + sizeof (ikev2_ts_t))
		return (B_FALSE);

	ikev2_add_payload(pkt, (ts_i) ? IKEV2_PAYLOAD_TSi : IKEV2_PAYLOAD_TSr,
	    B_FALSE);
	pkt_stack_push(pkt, DEPTH_TS, 0, ts_finish);
	APPEND_STRUCT(pkt, ts);
	return (B_TRUE);
}

static void
ts_finish(pkt_t *restrict pkt, buf_t *restrict buf, uintptr_t swaparg,
    size_t numts)
{
	ikev2_ts_t	ts = { 0 };
	buf_t		tsbuf = STRUCT_TO_BUF(ts);

	ASSERT3U(numts, <, 0x100);

	buf_copy(&tsbuf, buf);
	ts.ts_num = (uint8_t)numts;
	buf_copy(buf, &tsbuf);
}

boolean_t
ikev2_add_ts(ikev2_pkt_t *restrict pkt, uint_t ip_proto,
    const sockaddr_u_t *restrict start, const sockaddr_u_t *restrict end)
{
	ikev2_tsval_t	tsv = { 0 };
	buf_t		startbuf;
	buf_t		endbuf;

	ASSERT3U(ip_proto, <, 0x100);
	ASSERT3U(start->sau_ss->ss_family, ==, end->sau_ss->ss_family);

	pkt_stack_push(pkt, DEPTH_TS_VAL, NULL, 0);

	switch (start->sau_ss->ss_family) {
	case AF_INET:
		tsv.tsv_type = IKEV2_TS_IPV4_ADDR_RANGE;
		tsv.tsv_start_port = start->sau_sin->sin_port;
		tsv.tsv_end = end->sau_sin->sin_port;
		startbuf.ptr = &start->sau_sin->sin_addr;
		endbuf.ptr = &end->sau_sin->sin_addr;
		startbuf.len = endbuf.len = sizeof (start->sau_sin->sin_addr);
		break;
	case AF_INET6:
		tsv.tsv_type = IKEV2_TS_IPV6_ADDR_RANGE;
		tsv.tsv_start_port = start->sau_sin6->sin6_port;
		tsv.tsv_end = end->sau_sin6->sin6_port;
		startbuf.ptr = &start->sau_sin6->sin6_addr;
		endbuf.ptr = &end->sau_sin6->sin6_addr;
		startbuf.len = endbuf.len = sizeof (start->sau_sin->sin6_addr);
		break;
	default:
		INVALID(ts_type);
	}

	tsv.len = sizeof (tsv) + startbuf.len + endbuf.len;
	if (pkt->buf.len < tsv.len)
		return (B_FALSE);

	tsv.tsv_proto = (uint8_t)ip_proto;
	tsv.tsv_len = htons(tsv.len);
	APPEND_STRUCT(tsv);
	APPEND_BUF(&startbuf);
	APPEND_BUF(&endbuf);
	return (B_TRUE);
}

static void encrypt_payloads(pkt_t *restrict, buf_t *restrict, uintptr_t,
    size_t);

boolean_t
ikev2_add_sk(ikev2_pkt_t *restrict pkt)
{
	/* TODO */
}

static void
encrypt_payloads(pkt_t *restrict pkt, buf_t *restrict buf, uintptr_t swaparg,
    size_t numencr)
{
	/* TODO */
}

boolean_t
ikev2_add_config(ikev2_pkt_t *pkt, ikev2_cfg_type_t cfg_type)
{
	/* TODO */
}

boolean_t
ikev2_add_config_attr(ikev2_pkt_t *restrict pkt,
    ikev2_cfg_attr_type_t cfg_attr_type, const void *restrict data)
{
	/* TODO */
}

/*
 * Since an EAP payload is likely to have a number of components, for now
 * at least, we support scatter-gather semantics with writing out the data
 * as it seems likely when we get around to implementing this, that it
 * might prove easier than requiring the EAP code to assemble everything
 * in a temporary buffer, just to then write it out to another buffer.
 */
boolean_t
ikev2_add_eap(ikev2_pkt_t *restrict pkt, const buf_t *restrict data, size_t n)
{
	size_t len = sizeof (ikev2_packet_t);

	for (size_t i = 0; i < n; i++)
		len += data[i].len;

	if (pkt->buf.len < len)
		return (B_FALSE);

	ikev2_add_payload(pkt, IKEV2_PAYLOAD_EAP, B_FALSE);
	for (size_t i = 0; i < n; i++)
		APPEND_BUF(pkt, data[i]);
	return (B_TRUE);
}

typedef struct validate_data {
	size_t	paycount[IKEV2_NUM_PAYLOADS];
	uint8_t	exch_type;
} validate_data_t;

static pkt_walk_ret_t validate_cb(uint8_t, buf_t *restrict, void *restrict);

static boolean_t
validate_inbound(buf_t *data)
{
	ike_header_t	*hdr;
	validate_data_t	arg = { 0 };
	hdr = data->ptr;

	/*
	 * We allocate the memory, so we should start off on a 64-bit boundary,
	 * so accessing the header should be ok.
	 */
	ASSERT(IS_P2ALIGNED(hdr, uint64_t));

	arg.exch_type = hdr->exch_type;
	if (pkt_payload_walk(data, validate_cb, &arg) != PKT_WALK_OK)
		return (B_FALSE);

	switch (arg.exch_type) {
	case IKEV2_EXCH_IKE_AUTH:
	case IKEV2_EXCH_CREATE_CHILD_SA:
	case IKEV2_EXCH_INFORMATIONAL:
	}
}

static pkt_walk_ret_t
validate_cb(uint8_t paytype, buf_t *restrict pay, void *restrict cookie)
{
	validate_data_t	*arg = (validate_data_t *)cookie;

	arg->paycount[paytype - IKEV2_NUMPAYLOADS]++;

	return (PKT_WALK_OK);
}
