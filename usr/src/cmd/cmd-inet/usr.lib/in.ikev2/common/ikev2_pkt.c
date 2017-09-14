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
#include <alloca.h>
#include "defs.h"
#include "pkt_impl.h"
#include "ikev2.h"
#include "ikev2_sa.h"
#include "ikev2_pkt.h"
#include "ikev2_enum.h"
#include "pkcs11.h"
#include "random.h"

#define	PKT_IS_V2(p) \
	(IKE_GET_MAJORV((p)->header.version) == IKE_GET_MAJORV(IKEV2_VERSION))

/* Allocate an outbound IKEv2 pkt for a new exchange */
pkt_t *
ikev2_pkt_new_exchange(ikev2_sa_t *i2sa, ikev2_exch_t exch_type)
{
	pkt_t *pkt = NULL;
	uint32_t msgid = 0;
	uint8_t flags = 0;

	PTH(pthread_mutex_lock(&i2sa->lock));
	if (exch_type != IKEV2_EXCH_IKE_SA_INIT)
		msgid = i2sa->outmsgid++;

	if (i2sa->flags & I2SA_INITIATOR)
		flags |= IKEV2_FLAG_INITIATOR;

	pkt = pkt_out_alloc(I2SA_LOCAL_SPI(i2sa),
	    I2SA_REMOTE_SPI(i2sa),
	    IKEV2_VERSION,
	    exch_type, msgid, flags);

	if (pkt == NULL) {
		i2sa->outmsgid--;
		PTH(pthread_mutex_unlock(&i2sa->lock));
		return (NULL);
	}

	PTH(pthread_mutex_unlock(&i2sa->lock));

	pkt->pkt_header.flags = IKEV2_FLAG_INITIATOR;
	pkt->pkt_sa = i2sa;
	I2SA_REFHOLD(i2sa);
	return (pkt);
}

/* Allocate a ikev2_pkt_t for an IKEv2 outbound response */
pkt_t *
ikev2_pkt_new_response(const pkt_t *init)
{
	pkt_t *pkt;
	uint8_t flags = IKEV2_FLAG_RESPONSE;

	ASSERT(PKT_IS_V2(init));

	if (init->pkt_sa->flags & I2SA_INITIATOR)
		flags |= IKEV2_FLAG_INITIATOR;

	pkt = pkt_out_alloc(init->pkt_header.initiator_spi,
	    init->pkt_header.responder_spi,
	    IKEV2_VERSION,
	    init->pkt_header.exch_type,
	    init->pkt_header.msgid, flags);
	if (pkt == NULL)
		return (NULL);

	pkt->pkt_sa = init->pkt_sa;
	I2SA_REFHOLD(pkt->pkt_sa);
	return (pkt);
}

struct validate_data {
	bunyan_logger_t	*log;
	pkt_t		*pkt;
	size_t		notify_count;
	size_t		payload_count[IKEV2_NUM_PAYLOADS];
	boolean_t	initiator;
	ikev2_exch_t	exch_type;
};

static pkt_walk_ret_t check_payload(uint8_t, uint8_t, uint8_t *restrict,
    size_t, void *restrict);
static boolean_t check_sa_init_payloads(boolean_t, const size_t *);

/* Allocate a ikev2_pkt_t for an inbound datagram in raw */
pkt_t *
ikev2_pkt_new_inbound(uint8_t *restrict buf, size_t buflen,
    bunyan_logger_t *restrict l)
{
	const ike_header_t	*hdr = NULL;
	pkt_t			*pkt = NULL;
	size_t			*counts = NULL;
	struct validate_data	arg = { 0 };
	size_t			i = 0;
	boolean_t		keep = B_TRUE;

	(void) bunyan_trace(l, "Creating new inbound IKEV2 packet",
	    BUNYAN_T_END);

	ASSERT(IS_P2ALIGNED(buf, sizeof (uint64_t)));

	hdr = (const ike_header_t *)buf;

	ASSERT(IKE_GET_MAJORV(hdr->version) == IKE_GET_MAJORV(IKEV2_VERSION));

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
		(void) bunyan_info(l, "Unknown/unsupported exchange type",
		    BUNYAN_T_STRING, "exch_type",
		    ikev2_exch_str(hdr->exch_type), BUNYAN_T_END);
		return (NULL);
	}

	/* pkt_in_alloc() will log any errors messages */
	if ((pkt = pkt_in_alloc(buf, buflen, l)) == NULL)
		return (NULL);

#if 1
	return (pkt);
#else
	arg.log = l;
	arg.pkt = pkt;
	arg.exch_type = hdr->exch_type;
	arg.initiator = !!(hdr->flags & IKEV2_FLAG_INITIATOR);

	if (pkt_payload_walk((uint8_t *)(hdr + 1),
	    buflen - sizeof (ike_header_t), check_payload, hdr->next_payload,
	    &arg, l) != PKT_WALK_OK)
		goto discard;

	counts = arg.payload_count;

	ikev2_pkt_log(pkt, l, BUNYAN_L_DEBUG, "Received IKEv2 packet");

#define	PAYCOUNT(totals, paytype) totals[(paytype) - IKEV2_PAYLOAD_MIN]

	switch (arg.exch_type) {
	case IKEV2_EXCH_IKE_AUTH:
	case IKEV2_EXCH_CREATE_CHILD_SA:
	case IKEV2_EXCH_INFORMATIONAL:
		/* check_payload() already made sure we only have SK payloads */
		if (PAYCOUNT(counts, IKEV2_PAYLOAD_SK) == 1)
			return (pkt);
		bunyan_warn(l, "Encrypted payloads missing from non "
		    "IKE_SA_INIT exchange", BUNYAN_T_END);
		goto discard;
	case IKEV2_EXCH_IKE_SA_INIT:
		break;
	case IKEV2_EXCH_IKE_SESSION_RESUME:
		/* XXX: unsupported, notify? */
		keep = B_FALSE;
		break;
	default:
		bunyan_info(l, "Unknown exchange",
		    BUNYAN_T_UINT32, "exch_type", (uint32_t)arg.exch_type,
		    BUNYAN_T_END);
		keep = B_FALSE;
		break;
	}

	if (!keep)
		goto discard;

#define	HAS_NOTIFY(totals) (!!(PAYCOUNT(totals, IKEV2_PAYLOAD_NOTIFY) > 0))

	for (i = IKEV2_PAYLOAD_MIN; i <= IKEV2_PAYLOAD_MAX; i++) {
		size_t count = PAYCOUNT(counts, i);

		switch ((ikev2_pay_type_t)i) {
		case IKEV2_PAYLOAD_NONE:
			/* By virtue of loop, this would be an error */
			INVALID("i");
			break;

		/* Never allowed in an SA_INIT exchange */
		case IKEV2_PAYLOAD_IDi:
		case IKEV2_PAYLOAD_IDr:
		case IKEV2_PAYLOAD_CERT:
		case IKEV2_PAYLOAD_AUTH:
		case IKEV2_PAYLOAD_DELETE:
		case IKEV2_PAYLOAD_TSi:
		case IKEV2_PAYLOAD_TSr:
		case IKEV2_PAYLOAD_SK:
		case IKEV2_PAYLOAD_CP:
		case IKEV2_PAYLOAD_EAP:
		case IKEV2_PAYLOAD_GSPM:
		case IKEV2_PAYLOAD_IDg:
		case IKEV2_PAYLOAD_GSA:
		case IKEV2_PAYLOAD_KD:
		case IKEV2_PAYLOAD_SKF:
		case IKEV2_PAYLOAD_PS:	/* Not yet */
			if (count > 0) {
				bunyan_info(l, "Disallowed payload present "
				    "in IKE_SA_INIT exchange",
				    BUNYAN_T_STRING, "payload",
				    ikev2_pay_short_str(i), BUNYAN_T_END);
				keep = B_FALSE;
			}
			break;

		/* can appear 0 or more times */
		case IKEV2_PAYLOAD_NOTIFY:
		case IKEV2_PAYLOAD_CERTREQ:
			break;

		case IKEV2_PAYLOAD_VENDOR:
			if (PAYCOUNT(counts, IKEV2_PAYLOAD_SA) > 0 ||
			    PAYCOUNT(counts, IKEV2_PAYLOAD_NOTIFY) > 0)
				break;
			bunyan_info(l, "Vendor ID payload appears without "
			    "SA or Notification payload", BUNYAN_T_END);
			keep = B_FALSE;
			break;
		case IKEV2_PAYLOAD_SA:
			if (count != 1 && !HAS_NOTIFY(counts)) {
				bunyan_info(l, "Payload missing in "
				    "non-notification IKE_SA_INIT exchange",
				    BUNYAN_T_STRING, "missing",
				    ikev2_pay_short_str(i),
				    BUNYAN_T_END);
				keep = B_FALSE;
			}
			break;

		case IKEV2_PAYLOAD_KE:
		case IKEV2_PAYLOAD_NONCE:
			if (count != 1) {
				if (!HAS_NOTIFY(counts)) {
					bunyan_info(l, "Payload missing in "
					    "non-notification IKE_SA_INIT "
					    "exchange",
					    BUNYAN_T_STRING, "missing",
					    ikev2_pay_short_str(i),
					    BUNYAN_T_END);
					keep = B_FALSE;
				}
				break;
			}
			if (PAYCOUNT(counts, IKEV2_PAYLOAD_SA) != 1) {
				bunyan_info(l, "Missing SA payload",
				    BUNYAN_T_END);
				keep = B_FALSE;
			}
			break;
		}
	}
	if (!keep)
		goto discard;

	(void) bunyan_trace(l, "Created new IKEV2 packet",
	    BUNYAN_T_POINTER, "pkt", pkt,
	    BUNYAN_T_END);

	return (pkt);

discard:
	pkt_free(pkt);
	return (NULL);
#undef PAYCOUNT
#undef HAS_NOTIFY

#endif
}

static boolean_t check_sa_payload(uint8_t *restrict, size_t, boolean_t,
    bunyan_logger_t *restrict l);

/*
 * Cache the payload offsets and do some minimal checking.
 * By virtue of walking the payloads, we also validate the payload
 * lengths do not overflow or underflow
 */
static pkt_walk_ret_t
check_payload(uint8_t paytype, uint8_t resv, uint8_t *restrict buf,
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
		bunyan_info(arg->log, "Discarding packet with unknown exchange",
		    BUNYAN_T_UINT32, "exch_type", (uint32_t)arg->exch_type,
		    BUNYAN_T_END);
		return (PKT_WALK_ERROR);
	}

	ASSERT3U(exch_type, ==, IKEV2_EXCH_SA_INIT);

	arg->payload_count[paytype - IKEV2_PAYLOAD_MIN]++;

	switch (paytype) {
	case IKEV2_PAYLOAD_SA:
		if (!check_sa_payload(buf, buflen, !arg->initiator, log))
			return (PKT_WALK_ERROR);
		break;
	}

	return (PKT_WALK_OK);
}

struct sa_payload_data {
	bunyan_logger_t *log;
	uint32_t lastnum;
	boolean_t is_response;
	boolean_t first;
	boolean_t error;
};

static boolean_t
check_xf_cb(ikev2_transform_t *xf, uint8_t *attr, size_t attrlen, void *cookie)
{
	struct sa_payload_data *info = cookie;
	bunyan_logger_t *l = info->log;

	if (xf->xf_reserved != 0) {
		bunyan_error(l, "Transform reserved field non-zero",
		    BUNYAN_T_UINT32, "value", (uint32_t)xf->xf_reserved,
		    BUNYAN_T_END);
		info->error = B_TRUE;
		return (B_FALSE);
	}
	if (xf->xf_reserved1 != 0) {
		bunyan_error(l, "Transform reserved1 field non-zero",
		    BUNYAN_T_UINT32, "value", (uint32_t)xf->xf_reserved1,
		    BUNYAN_T_END);
		info->error = B_TRUE;
		return (B_FALSE);
	}

	if (attr != NULL && !ikev2_walk_xfattrs(attr, attrlen, NULL, cookie, l))
		return (B_FALSE);

	return (B_TRUE);
}

static boolean_t
check_sa_cb(ikev2_sa_proposal_t *prop, uint64_t spi, uint8_t *data, size_t len,
    void *cookie)
{
	struct sa_payload_data *info = cookie;
	bunyan_logger_t *l = info->log;

	/*
	 * When initiating an SA exchange (IKE or CHILD), there are 1+
	 * proposals numbered sequentially starting with 1.  For an SA payload
	 * in a response, there should be a single proposal whose number
	 * matches the chosen proposal number from the SA payload in the
	 * initiator
	 */
	if (info->is_response) {
		VERIFY(info->first);

		if (prop->proto_more != IKEV2_PROP_LAST) {
			bunyan_error(l,
			    "Proposal response has multiple proposals",
			    BUNYAN_T_END);
			info->error = B_TRUE;
			return (B_FALSE);
		}
	} else {
		if (prop->proto_proposalnr != info->lastnum + 1) {
			bunyan_error(l,
			    "Proposal number is not one greater than "
			    "the previous proposal",
			    BUNYAN_T_UINT32, "propnum",
			    (uint32_t)prop->proto_proposalnr,
			    BUNYAN_T_UINT32, "prevprop", info->lastnum,
			    BUNYAN_T_END);
			info->error = B_TRUE;
			return (B_FALSE);
		}
	}

	switch (prop->proto_protoid) {
		case IKEV2_PROTO_NONE:
		case IKEV2_PROTO_FC_ESP_HEADER:
		case IKEV2_PROTO_FC_CT_AUTH:
			/* Ignore these */
			break;
		case IKEV2_PROTO_IKE:
			/* XXX: validate when 0 vs 8? */
			if (prop->proto_spisize == 0 ||
			    prop->proto_spisize == sizeof (uint64_t))
				break;

			bunyan_error(l,
			    "Invalid proposal SPI length for protocol",
			    BUNYAN_T_UINT32, "propnum",
			    (uint32_t)prop->proto_proposalnr,
			    BUNYAN_T_STRING, "protocol",
			    ikev2_spi_str(prop->proto_protoid),
			    BUNYAN_T_UINT32, "spilen",
			    (uint32_t)prop->proto_spisize, BUNYAN_T_END);
			return (B_FALSE);
		case IKEV2_PROTO_AH:
		case IKEV2_PROTO_ESP:
			if (prop->proto_spisize == sizeof (uint32_t))
				break;
			bunyan_error(l,
			    "Invalid proposal SPI length for protocol",
			    BUNYAN_T_UINT32, "propnum",
			    (uint32_t)prop->proto_proposalnr,
			    BUNYAN_T_STRING, "protocol",
			    ikev2_spi_str(prop->proto_protoid),
			    BUNYAN_T_UINT32, "spilen",
			    (uint32_t)prop->proto_spisize, BUNYAN_T_END);
			return (B_FALSE);
		}

		if (!ikev2_walk_xfs(data, len, check_xf_cb, cookie, l)) {
			info->error = B_TRUE;
			return (B_FALSE);
		}

		info->lastnum = prop->proto_proposalnr;
		info->first = B_FALSE;
		return (B_TRUE);
}

static boolean_t
check_sa_payload(uint8_t *restrict pay, size_t len, boolean_t is_response,
    bunyan_logger_t *restrict l)
{
	struct sa_payload_data data = {
		.log = l,
		.lastnum = 0,
		.is_response = is_response,
		.first = B_FALSE,
		.error = B_FALSE
	};

	if (!ikev2_walk_proposals(pay, len, check_sa_cb, &data, l))
		return (B_FALSE);
	return (data.error);
}

/*
 * Slightly subtle point about the *_walk_* functions - they return B_FALSE
 * on an error during the walk (mostly if payload lengths don't agree). The
 * callback functions however return B_FALSE to terminate the walk early or
 * B_TRUE to continue the walk.  Any error state that needs to propagate up
 * from the walker callbacks needs to be sent through the cookie parameter
 */
boolean_t
ikev2_walk_proposals(uint8_t *restrict start, size_t len,
    ikev2_prop_cb_t cb, void *restrict cookie,
    bunyan_logger_t *restrict l)
{
	uint8_t *ptr = start, *end = start + len;

	while (ptr < end) {
		ikev2_sa_proposal_t prop = { 0 };

		if (ptr + sizeof (prop) > end) {
			bunyan_error(l, "Proposal length mismatch",
			    BUNYAN_T_END);
			return (B_FALSE);
		}

		(void) memcpy(&prop, ptr, sizeof (prop));
		prop.proto_length = ntohs(prop.proto_length);

		if (ptr + prop.proto_length > end) {
			bunyan_error(l, "Proposal overruns SA payload",
			    BUNYAN_T_UINT32, "propnum",
			    (uint32_t)prop.proto_proposalnr,
			    BUNYAN_T_UINT32, "proplen",
			    (uint32_t)prop.proto_length, BUNYAN_T_END);
			return (B_FALSE);
		}

		if (ptr + prop.proto_length == end) {
			if (prop.proto_more != IKEV2_PROP_LAST) {
				bunyan_error(l, "Last proposal does not have "
				    "IKEV2_PROP_LAST set", BUNYAN_T_END);
				return (B_FALSE);
			}
		} else {
			if (prop.proto_more != IKEV2_PROP_MORE) {
				bunyan_error(l, "Non-last proposal does not "
				    "have IKEV2_PROP_MORE set", BUNYAN_T_END);
				return (B_FALSE);
			}
		}

		ptr += sizeof (prop);

		uint64_t spi = 0;
		for (size_t i = 0; i < prop.proto_spisize; i++) {
			uint64_t val = *ptr;
			spi = (spi << 8) | (val & 0xffULL);
			ptr++;
		}

		if (cb != NULL && !cb(&prop, spi, ptr,
		    len - (size_t)(ptr - start), cookie))
			return (B_TRUE);

		ptr += prop.proto_length;
	}
	return (B_TRUE);
}

boolean_t
ikev2_walk_xfs(uint8_t *restrict start, size_t len, ikev2_xf_cb_t cb,
    void *restrict cookie, bunyan_logger_t *restrict l)
{
	uint8_t *ptr = start, *end = start + len;

	while (ptr < end) {
		ikev2_transform_t xf = { 0 };
		uint8_t *attrp = NULL;
		size_t attrlen = 0;

		if (ptr + sizeof (xf) > end) {
			bunyan_error(l, "Transform length mismatch",
			    BUNYAN_T_END);
			return (B_FALSE);
		}

		(void) memcpy(&xf, ptr, sizeof (xf));
		xf.xf_length = ntohs(xf.xf_length);
		xf.xf_id = ntohs(xf.xf_id);

		if (ptr + xf.xf_length > end) {
			bunyan_error(l, "Transform overruns SA payload",
			    BUNYAN_T_END);
			return (B_FALSE);
		}

		if (ptr + xf.xf_length == end) {
			if (xf.xf_more != IKEV2_XF_LAST) {
				bunyan_error(l, "Last transform does not have "
				    "IKEV2_XF_LAST set", BUNYAN_T_END);
				return (B_FALSE);
			}
		} else {
			if (xf.xf_more != IKEV2_XF_MORE) {
				bunyan_error(l, "Non-last transform does not "
				    "have IKEV2_XF_MORE set", BUNYAN_T_END);
				return (B_FALSE);
			}
		}

		if (xf.xf_length > sizeof (xf)) {
			attrp = ptr + sizeof (xf);
			attrlen = xf.xf_length - sizeof (xf);
		}

		if (cb != NULL && !cb(&xf, attrp, attrlen, cookie))
			return (B_TRUE);

		ptr += xf.xf_length;
	}
	return (B_TRUE);
}

boolean_t
ikev2_walk_xfattrs(uint8_t *restrict start, size_t len, ikev2_xfattr_cb_t cb,
    void *restrict cookie, bunyan_logger_t *restrict l)
{
	uint8_t *ptr = start, *end = start + len;

	while (ptr < end) {
		size_t amt = 0;
		ikev2_attribute_t attr = { 0 };

		if (ptr + sizeof (attr) > end) {
			bunyan_error(l, "Attribute length overruns end of "
			    "transform", BUNYAN_T_END);
			return (B_FALSE);
		}

		(void) memcpy(&attr, ptr, sizeof (attr));
		attr.attr_type = ntohs(attr.attr_type);
		attr.attr_length = ntohs(attr.attr_length);

		if (attr.attr_type & IKEV2_ATTRAF_TV) {
			amt = sizeof (attr);
		} else {
			/*
			 * XXX: it's unclear if this length includes the
			 * attribute length includes the header.  Need to check
			 */
			amt = attr.attr_length;
		}

		if (ptr + amt > end) {
			bunyan_error(l, "Attribute value overruns end of "
			    "transform", BUNYAN_T_END);
			return (B_FALSE);
		}

		if (cb != NULL && !cb(&attr, cookie))
			return (B_TRUE);

		ptr += amt;
	}

	return (B_TRUE);
}

void
ikev2_pkt_free(pkt_t *pkt)
{
	if (pkt == NULL)
		return;

	if (pkt->pkt_sa != NULL)
		I2SA_REFRELE(pkt->pkt_sa);

	pkt_free(pkt);
}

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
	encr_data_t *ed = &encr_data[encr];
	uint16_t incr = 0;
	boolean_t ok = B_TRUE;

	if (encr == IKEV2_ENCR_NONE || encr == IKEV2_ENCR_NULL) {
		INVALID("encr");
		/*NOTREACHED*/
		return (B_FALSE);
	}

	if (!ENCR_KEYLEN_ALLOWED(ed)) {
		VERIFY3U(minbits, ==, 0);
		VERIFY3U(maxbits, ==, 0);
		return (ikev2_add_xform(pss, IKEV2_XF_ENCR, encr));
	}

	if (minbits == 0 && maxbits == 0 && !ENCR_KEYLEN_REQ(ed))
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
	bunyan_logger_t		*l = pkt->pkt_sa->i2sa_log;
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
		PKCS11ERR(error, l, "C_GetAttributeValue", rc);
		return (B_FALSE);
	}
	keylen = template.ulValueLen;

	if (!ikev2_add_payload(pkt, IKEV2_PAYLOAD_KE, B_FALSE,
	    sizeof (ke) + keylen)) {
		bunyan_error(l, "Not enough space in packet for DH pubkey",
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
		PKCS11ERR(error, l, "C_GetAttributeValue", rc);
		return (B_FALSE);
	}
	pkt_adv_ptr(pkt, keylen);

	return (B_TRUE);
}

static boolean_t
ikev2_add_id_common(pkt_t *restrict pkt, boolean_t id_i, ikev2_id_type_t idtype,
    va_list ap)
{
	ikev2_id_t		id = { 0 };
	ikev2_pay_type_t 	paytype =
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
	PKT_APPEND_DATA(pkt, data, len);
	return (B_TRUE);
}

boolean_t
ikev2_add_nonce(pkt_t *restrict pkt, uint8_t *restrict nonce, size_t len)
{
	if (!ikev2_add_payload(pkt, IKEV2_PAYLOAD_NONCE, B_FALSE, len))
		return (B_FALSE);

	/*
	 * We allow a NULL value to generate a new nonce of size len,
	 * and otherwise use the existing one passed in to simplify
	 * creating a new initiator packet for a IKE_SA_INIT exchange
	 * when we have to add additional payloads (COOKIE, new DH group).
	 */
	if (nonce != NULL) {
		PKT_APPEND_DATA(pkt, nonce, len);
	} else {
		random_high(pkt->pkt_ptr, len);
		pkt_adv_ptr(pkt, len);
	}
	return (B_TRUE);
}

boolean_t
ikev2_add_notify(pkt_t *restrict pkt, ikev2_spi_proto_t proto, uint64_t spi,
    ikev2_notify_type_t ntfy_type, const void *restrict data, size_t len)
{
	size_t spisize = ikev2_spilen(proto);

	if (proto == IKEV2_PROTO_IKE && spi == 0)
		spisize = 0;

	return (pkt_add_notify(pkt, 0, proto, spisize, spi, ntfy_type, data,
	    len));
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
	PKT_APPEND_DATA(pkt, vid, len);
	return (B_TRUE);
}

/*
 * This will need to be adjusted once we have a better idea how we will
 * obtain the traffic selectors to better tailor the interface for adding
 * them to the IKE datagram
 */
#if 0
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

static boolean_t ts_finish(pkt_t *restrict, uint8_t *restrict, uintptr_t,
    size_t);

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

static boolean_t
ts_finish(pkt_t *restrict pkt, uint8_t *restrict buf, uintptr_t swaparg,
    size_t numts)
{
	ikev2_tsp_t	ts = { 0 };

	ASSERT3U(numts, <, 0x100);

	(void) memcpy(&ts, buf, sizeof (ts));
	ts.tsp_count = (uint8_t)numts;
	(void) memcpy(buf, &ts, sizeof (ts));
	return (B_TRUE);
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
#else
/* Placeholders */
boolean_t
ikev2_add_ts_i(pkt_t *restrict pkt)
{
	return (B_FALSE);
}

boolean_t
ikev2_add_ts_r(pkt_t *restrict pkt)
{
	return (B_FALSE);
}
boolean_t
ikev2_add_ts(pkt_t *restrict pkt, ikev2_ts_type_t type, uint8_t ip_proto,
    const sockaddr_u_t *restrict start, const sockaddr_u_t *restrict end)
{
	return (B_FALSE);
}
#endif

static boolean_t add_iv(pkt_t *restrict pkt);

boolean_t
ikev2_add_sk(pkt_t *restrict pkt)
{
	ikev2_sa_t *sa = pkt->pkt_sa;
	ikev2_payload_t *payp = (ikev2_payload_t *)pkt->pkt_ptr;

	if (!ikev2_add_payload(pkt, IKEV2_PAYLOAD_SK, B_FALSE, 0))
		return (B_FALSE);

	pkt->pkt_encr_pay = pkt_get_payload(pkt, IKEV2_PAYLOAD_SK, NULL);
	return (add_iv(pkt));
}

static boolean_t
add_iv(pkt_t *restrict pkt)
{
	ikev2_sa_t *sa = pkt->pkt_sa;
	size_t len = encr_data[sa->encr].ed_blocklen;
	encr_modes_t mode = encr_data[sa->encr].ed_mode;

	if (pkt_write_left(pkt) < len)
		return (B_FALSE);

	switch (mode) {
	case MODE_CCM:
	case MODE_GCM:
		/*
		 * For these modes, it's sufficient that the IV + key
		 * is unique.  The packet message id satisifies these
		 * requirements.
		 */
		put32(pkt, pkt->pkt_header.msgid);
		pkt_adv_ptr(pkt, len - sizeof (pkt->pkt_header.msgid));
		return (B_TRUE);
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
	CK_ULONG blocklen = 0;
	CK_RV rc = CKR_OK;

	if (pkt->pkt_sa->flags & I2SA_INITIATOR)
		key = sa->sk_ei;
	else
		key = sa->sk_er;

	switch (pkt->pkt_sa->encr) {
	case IKEV2_ENCR_AES_CBC:
		mech.mechanism = CKM_AES_ECB;
		mech.pParameter = NULL_PTR;
		mech.ulParameterLen = 0;
		blocklen = 16;
		break;
	case IKEV2_ENCR_CAMELLIA_CBC:
		mech.mechanism = CKM_CAMELLIA_ECB;
		mech.pParameter = NULL_PTR;
		mech.ulParameterLen = 0;
		blocklen = 16;
		break;
	default:
		INVALID("encr");
		/*NOTREACHED*/
		return (B_FALSE);
	}
	CK_BYTE buf[blocklen];

	(void) memset(buf, 0, blocklen);
	(void) memcpy(buf, &pkt->pkt_header.msgid,
	    sizeof (pkt->pkt_header.msgid));

	rc = C_EncryptInit(h, &mech, key);
	if (rc != CKR_OK) {
		PKCS11ERR(error, sa->i2sa_log, "C_EncryptInit", rc);
		return (B_FALSE);
	}

	rc = C_Encrypt(h, buf, blocklen, buf, &blocklen);
	if (rc != CKR_OK) {
		PKCS11ERR(error, sa->i2sa_log, "C_Encrypt", rc);
		return (B_FALSE);
	}

	(void) memcpy(pkt->pkt_ptr, buf, MIN(len, blocklen));
	explicit_bzero(buf, blocklen);
	pkt_adv_ptr(pkt, MIN(len, blocklen));
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
	CK_ULONG ivlen = encr_data[sa->encr].ed_blocklen;
	CK_ULONG icvlen = ikev2_auth_icv_size(sa->encr, sa->auth);
	CK_ULONG blocklen = encr_data[sa->encr].ed_blocklen;
	CK_ULONG noncelen = ivlen + sa->saltlen;
	CK_ULONG datalen = 0, outlen = 0;
	CK_BYTE nonce[noncelen];
	CK_RV rc = CKR_OK;
	encr_modes_t mode = encr_data[sa->encr].ed_mode;
	uint8_t padlen = 0;

	if (encrypt)
		VERIFY3P(pkt->pkt_encr_pay, ==, sk);

	if (sa->flags & I2SA_INITIATOR) {
		key = sa->sk_ei;
		salt = sa->salt_i;
	} else {
		key = sa->sk_er;
		salt = sa->salt_r;
	}

	(void) memcpy(nonce, iv, ivlen);
	if (sa->saltlen > 0)
		(void) memcpy(nonce + ivlen, salt, sa->saltlen);

	iv = sk->pp_ptr;

	data = iv + ivlen;
	datalen = (CK_ULONG)(pkt->pkt_ptr - data) - icvlen;
	outlen = pkt_write_left(pkt) + icvlen;

	icv = data + datalen;

	if (encrypt) {
		/* If we're creating it, it better be correct */
		VERIFY3U(sk->pp_len, ==, ivlen + datalen + icvlen);
	} else {
		/* Otherwise check first */
		if (sk->pp_len != ivlen + datalen + icvlen) {
			bunyan_info(sa->i2sa_log,
			    "Encrypted payload invalid length",
			    BUNYAN_T_UINT32, "paylen", (uint32_t)sk->pp_len,
			    BUNYAN_T_UINT32, "ivlen", (uint32_t)ivlen,
			    BUNYAN_T_UINT32, "datalen", (uint32_t)datalen,
			    BUNYAN_T_UINT32, "icvlen", (uint32_t)icvlen,
			    BUNYAN_T_END);
			return (B_FALSE);
		}
	}
 
	mech.mechanism = encr_data[sa->encr].ed_p11id;
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
		PKCS11ERR(error, sa->i2sa_log, fn, rc);
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
		PKCS11ERR(error, sa->i2sa_log, "C_Encrypt", rc,
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
	if (pkt->pkt_sa->vendor == VENDOR_ILLUMOS_1) {
		uint8_t *pad;

		padlen = icv[-1];
		pad = icv - padlen - 1;

		for (size_t i = 0; i <= padlen; i++) {
			if (pad[i] == padlen)
				continue;

			bunyan_warn(sa->i2sa_log, "Padding validation failed",
			    BUNYAN_T_UINT32, "padlen", (uint32_t)padlen,
			    BUNYAN_T_UINT32, "offset", (uint32_t)i,
			    BUNYAN_T_END);
			return (B_FALSE);
		}
	}
	datalen -= padlen + 1;

	ike_payload_t *skpay = ((ike_payload_t *)sk->pp_ptr) - 1;

	if (!pkt_index_payloads(pkt, data, datalen, skpay->pay_next,
	    sa->i2sa_log))
		return (B_FALSE);

	return (B_TRUE);
}

boolean_t
ikev2_pkt_signverify(pkt_t *pkt, boolean_t sign)
{
	ikev2_sa_t *sa = pkt->pkt_sa;

	if (MODE_IS_COMBINED(encr_data[sa->encr].ed_mode))
		return (B_TRUE);

	const char *fn = NULL;
	pkt_payload_t *sk = pkt_get_payload(pkt, IKEV2_PAYLOAD_SK, NULL);
	CK_SESSION_HANDLE h = p11h();
	CK_OBJECT_HANDLE key;
	CK_MECHANISM mech = {
		.mechanism = auth_data[sa->auth].ad_p11id,
		.pParameter = NULL_PTR,
		.ulParameterLen = 0
	};
	CK_BYTE_PTR icv;
	CK_ULONG signlen, icvlen;
	CK_ULONG outlen = auth_data[sa->auth].ad_outlen;
	CK_BYTE outbuf[outlen];
	CK_RV rc;

	if (sa->flags & I2SA_INITIATOR)
		key = sa->sk_ai;
	else
		key = sa->sk_ar;

	icvlen = ikev2_auth_icv_size(sa->encr, sa->auth);
	signlen = pkt_len(pkt) - icvlen;
	icv = pkt->pkt_ptr - icvlen;

	rc = C_SignInit(h, &mech, key);
	if (rc != CKR_OK) {
		PKCS11ERR(error, sa->i2sa_log, "C_SignInit", rc);
		return (B_FALSE);
	}

	rc = C_Sign(h, pkt_start(pkt), signlen, outbuf, &outlen);
	if (rc != CKR_OK) {
		PKCS11ERR(error, sa->i2sa_log, "C_Sign", rc);
		return (B_FALSE);
	}

	if (sign) {
		(void) memcpy(icv, outbuf, auth_data[sa->auth].ad_icvlen);
		return (B_TRUE);
	}

	if (memcmp(icv, outbuf, auth_data[sa->auth].ad_icvlen) == 0)
		return (B_TRUE);

	bunyan_info(sa->i2sa_log, "Payload signature validation failed",
	    BUNYAN_T_END);
	return (B_FALSE);
}

boolean_t
ikev2_pkt_done(pkt_t *pkt)
{
	if (pkt->pkt_done)
		return (B_TRUE);

	pkt_payload_t *sk = pkt_get_payload(pkt, IKEV2_PAYLOAD_SK, NULL);

	if (pkt->pkt_header.exch_type == IKEV2_EXCH_IKE_SA_INIT) {
		VERIFY3P(sk, ==, NULL);
		return (pkt_done(pkt));
	}

	VERIFY3P(sk, !=, NULL);

	ike_payload_t *skpay = ((ike_payload_t *)sk->pp_ptr) - 1;
	uint8_t *sklen = (uint8_t *)&skpay->pay_length;
	ikev2_sa_t *sa = pkt->pkt_sa;
	CK_ULONG datalen = (CK_ULONG)(pkt->pkt_ptr - pkt->pkt_encr_pay->pp_ptr);
	CK_ULONG icvlen = ikev2_auth_icv_size(sa->encr, sa->auth);
	CK_ULONG blocklen = encr_data[sa->encr].ed_blocklen;
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
		bunyan_info(sa->i2sa_log, "Not enough space for packet",
		    BUNYAN_T_END);
		goto done;
	}

	for (size_t i = 0; i <= padlen; i++)
		pkt->pkt_ptr[i] = padlen;
	pkt_adv_ptr(pkt, padlen);

	/*
	 * Skip over the space for the ICV.  This is necessary so that all
	 * the lengths (packet, payload) are updated with the final values
	 * prior to encryption and signing.
	 */
	pkt_adv_ptr(pkt, icvlen);

	BE_OUT16(sklen, (uint16_t)(pkt->pkt_ptr - sk->pp_ptr) +
	    sizeof (ike_payload_t));

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
char *
ikev2_pkt_desc(pkt_t *pkt)
{
	char *s = NULL;
	size_t len = 0;
	uint16_t i;
	uint16_t j;

	for (i = j = 0; i < pkt->pkt_payload_count; i++) {
		pkt_payload_t *pay = pkt_payload(pkt, i);
		const char *paystr =
		    ikev2_pay_short_str((ikev2_pay_type_t)pay->pp_type);

		len += strlen(paystr) + 2;
		if (pay->pp_type == IKEV2_PAYLOAD_NOTIFY) {
			pkt_notify_t *n = pkt_notify(pkt, j++);
			const char *nstr =
			    ikev2_notify_str((ikev2_notify_type_t)n->pn_type);

			len += strlen(nstr) + 2;
		}
	}

	s = calloc(1, len);
	VERIFY3P(s, !=, len);

	for (i = j = 0; i < pkt->pkt_payload_count; i++) {
		pkt_payload_t *pay = pkt_payload(pkt, i);
		const char *paystr =
		    ikev2_pay_short_str((ikev2_pay_type_t)pay->pp_type);

		if (i > 0)
			(void) strlcat(s, ", ", len);

		(void) strlcat(s, paystr, len);
		if (pay->pp_type == IKEV2_PAYLOAD_NOTIFY) {
			pkt_notify_t *n = pkt_notify(pkt, j++);
			const char *nstr =
			    ikev2_notify_str((ikev2_notify_type_t)n->pn_type);

			/*
			 * Notify type is 16-bits, so (XXXXX) (7 chars) is
			 * the largest it can be (and is < than "UNKNOWN"),
			 * so no worries about truncation.
			 */
			if (strcmp(nstr, "UNKNOWN") == 0) {
				char buf[8] = { 0 };
				(void) snprintf(buf, sizeof (buf), "(%hhu)",
				    (uint16_t)n->pn_type);
				(void) strlcat(s, buf, len);
			} else {
				(void) strlcat(s, "(", len);
				(void) strlcat(s, nstr, len);
				(void) strlcat(s, ")", len);
			}
		}
	}

	return (s);
}

void
ikev2_pkt_log(pkt_t *restrict pkt, bunyan_logger_t *restrict log,
    bunyan_level_t level, const char *msg)
{
	char *descstr = ikev2_pkt_desc(pkt);
	char ispi[19];
	char rspi[19];

	VERIFY3P(descstr, !=, NULL);

	(void) snprintf(ispi, sizeof (ispi), "0x%" PRIX64,
	    pkt->pkt_header.initiator_spi);
	(void) snprintf(rspi, sizeof (rspi), "0x%" PRIX64,
	    pkt->pkt_header.responder_spi);

	getlog(level)(log, msg,
	    BUNYAN_T_STRING, "initiator_spi", ispi,
	    BUNYAN_T_UINT64, "responder_spi", rspi,
	    BUNYAN_T_STRING, "exch_type",
	    ikev2_exch_str(pkt->pkt_header.exch_type),
	    BUNYAN_T_UINT32, "msgid", pkt->pkt_header.msgid,
	    BUNYAN_T_UINT32, "msglen", pkt->pkt_header.length,
	    BUNYAN_T_STRING, "payloads", descstr,
	    BUNYAN_T_END);
	free(descstr);
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
	(void) memcpy(&val, ke->pp_ptr, sizeof (val));
	return ((ikev2_dh_t)ntohs(val));
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
