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

	ASSERT(IS_P2ALIGNED(buf, sizeof (uint64_t)));

	hdr = (const ike_header_t *)buf;

	ASSERT(IKE_GET_MAJORV(hdr->version) == IKE_GET_MAJORV(IKEV2_VERSION));

	/*
	 * Make sure either the initiator or response flag is set, but
	 * not both.
	 */
	uint8_t flags = hdr->flags & (IKEV2_FLAG_INITIATOR|IKEV2_FLAG_RESPONSE);
	if ((flags ^ (IKEV2_FLAG_INITIATOR|IKEV2_FLAG_RESPONSE)) == 0) {
		char flagstr[5] = { 0 };	/* 0xXX + NUL */

		(void) snprintf(flagstr, sizeof (flagstr), "0x%hhx", flags);
		bunyan_info(l, "Invalid flags value in IKE header",
		    BUNYAN_T_STRING, "flags", flagstr,
		    BUNYAN_T_END);
		return (NULL);
	}

	/* pkt_in_alloc() will log any errors messages */
	if ((pkt = pkt_in_alloc(buf, buflen, l)) == NULL)
		return (NULL);

	arg.log = l;
	arg.pkt = pkt;
	arg.exch_type = hdr->exch_type;
	arg.initiator = !!(hdr->flags & IKEV2_FLAG_INITIATOR);

	if (pkt_payload_walk((uint8_t *)(hdr + 1),
	    buflen - sizeof (ike_header_t), check_payload, hdr->next_payload,
	    &arg, l) != PKT_WALK_OK)
		goto discard;

	counts = arg.payload_count;

	ikev2_pkt_log(pkt, l, "Received IKEv2 packet", BUNYAN_L_DEBUG);

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

	return (pkt);

discard:
	pkt_free(pkt);
	return (NULL);
#undef PAYCOUNT
#undef HAS_NOTIFY
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

static boolean_t check_sa_payload(uint8_t *restrict, size_t, boolean_t,
    bunyan_logger_t *restrict l);
static boolean_t check_notify_payload(struct validate_data *restrict,
    uint8_t *restrict, size_t, bunyan_logger_t *restrict l);

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
	case IKEV2_PAYLOAD_NOTIFY:
		if (!check_notify_payload(arg, buf, buflen, log))
			return (PKT_WALK_ERROR);
		break;
	case IKEV2_PAYLOAD_SA:
		if (!check_sa_payload(buf, buflen, !arg->initiator, log))
			return (PKT_WALK_ERROR);
		break;
	}

	return (PKT_WALK_OK);
}

static boolean_t
check_notify_payload(struct validate_data *restrict arg, uint8_t *restrict buf,
    size_t buflen, bunyan_logger_t *restrict l)
{
	pkt_notify_t *ntfyp = pkt_notify(arg->pkt, arg->notify_count++);
	ikev2_notify_t ntfy = { 0 };
	size_t len = sizeof (ntfy);

	if (buflen < len) {
		bunyan_info(l, "Notify data is truncated", BUNYAN_T_END);
		return (B_FALSE);
	}

	(void) memcpy(&ntfy, buf, sizeof (ntfy));
	len += ntfy.n_spisize;
	if (buflen < len) {
		bunyan_info(l, "SPI size overflows notify payload",
		    BUNYAN_T_UINT32, "spisize", (uint32_t)ntfy.n_spisize,
		    BUNYAN_T_END);
		return (B_FALSE);
	}

	ntfyp->pn_ptr = buf;
	ntfyp->pn_type = ntohs(ntfy.n_type);
	ntfyp->pn_len = buflen;
	return (B_TRUE);
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

void
ikev2_pkt_free(pkt_t *pkt)
{
	pkt_free(pkt);
}

static void
ikev2_add_payload(pkt_t *pkt, ikev2_pay_type_t ptype, boolean_t critical)
{
	uint8_t *payptr;
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
ikev2_add_xf_encr(pkt_t *pkt, ikev2_xf_encr_t encr, uint16_t minbits,
    uint16_t maxbits)
{
	uint16_t incr = 0;
	boolean_t ok = B_TRUE;

	switch (encr) {
	case IKEV2_ENCR_NONE:
	case IKEV2_ENCR_NULL:
		INVALID("encr");
		/*NOTREACHED*/
		return (B_FALSE);

	/* XXX: need to confirm this */
	case IKEV2_ENCR_NULL_AES_GMAC:
		return (B_TRUE);

	/* ones that should never include a key size */
	case IKEV2_ENCR_DES_IV64:
	case IKEV2_ENCR_DES:
	case IKEV2_ENCR_3DES:
	case IKEV2_ENCR_IDEA:
	case IKEV2_ENCR_3IDEA:
	case IKEV2_ENCR_DES_IV32:
		VERIFY3U(minbits, ==, 0);
		VERIFY3U(maxbits, ==, 0);
		return (ikev2_add_xform(pkt, IKEV2_XF_ENCR, encr));

	/* optional key size */
	case IKEV2_ENCR_RC4:
	case IKEV2_ENCR_RC5:
	case IKEV2_ENCR_BLOWFISH:
	case IKEV2_ENCR_CAST:
		if (minbits == 0 && maxbits == 0)
			return (ikev2_add_xform(pkt, IKEV2_XF_ENCR, encr));
		incr = 1;
		break;

	case IKEV2_ENCR_AES_CBC:
	case IKEV2_ENCR_AES_CTR:
	case IKEV2_ENCR_AES_CCM_8:
	case IKEV2_ENCR_AES_CCM_12:
	case IKEV2_ENCR_AES_CCM_16:
	case IKEV2_ENCR_AES_GCM_8:
	case IKEV2_ENCR_AES_GCM_12:
	case IKEV2_ENCR_AES_GCM_16:
	case IKEV2_ENCR_XTS_AES:
		incr = 64;
		break;

	case IKEV2_ENCR_CAMELLIA_CBC:
	case IKEV2_ENCR_CAMELLIA_CTR:
	case IKEV2_ENCR_CAMELLIA_CCM_8:
	case IKEV2_ENCR_CAMELLIA_CCM_12:
	case IKEV2_ENCR_CAMELLIA_CCM_16:
		VERIFY3U(minbits, >=, 128);
		VERIFY3U(maxbits, <=, 256);
		incr = 64;
		break;
	}

	if (incr == 1) {
		/*
		 * instead of adding potentially hundreds of transforms for
		 * a range of keysizes, for those with arbitrary key sizes
		 * we just add the min and max
		 */
		if (minbits != maxbits) {
			ok &= ikev2_add_xform(pkt, IKEV2_XF_ENCR, encr);
			ok &= ikev2_add_xf_attr(pkt, IKEV2_XF_ATTR_KEYLEN,
			    minbits);
		}
		ok &= ikev2_add_xform(pkt, IKEV2_XF_ENCR, encr);
		ok &= ikev2_add_xf_attr(pkt, IKEV2_XF_ATTR_KEYLEN, maxbits);
		return (ok);
	}

	for (size_t bits = minbits; bits <= maxbits; bits += incr) {
		ok &= ikev2_add_xform(pkt, IKEV2_XF_ENCR, encr);
		ok &= ikev2_add_xf_attr(pkt, IKEV2_XF_ATTR_KEYLEN, bits);
	}

	return (ok);
}

boolean_t
ikev2_add_ke(pkt_t *restrict pkt, uint_t group,
    const uint8_t *restrict data, size_t len)
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
    ikev2_cert_t, const uint8_t *, size_t);

boolean_t
ikev2_add_cert(pkt_t *restrict pkt, ikev2_cert_t cert_type, const uint8_t *cert,
    size_t len)
{
	return (ikev2_add_cert_common(pkt, B_TRUE, cert_type, cert, len));
}

boolean_t
ikev2_add_certreq(pkt_t *restrict pkt, ikev2_cert_t cert_type,
    const uint8_t *cert, size_t len)
{
	return (ikev2_add_cert_common(pkt, B_FALSE, cert_type, cert, len));
}

static boolean_t
ikev2_add_cert_common(pkt_t *restrict pkt, boolean_t cert, ikev2_cert_t type,
    const uint8_t *restrict data, size_t len)
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
    const uint8_t *restrict data, size_t len)
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
ikev2_add_nonce(pkt_t *restrict pkt, size_t len)
{
	if (pkt_write_left(pkt) < sizeof (ikev2_payload_t) + len)
		return (B_FALSE);

	ikev2_add_payload(pkt, IKEV2_PAYLOAD_NONCE, B_FALSE);
	random_high(pkt->pkt_ptr, len);
	pkt->pkt_ptr += len;
	return (B_TRUE);
}

boolean_t
ikev2_add_notify(pkt_t *restrict pkt, ikev2_spi_proto_t proto, uint64_t spi,
    ikev2_notify_type_t ntfy_type, const void *restrict data, size_t len)
{
	ikev2_notify_t ntfy = { 0 };
	size_t spisize = 0;

	switch (proto) {
	case IKEV2_PROTO_NONE:
	case IKEV2_PROTO_FC_ESP_HEADER:
	case IKEV2_PROTO_FC_CT_AUTH:
		INVALID("proto");
		/*NOTREACHED*/
		return (B_FALSE);
	case IKEV2_PROTO_IKE:
		if (spi != 0)
			spisize == sizeof (uint64_t);
		break;
	case IKEV2_PROTO_AH:
	case IKEV2_PROTO_ESP:
		spisize = sizeof (uint32_t);
		VERIFY3U(spi, <=, UINT32_MAX);
		VERIFY3U(spi, !=, 0);
		break;
	}

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
		put32(pkt, htonl((uint32_t)spi));
		break;
	case sizeof (uint64_t):
		put64(pkt, htonll(spi));
		break;
	default:
		INVALID(spisize);
	}

	if (data != NULL)
		PKT_APPEND_DATA(pkt, data, len);

	return (B_TRUE);
}

static boolean_t delete_finish(pkt_t *restrict, uint8_t *restrict, uintptr_t,
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

static boolean_t
delete_finish(pkt_t *restrict pkt, uint8_t *restrict buf, uintptr_t swaparg,
    size_t numspi)
{
	ikev2_delete_t	del = { 0 };

	ASSERT3U(numspi, <, 0x10000);

	(void) memcpy(&del, buf, sizeof (del));
	del.del_nspi = htons((uint16_t)numspi);
	(void) memcpy(buf, &del, sizeof (del));
	return (B_TRUE);
}

boolean_t
ikev2_add_vendor(pkt_t *restrict pkt, const void *restrict vid, size_t len)
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

static boolean_t encrypt_payloads(pkt_t *restrict, uint8_t *restrict, uintptr_t,
    size_t);
static boolean_t cbc_iv(pkt_t *restrict, uint8_t *);

boolean_t
ikev2_add_sk(pkt_t *restrict pkt)
{
	ikev2_sa_t *sa = pkt->pkt_sa;
	size_t len = sizeof (ikev2_payload_t);
	size_t ivlen = ikev2_encr_iv_size(sa->encr);
	boolean_t ret;

	len += ivlen;
	len += ikev2_auth_icv_size(sa->encr, sa->auth);
	len += ikev2_encr_block_size(sa->encr);

	if (pkt_write_left(pkt) < len)
		return (B_FALSE);

	/*
	 * This needs to happen first so that subsequent payloads are
	 * encapsulated by the SK payload
	 */
	pkt_stack_push(pkt, PSI_SK, encrypt_payloads, 0);
	ikev2_add_payload(pkt, IKEV2_PAYLOAD_SK, B_FALSE);

	/*
	 * Skip over space for IV, encrypt_payloads() will fill it in.
	 * The memset() shouldn't be needed, as the memory should already be
	 * 0-filled, but erring on the side of caution.
	 */
	(void) memset(pkt->pkt_ptr, 0, ivlen);
	pkt->pkt_ptr += ivlen;
	return (B_TRUE);
}

/*
 * Based on recommendation from NIST 800-38A, Appendix C, use msgid
 * which should be unique, encrypt using SK to generate IV
 */
static boolean_t
cbc_iv(pkt_t *restrict pkt, uint8_t *ivp)
{
	ikev2_sa_t *sa = pkt->pkt_sa;
	CK_SESSION_HANDLE handle = p11h;
	CK_MECHANISM mech;
	CK_OBJECT_HANDLE key;
	CK_RV rv;
	CK_ULONG blocklen = 0; /* in bytes */

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

	if (pkt_write_left(pkt) < blocklen)
		return (B_FALSE);

	VERIFY3U(blocklen, >=, sizeof (uint32_t));

	CK_ULONG buflen = blocklen;
	uint8_t buf[blocklen];

	(void) memset(buf, 0, blocklen);
	(void) memcpy(buf, &pkt->pkt_header.msgid,
	    sizeof (pkt->pkt_header.msgid));

	rv = C_EncryptInit(handle, &mech, key);
	if (rv != CKR_OK) {
		PKCS11ERR(error, sa->i2sa_log, "C_EncryptInit", rv);
		return (B_FALSE);
	}

	rv = C_Encrypt(handle, buf, blocklen, buf, &blocklen);
	if (rv != CKR_OK) {
		PKCS11ERR(error, sa->i2sa_log, "C_Encrypt", rv);
		return (B_FALSE);
	}

	(void) memcpy(ivp, buf, ikev2_encr_iv_size(sa->encr));
	return (B_TRUE);
}

static boolean_t
crypt_common(pkt_t *pkt, boolean_t encrypt, uint8_t *iv, CK_ULONG ivlen,
    uint8_t *data, CK_ULONG datalen, uint8_t *icv, CK_ULONG icvlen)
{
	ikev2_sa_t *sa = pkt->pkt_sa;
	const char *fn;
	CK_SESSION_HANDLE handle = p11h;
	CK_OBJECT_HANDLE key;
	CK_MECHANISM mech;
	union {
		CK_AES_CTR_PARAMS	aes_ctr;
		CK_CAMELLIA_CTR_PARAMS	cam_ctr;
		CK_GCM_PARAMS		gcm;
		CK_CCM_PARAMS		ccm;
	} params;
	CK_RV rc = 0;
	encr_modes_t mode = ikev2_encr_mode(sa->encr);
	uint8_t *nonce = NULL;
	CK_ULONG noncelen = 0;

	if (sa->flags & I2SA_INITIATOR)
		key = pkt->pkt_sa->sk_ei;
	else
		key = pkt->pkt_sa->sk_er;

	/*
	 * For GCM and CCM, the nonce/IV used is a combination of both
	 * the salt (derived from the PRF function along with the key)
	 * and the transmitted 'IV' value.  This total value should be
	 * 10-16 bytes at most, so the use of alloca() shouldn't present
	 * any issues
	 */
	mech.mechanism = ikev2_encr_to_p11(sa->encr);
	switch (mode) {
	case MODE_NONE:
		break;
	case MODE_CBC:
		mech.pParameter = iv;
		mech.ulParameterLen = ivlen;
		break;
	case MODE_CTR:
		/* TODO */
		break;
	case MODE_CCM:
		noncelen = sa->saltlen + ivlen;
		nonce = alloca(noncelen);
		(void) memcpy(nonce, sa->salt, sa->saltlen);
		(void) memcpy(nonce + sa->saltlen, iv, ivlen);
		params.ccm.pAAD = pkt_start(pkt);
		params.ccm.ulAADLen = (CK_ULONG)(iv - params.ccm.pAAD);
		params.ccm.ulMACLen = icvlen;
		params.ccm.pNonce = nonce;
		params.ccm.ulNonceLen = noncelen;
		mech.pParameter = &params.ccm;
		mech.ulParameterLen = sizeof (CK_CCM_PARAMS);
		break;
	case MODE_GCM:
		noncelen = sa->saltlen + ivlen;
		nonce = alloca(noncelen);
		(void) memcpy(nonce, sa->salt, sa->saltlen);
		(void) memcpy(nonce + sa->saltlen, iv, ivlen);
		params.gcm.pIv = nonce;
		params.gcm.ulIvLen = noncelen;
		/*
		 * There is a 'ulIvBits' field in CK_GCM_PARAMS.  This comes
		 * straight from the published pkcs11t.h file.  However, it
		 * does not appear to actually be used for anything, and looks
		 * to be a leftover from the unpublished PKCS#11 v2.30 standard.
		 * It is currently not set and ignored
		 */
		params.gcm.pAAD = pkt_start(pkt);
		params.gcm.ulAADLen = (CK_ULONG)(iv - params.gcm.pAAD);
		params.gcm.ulTagBits = icvlen * 8;
		mech.pParameter = &params.gcm;
		mech.ulParameterLen = sizeof (CK_GCM_PARAMS);
		break;
	}

	if (encrypt) {
		rc = C_EncryptInit(handle, &mech, key);
		fn = "C_EncryptInit";
	} else {
		rc = C_DecryptInit(handle, &mech, key);
		fn = "C_DecryptInit";
	}

	if (rc != CKR_OK) {
		PKCS11ERR(error, sa->i2sa_log, fn, rc);
		goto done;
	}

	/*
	 * XXX: the last parameter might need a separate var
	 * because of extra room needed for ccm/gcm
	 * ALSO: probably want a better error message for the combined mode
	 * failures
	 */
	if (encrypt) {
		rc = C_Encrypt(handle, data, datalen, data, &datalen);
		fn = "C_Encrypt";
	} else {
		rc = C_Decrypt(handle, data, datalen, data, &datalen);
		fn = "C_Decrypt";
	}
	if (rc != CKR_OK)
		PKCS11ERR(error, sa->i2sa_log, fn, rc);

done:
	if (nonce != NULL)
		(void) memset(nonce, 0, sizeof (nonce));
	return ((rc == CKR_OK) ? B_TRUE : B_FALSE);
}

static boolean_t
auth_common(pkt_t *pkt, boolean_t encrypt, uint8_t *icv, size_t icvlen)
{
	ikev2_sa_t *sa = pkt->pkt_sa;
	const char *fn = NULL;
	CK_SESSION_HANDLE handle = p11h;
	CK_OBJECT_HANDLE key;
	CK_MECHANISM mech = { 0 };
	CK_RV rc;
	CK_BYTE_PTR data;
	CK_ULONG datalen, len = icvlen;

	if (sa->flags & I2SA_INITIATOR)
		key = sa->sk_ai;
	else
		key = sa->sk_ar;

	ASSERT3S(sa->auth, !=, IKEV2_XF_AUTH_NONE);
	mech.mechanism = ikev2_auth_to_p11(sa->auth);
	mech.pParameter = NULL_PTR;
	mech.ulParameterLen = 0;

	data = pkt_start(pkt);
	datalen = (CK_ULONG)(icv - data);

	if (encrypt) {
		rc = C_SignInit(handle, &mech, key);
		fn = "C_SignInit";
	} else {
		rc = C_VerifyInit(handle, &mech, key);
		fn = "C_SignInit";
	}

	if (rc != CKR_OK) {
		PKCS11ERR(error, sa->i2sa_log, fn, rc);
		return (B_FALSE);
	}

	if (encrypt) {
		rc = C_Sign(handle, data, datalen, icv, &len);
		fn = "C_Sign";
	} else {
		rc = C_Verify(handle, data, datalen, icv, len);
		fn = "C_Verify";

		/* give this one a better message */
		if (rc == CKR_SIGNATURE_INVALID) {
			bunyan_error(sa->i2sa_log, "integrity check failed",
			    BUNYAN_T_END);
			return (B_FALSE);
		}
	}

	if (rc != CKR_OK)
		PKCS11ERR(error, sa->i2sa_log, fn, rc);

	return ((rc == CKR_OK) ? B_TRUE : B_FALSE);
}

static boolean_t
encrypt_payloads(pkt_t *restrict pkt, uint8_t *restrict buf, uintptr_t swaparg,
    size_t numencr)
{
	ikev2_sa_t *sa = pkt->pkt_sa;
	CK_BYTE_PTR iv, data, icv, nonce;
	CK_ULONG ivlen, datalen, icvlen, noncelen, blocklen;
	uint8_t padlen = 0;
	encr_modes_t mode = ikev2_encr_mode(sa->encr);

	ivlen = ikev2_encr_iv_size(sa->encr);
	icvlen = ikev2_auth_icv_size(sa->encr, sa->auth);
	blocklen = ikev2_encr_block_size(sa->encr);

	iv = (CK_BYTE_PTR)buf + sizeof (ike_payload_t);
	data = iv + ivlen;

	/* Sanity check */
	VERIFY3P(data, >=, (CK_BYTE_PTR)pkt->pkt_ptr);
	datalen = (CK_ULONG)((CK_BYTE_PTR)pkt->pkt_ptr - data);

	/*
	 * Per RFC7296 3.14, the sender can choose any value for the padding.
	 * We elect to use PKCS#7 style padding (repeat the pad value as the
	 * padding).  This is well studied and appears to work.  Unfortunately,
	 * we cannot validate the padding in the general case.  However,
	 * since we know when we're communicating to other instances of
	 * ourselves via the vendor ID payload, it is permissible to have
	 * custom behavior in such instances, as long as we are backwards
	 * compatible.  As such we DO validate the padding when communicating
	 * to other instances of ourselves. Based on attacks to
	 * protocols (e.g. TLS) where validation of the padding wasn't done,
	 * we think this is prudent to do.
	 */
	if ((datalen + 1) % blocklen != 0)
		padlen = blocklen - ((datalen + 1) % blocklen);

	if (pkt_write_left(pkt) < padlen + 1 + icvlen) {
		bunyan_info(sa->i2sa_log, "not enough space for packet",
		    BUNYAN_T_END);
		return (B_FALSE);
	}

	/*
	 * Once we've written the padding out, we need to write out how much
	 * padding was added.  Since the amount of padding and the value of
	 * the padding are the same, we can just use <= in the loop test to
	 * cause one extra iteration of the loop to accomplish that.
	 */
	for (size_t i = 0; i <= padlen; i++) {
		*pkt->pkt_ptr = padlen;
		pkt->pkt_ptr++;
	}

	datalen += padlen;
	icv = data + datalen;
	*icv = padlen;
	icv++;

	/*
	 * XXX: So far, every encryption mode supported requires a unique IV
	 * per packet.  For CBC modes, the IV also needs to be unpredictable.
	 * Other modes do not appear to have an unpredictability requirement.
	 *
	 * With the possible exception of msgid 0 during an IKE_SA_INIT
	 * exchange (where nothing is encrypted, so is not relevant to IV
	 * creation), the IKEV2 packet message id value is only ever used to
	 * encrypt a single packet.  New packets get a new unique message id
	 * that is never reused within an IKE SA (and thus a given encryption
	 * key for that IKE SA) -- usually by incrementing the previous used
	 * value.  As such, using the message id should satisify the unique
	 * requirement.
	 *
	 * When using CBC modes, to satisify the additional unpredictability
	 * requirement, we use the suggestion in NIST 800-38A, Appendix C.
	 * That is, we take the unique message id, and then encrypt it using
	 * the same key to generate the IV.
	 */
	VERIFY3S(ivlen, >=, sizeof (uint32_t));
	if (mode == MODE_CBC) {
		if (!cbc_iv(pkt, iv))
			return (B_FALSE);
	} else {
		(void) memcpy(iv, &pkt->pkt_header.msgid, sizeof (uint32_t));
	}

	pkt->pkt_ptr = icv + icvlen;

	/* Update SK payload length field to reflect padding + ICV */
	ike_payload_t pay = { 0 };
	(void) memcpy(&pay, buf, sizeof (pay));
	pay.pay_length = htons((uint16_t)(pkt->pkt_ptr - buf));
	(void) memcpy(buf, &pay, sizeof (pay));

	if (!crypt_common(pkt, B_TRUE, iv, ivlen, data, datalen, icv, icvlen))
		return (B_FALSE);

	if (mode == MODE_CCM || mode == MODE_GCM)
		return (B_TRUE);

	if (!auth_common(pkt, B_TRUE, icv, icvlen))
		return (B_FALSE);

	return (B_TRUE);
}

boolean_t
ikev2_pkt_decrypt(pkt_t *pkt)
{
	ikev2_sa_t *sa = pkt->pkt_sa;
	CK_BYTE_PTR iv, data, icv;
	CK_ULONG ivlen, datalen, icvlen;
	uint8_t padlen = 0;
	encr_modes_t mode = ikev2_encr_mode(sa->encr);

	data = NULL;
	datalen = 0;
	for (size_t i = 0; i < pkt->pkt_payload_count; i++) {
		pkt_payload_t *pay = pkt_payload(pkt, i);

		if (pay->pp_type != IKEV2_PAYLOAD_SK)
			continue;

		data = pay->pp_ptr;
		datalen = pay->pp_len;
		break;
	}
	ASSERT3P(data, !=, NULL);

	ivlen = ikev2_encr_iv_size(sa->encr);
	icvlen = ikev2_auth_icv_size(sa->encr, sa->auth);
	if (icvlen + icvlen + 1 >= datalen) {
		bunyan_info(sa->i2sa_log, "SK payload is too small",
		    BUNYAN_T_UINT32, "len", (uint32_t)datalen,
		    BUNYAN_T_UINT32, "ivlen", (uint32_t)ivlen,
		    BUNYAN_T_UINT32, "icvlen", (uint32_t)icvlen,
		    BUNYAN_T_END);
		return (B_FALSE);
	}

	iv = data;
	data += ivlen;
	datalen -= ivlen;
	datalen -= icvlen;
	icv = data + datalen;

	if (mode != MODE_CCM && mode != MODE_GCM &&
	    sa->encr != IKEV2_XF_AUTH_NONE) {
		if (!auth_common(pkt, B_FALSE, icv, icvlen))
			return (B_FALSE);
	}

	if (!crypt_common(pkt, B_FALSE, iv, ivlen, data, datalen, icv, icvlen))
		return (B_FALSE);

	padlen = *(icv - 1);
	datalen -= padlen + 1;

	/*
	 * As described in enrypt_payloads(), when communicating with other
	 * illumos instances, we opt to validate the contents of the padding.
	 * Since RFC7296 allows the sender to choose any arbitrary value
	 * for the padding, we cannot do this in the general case.
	 */
	if (pkt->pkt_sa->vendor == VENDOR_ILLUMOS_1) {
		CK_BYTE_PTR padp = data + datalen;
		for (size_t i = 0; i < padlen; i++) {
			if (*padp == padlen)
				continue;

			bunyan_warn(sa->i2sa_log,
			    "Padding validation failed",
			    BUNYAN_T_UINT32, "padlen", (uint32_t)padlen,
			    BUNYAN_T_UINT32, "offset", (uint32_t)i,
			    BUNYAN_T_END);
			return (B_FALSE);
		}
	}

	ike_payload_t *payp, pay = { 0 };
	size_t paycount = 0, ncount = 0;
	size_t paystart, nstart;

	payp = (ike_payload_t *)iv;
	payp--;
	(void) memcpy(&pay, payp, sizeof (ike_payload_t));

	if (!pkt_count_payloads(data, datalen, pay.pay_next, &paycount,
	    &ncount, sa->i2sa_log)) {
		return (B_FALSE);
	}

	paystart = pkt->pkt_payload_count;
	nstart = pkt->pkt_notify_count;
	if (!pkt_size_index(pkt, pkt->pkt_payload_count + paycount,
	    pkt->pkt_notify_count + ncount))
		return (B_FALSE);

	if (!pkt_index_payloads(pkt, data, datalen, pay.pay_next, paystart,
	    sa->i2sa_log))
		return (B_FALSE);

	ncount = nstart;
	for (size_t i = 0; i < pkt->pkt_payload_count; i++) {
		pkt_payload_t *pp = pkt_payload(pkt, i);

		if (pp->pp_type != IKEV2_PAYLOAD_NOTIFY)
			continue;

		pkt_notify_t *np = NULL;
		ikev2_notify_t n = { 0 };

		np = pkt_notify(pkt, ncount++);
		ASSERT3U(pp->pp_len, >=, sizeof (n));
		(void) memcpy(&n, pp->pp_ptr, sizeof (n));
		np->pn_ptr = pp->pp_ptr;
		np->pn_len = pp->pp_len;
		np->pn_type = ntohs(n.n_type);
	}

	return (B_TRUE);
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

		(void) strlcat(s, paystr, len);
		if (pay->pp_type == IKEV2_PAYLOAD_NOTIFY) {
			pkt_notify_t *n = pkt_notify(pkt, j++);
			const char *nstr =
			    ikev2_notify_str((ikev2_notify_type_t)n->pn_type);

			(void) strlcat(s, "(", len);
			(void) strlcat(s, nstr, len);
			(void) strlcat(s, ")", len);
		}
		(void) strlcat(s, ", ", len);
	}

	return (s);
}

void
ikev2_pkt_log(pkt_t *restrict pkt, bunyan_logger_t *restrict log,
    const char *msg, bunyan_level_t level)
{
	char *descstr = ikev2_pkt_desc(pkt);
	VERIFY3P(descstr, !=, NULL);
	getlog(level)(log, msg,
	    BUNYAN_T_UINT64, "initiator_spi", pkt->pkt_header.initiator_spi,
	    BUNYAN_T_UINT64, "responder_spi", pkt->pkt_header.responder_spi,
	    BUNYAN_T_STRING, "exch_type",
	    ikev2_exch_str(pkt->pkt_header.exch_type),
	    BUNYAN_T_UINT32, "msgid", pkt->pkt_header.msgid,
	    BUNYAN_T_STRING, "payloads", descstr,
	    BUNYAN_T_END);
	free(descstr);
}
