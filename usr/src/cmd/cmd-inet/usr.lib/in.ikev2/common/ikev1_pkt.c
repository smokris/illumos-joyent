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
 * Copyright 2015 Jason King.  All rights reserved.
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
#include "pkt_impl.h"
#include "pkcs11.h"

static void
ikev1_add_payload(pkt_t *pkt, ikev1_pay_t type)
{
	ASSERT(IKEV1_VALID_PAYLOAD(type));
	ASSERT(IKE_GET_MAJORV(pkt->header.version) == IKEV1_VERSION);
	pkt_add_payload(pkt, type, 0);
}


void
ikev1_add_sa(pkt_t *pkt, uint32_t doi, uint32_t sit)
{
	ikev1_add_payload(pkt, IKEV1_PAYLOAD_SA);
	buf_put32(&pkt->buf, doi);
	buf_put32(&pkt->buf, sit);
}

void
ikev1_add_prop(pkt_t *pkt, uint8_t propnum, ikev1_spi_proto_t spitype,
    uint64_t spi)
{
	size_t spilen;

	switch (spitype) {
	case IKEV1_SPI_PROTO_ISAKMP:
		spilen = sizeof (uint64_t);
		break;
	case IKEV1_SPI_PROTO_IPSEC_AH:
	case IKEV1_SPI_PROTO_IPSEC_ESP:
	case IKEV1_SPI_PROTO_IPCOMP:
		spilen = sizeof (uint32_t);
		break;
	default:
		INVALID(spitype);
	}

	pkt_add_prop(pkt, propnum, spitype, spi);
}


/* TODO */
