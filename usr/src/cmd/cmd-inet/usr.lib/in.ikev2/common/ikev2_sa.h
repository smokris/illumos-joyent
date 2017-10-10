/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */

/*
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright 2014 Jason King.
 * Copyright 2017 Joyent, Inc.
 */

#ifndef _IKEV2_SA_H
#define	_IKEV2_SA_H

#include <atomic.h>
#include <libperiodic.h>
#include <security/cryptoki.h>
#include <sys/list.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <stddef.h>
#include <synch.h>
#include <thread.h>
#include "defs.h"
#include "ikev2.h"

#ifdef  __cplusplus
extern "C" {
#endif

struct ikev2_sa_s;
struct ikev2_child_sa;
struct i2sa_bucket;
struct pkt_s;

#ifndef IKEV2_SA_T
#define	IKEV2_SA_T
typedef struct ikev2_sa_s ikev2_sa_t;
typedef struct ikev2_child_sa ikev2_child_sa_t;
typedef struct i2sa_bucket i2sa_bucket_t;
#endif /* IKEV2_SA_T */

struct config_rule_s;

typedef enum i2sa_hash {
	I2SA_LSPI	= 0,
	I2SA_RHASH	= 1,
} i2sa_hash_t;
#define	I2SA_NUM_HASH	2	/* The number of IKEv2 SA hashes we have */

#define	I2SA_SALT_LEN		32	/* Max size of salt, may be smaller */

typedef enum i2sa_msg_type {
	I2SA_MSG_NONE = 0,
	I2SA_MSG_PKT,
	I2SA_MSG_PFKEY,
} i2sa_msg_type_t;

typedef struct i2sa_msg {
	i2sa_msg_type_t	i2m_type;
	void		*i2m_data;
} i2sa_msg_t;
#define	I2SA_QUEUE_DEPTH	8	/* How many messages we'll queue */

/* Timer events */
typedef enum i2sa_evt {
	I2SA_EVT_NONE		= 0x00,
	I2SA_EVT_PKT_XMIT	= 0x01,
	I2SA_EVT_P1_EXPIRE	= 0x02,
	I2SA_EVT_SOFT_EXPIRE	= 0x04,
	I2SA_EVT_HARD_EXPIRE	= 0x08,
} i2sa_evt_t;

/*
 * The IKEv2 SA.
 *
 * This is the central data structure to the IKEv2 daemon.  It is a
 * reference-counted node, where the lookup key is either the local
 * SPI/cookie, or a hash based on the remote address and remote SPI.  (See
 * ikev2_pkt.h for the _SPI() macros.)  It should be allocated with a umem
 * cache.
 *
 * Because of the distinct sets of lookup keys, it requires two linkages.
 */
struct ikev2_sa_s {
			/*
			 * Logger for this IKEv2 SA.  Set at creation time.
			 * Nothing should add or remove keys to this.  Can
			 * be used by any refheld pointer to the SA without
			 * acquiring i2sa_lock (since bunyan does it's own
			 * locking).
			 */
	bunyan_logger_t	*i2sa_log;

			/* Protects i2sa_queue_* and i2sa_events fields */
	mutex_t		i2sa_queue_lock;
	i2sa_msg_t	i2sa_queue[I2SA_QUEUE_DEPTH];
	size_t		i2sa_queue_start;
	size_t		i2sa_queue_end;
	i2sa_evt_t	i2sa_events;

			/*
			 * i2sa_lock protects everything else, acquire after
			 * i2sa_queue_lock
			 */
	mutex_t		i2sa_lock;
	thread_t	i2sa_tid;	/* active tid */
	list_node_t	i2sa_lspi_node;
	list_node_t	i2sa_rspi_node;

			/* Link to the bucket we are in for each hash */
	i2sa_bucket_t	*bucket[I2SA_NUM_HASH];

	struct config_rule_s	*i2sa_rule;

	uint64_t		i_spi;	  /* Initiator SPI. */
	uint64_t		r_spi;	  /* Responder SPI. */
	uint32_t		flags;
	volatile uint32_t	refcnt;

	struct sockaddr_storage laddr;  /* Local address & port. */
	struct sockaddr_storage raddr;  /* Remote address & port. */

			/*
			 * What IKEv2 daemon are we talking to.
			 * Currently it is just used to determine if
			 * we can validate padding in SK payloads.
			 * If there are any additional custom behaviors
			 * we want to support in the future, this
			 * will probably need to evolve into
			 * feature flags or such.
			 */
	vendor_t	vendor;

	ikev2_xf_encr_t	encr;		/* Encryption algorithm */
	size_t		encr_key_len;	/* Key length (bytes) for encr */
	ikev2_xf_auth_t	auth;		/* Authentication algorithm */
	ikev2_prf_t	prf;		/* PRF algorithm */
	ikev2_dh_t	dhgrp;		/* Diffie-Hellman group. */

	/* Current number of outstanding messages prior to outmsgid. */
	int		msgwin;
	uint32_t	outmsgid;	/* Next msgid for outbound packets. */
	uint32_t	inmsgid;	/* Next expected inbound msgid. */

	periodic_id_t	i2sa_xmit_timer;
	struct pkt_s	*init_i;	/* IKE_SA_INIT packet. */
	struct pkt_s	*init_r;
	struct pkt_s	*last_resp_sent;
	struct pkt_s	*last_sent;
	struct pkt_s	*last_recvd;

	time_t		birth;		/* When was AUTH completed */
	hrtime_t	softexpire;
	periodic_id_t	i2sa_softlife_timer;
	hrtime_t	hardexpire;
	periodic_id_t	i2sa_hardlife_timer;

	list_t		i2sa_pending;
	list_t		i2sa_child_sas;

	CK_OBJECT_HANDLE dh_pubkey;
	CK_OBJECT_HANDLE dh_privkey;
	CK_OBJECT_HANDLE dh_key;
	CK_OBJECT_HANDLE sk_d;
	CK_OBJECT_HANDLE sk_ai;
	CK_OBJECT_HANDLE sk_ar;
	CK_OBJECT_HANDLE sk_ei;
	CK_OBJECT_HANDLE sk_er;
	CK_OBJECT_HANDLE sk_pi;
	CK_OBJECT_HANDLE sk_pr;

	/* Salt size may be smaller, but no larger than I2SA_SALT_LEN */
	uint8_t		salt_i[I2SA_SALT_LEN];
	uint8_t		salt_r[I2SA_SALT_LEN];
	size_t		saltlen;

	periodic_id_t		i2sa_p1_timer;
};

struct ikev2_child_sa {
	list_node_t		i2c_node;
	hrtime_t		i2c_birth;
	ikev2_spi_proto_t	i2c_satype;
	uint32_t		i2c_spi;

	/*A subset of the child SAs state duplicated for observability */
	ikev2_xf_encr_t		i2c_encr;
	size_t			i2c_encr_key_len;
	ikev2_xf_auth_t		i2c_auth;
	ikev2_dh_t		i2c_dh;

	/* XXX: More to come.  Traffic selectors perhaps? */
};

/* SA flags */
#define	I2SA_INITIATOR		0x1	/* Am I the initiator of this IKE SA? */
#define	I2SA_NAT_LOCAL		0x2	/* I am behind a NAT. */
#define	I2SA_NAT_REMOTE		0x4	/* My peer is behind a NAT. */
#define	I2SA_CONDEMNED		0x8	/* SA is unlinked from a tree. */
#define	I2SA_AUTHENTICATED	0x10	/* SA has been authenticated */

#define	I2SA_LOCAL_SPI(i2sa) \
	(((i2sa)->flags & I2SA_INITIATOR) ? (i2sa)->i_spi : \
	    (i2sa)->r_spi)

#define	I2SA_REMOTE_SPI(i2sa) \
	(((i2sa)->flags & I2SA_INITIATOR) ? (i2sa)->r_spi : \
	    (i2sa)->i_spi)

#define	I2SA_REMOTE_INIT(i2sa) \
	(((i2sa)->flags & I2SA_INITIATOR) ? (i2sa)->init_r : \
	    (i2sa)->init_i)

#define	I2SA_IS_NAT(i2sa) \
	(!!((i2sa)->flags & (I2SA_NAT_LOCAL|I2SA_NAT_REMOTE)))

#define	I2SA_REFHOLD(i2sa) \
	atomic_inc_32(&(i2sa)->refcnt)

/* Stupid C tricks stolen from <assert.h>. */
#define	I2SA_REFRELE(i2sa) \
	(void) ((atomic_dec_32_nv(&(i2sa)->refcnt) != 0) || \
	    (ikev2_sa_free(i2sa), 0))

#define	I2SA_QUEUE_EMPTY(i2sa) \
	((i2sa)->i2sa_queue_start == (i2sa)->i2sa_queue_end)
#define	I2SA_QUEUE_FULL(i2sa) \
	((((i2sa)->i2sa_queue_end + 1) % I2SA_QUEUE_DEPTH) == \
	(i2sa)->i2sa_queue_start)

extern size_t ikev2_sa_buckets;		/* Number of HASH buckets */

ikev2_sa_t *ikev2_sa_get(uint64_t, uint64_t,
    const struct sockaddr_storage *restrict,
    const struct sockaddr_storage *restrict,
    const struct pkt_s *restrict);
ikev2_sa_t *ikev2_sa_alloc(boolean_t, struct pkt_s *restrict,
    const struct sockaddr_storage *restrict,
    const struct sockaddr_storage *restrict);

void	ikev2_sa_set_remote_spi(ikev2_sa_t *, uint64_t);
void	ikev2_sa_free(ikev2_sa_t *);
void	ikev2_sa_condemn(ikev2_sa_t *);

void	ikev2_sa_flush(void);
void	ikev2_sa_set_hashsize(uint_t);

boolean_t ikev2_sa_queuemsg(ikev2_sa_t *, i2sa_msg_type_t, void *);
const char *i2sa_msgtype_str(i2sa_msg_type_t);

#ifdef  __cplusplus
}
#endif

#endif  /* _IKEV2_SA_H */
