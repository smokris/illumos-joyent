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
 * Copyright 2018 Joyent, Inc.
 */

#ifndef _IKEV2_SA_H
#define	_IKEV2_SA_H

#include <atomic.h>
#include <libperiodic.h>
#include <security/cryptoki.h>
#include <sys/list.h>
#include <sys/refhash.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <stddef.h>
#include <synch.h>
#include <thread.h>
#include "ikev2.h"
#include "ts.h"

#ifdef  __cplusplus
extern "C" {
#endif

struct ikev2_sa_s;
struct ikev2_child_sa;
struct ikev2_sa_args_s;
struct pkt_s;
struct config_rule;
struct config_id;

typedef struct ikev2_sa_s ikev2_sa_t;
typedef struct ikev2_child_sa_s ikev2_child_sa_t;

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

/* Outbound requests */
typedef struct i2sa_req {
	struct pkt_s	*i2r_pkt;
	void		*i2r_cb;	/* Handler for reply */
	void		*i2r_arg;	/* Cookie for handler */
	periodic_id_t	i2r_timer;	/* Retransmit timer */
	uint32_t	i2r_msgid;	/* Request msgid in local byte order */
	boolean_t	i2r_fired;	/* B_TRUE if i2r_timer has fired */
} i2sa_req_t;
#define	I2REQ_ACTIVE(i2r) ((i2r)->i2r_pkt != NULL)

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
 * Because of the distinct sets of lookup keys (local SPI, remote SPI,
 * address), it requires three linkages.
 */
struct ikev2_sa_s {
	/*
	 * i2sa_queue_lock protects i2sa_queue_*, i2sa_events, and the
	 * periodic timers.  Acquire before acquiring i2sa_lock.
	 */
	mutex_t		i2sa_queue_lock;
	i2sa_msg_t	i2sa_queue[I2SA_QUEUE_DEPTH];
	size_t		i2sa_queue_start;
	size_t		i2sa_queue_end;
	i2sa_evt_t	i2sa_events;
	periodic_id_t	i2sa_p1_timer;
	periodic_id_t	i2sa_softlife_timer;
	periodic_id_t	i2sa_hardlife_timer;

			/*
			 * i2sa_lock protects everything else, acquire after
			 * i2sa_queue_lock
			 */
	mutex_t		i2sa_lock;
	thread_t	i2sa_tid;	/* active tid */

	refhash_link_t	i2sa_lspi_link;
	refhash_link_t	i2sa_rspi_link;
	refhash_link_t	i2sa_addr_link;

	struct config_rule	*i2sa_rule;

	uint64_t		i_spi;	  /* Initiator SPI. */
	uint64_t		r_spi;	  /* Responder SPI. */
	uint32_t		flags;
	volatile uint32_t	refcnt;

	struct sockaddr_storage laddr;  /* Local address & port. */
	struct sockaddr_storage raddr;  /* Remote address & port. */
	struct sockaddr_storage lnatt;	/* Local NAT-Ted address */
	struct sockaddr_storage rnatt;	/* Remote NAT-Ted address */

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

	struct config_id *local_id;
	struct config_id *remote_id;

	ikev2_auth_type_t authmethod;	/* How the IKEV2 SA is authenticated */
	ikev2_xf_encr_t	encr;		/* Encryption algorithm */
	size_t		encr_keylen;	/* Key length (bits) for encr */
	ikev2_xf_auth_t	auth;		/* Authentication algorithm */
	ikev2_prf_t	prf;		/* PRF algorithm */
	ikev2_dh_t	dhgrp;		/* Diffie-Hellman group. */

	/* Current number of outstanding messages prior to outmsgid. */
	int		msgwin;
	uint32_t	outmsgid;	/* Next msgid for outbound packets. */
	uint32_t	inmsgid;	/* Next expected inbound msgid. */

	struct pkt_s	*last_resp_sent;
	struct pkt_s	*last_recvd;
	i2sa_req_t	last_req;

	time_t		birth;		/* When was AUTH completed */
	hrtime_t	softexpire;
	hrtime_t	hardexpire;

	refhash_t	*i2sa_child_sas;

	CK_OBJECT_HANDLE sk_d;
	CK_OBJECT_HANDLE sk_ai;
	CK_OBJECT_HANDLE sk_ar;
	CK_OBJECT_HANDLE sk_ei;
	CK_OBJECT_HANDLE sk_er;
	CK_OBJECT_HANDLE sk_pi;
	CK_OBJECT_HANDLE sk_pr;

	CK_OBJECT_HANDLE psk;

	/* Salt size may be smaller, but no larger than I2SA_SALT_LEN */
	uint8_t		salt_i[I2SA_SALT_LEN];
	uint8_t		salt_r[I2SA_SALT_LEN];
	size_t		saltlen;

	struct ikev2_sa_args_s	*sa_init_args;
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

typedef enum ikev2_child_sa_flags {
	I2CF_INITIATOR	= 0x01,
	I2CF_INBOUND	= 0x02,
	I2CF_TRANSPORT	= 0x04,
	I2CF_MORIBUND	= 0x08,		/* In the process of being deleted */
	I2CF_DEAD	= 0x10,		/* Deleted from the kernel */
} ikev2_child_sa_flags_t;

struct ikev2_child_sa_s {
	refhash_link_t		i2c_link;
	ikev2_child_sa_t	*i2c_pair;
	hrtime_t		i2c_birth;

	/* A subset of the child SAs state duplicated for observability */
	ikev2_spi_proto_t	i2c_satype;
	uint32_t		i2c_spi;
	uint32_t		i2c_flags;

	ikev2_xf_encr_t		i2c_encr;
	uint16_t		i2c_encr_keylen; /* in bits */
	uint16_t		i2c_encr_saltlen; /* in bits */
	ikev2_xf_auth_t		i2c_auth;
	ikev2_dh_t		i2c_dh;

	ts_t			i2c_ts_i;
	ts_t			i2c_ts_r;
};

#define	I2C_INBOUND(i2c)	((i2c)->i2c_flags & I2CF_INBOUND)
#define	I2C_INITIATOR(i2c)	((i2c)->i2c_flags & I2CF_INITIATOR)
#define	I2C_TRANSPORT(i2c)	((i2c)->i2c_flags & I2CF_TRANSPORT)
#define	I2C_MORIBUND(i2c)	((i2c)->i2c_flags & I2CF_MORIBUND)
#define	I2C_DEAD(i2c)		((i2c)->i2c_flags & I2CF_DEAD)
#define	I2C_SRC(i2c)		((I2C_INBOUND(i2c) && !I2C_INITIATOR(i2c)) || \
	(!I2C_INBOUND(i2c) && I2C_INITIATOR(i2c)))

#define	I2C_TS_SRC(i2c) I2C_SRC(i2c) ? &(csa)->i2c_ts_i : &(csa)->i2c_ts_r
#define	I2C_TS_DST(i2c) I2C_SRC(i2c) ? &(csa)->i2c_ts_r : &(csa)->i2c_ts_i
#define	I2C_SRC_ID(i2sa, i2c) \
	I2C_INBOUND(i2c) ? (i2sa)->remote_id : (i2sa)->local_id
#define	I2C_DST_ID(i2sa, i2c) \
	I2C_INBOUND(i2c) ? (i2sa)->local_id : (i2sa)->remote_id

ikev2_sa_t *ikev2_sa_getbylspi(uint64_t, boolean_t);
ikev2_sa_t *ikev2_sa_getbyrspi(uint64_t,
    const struct sockaddr *restrict,
    const struct sockaddr *restrict,
    struct pkt_s *restrict);
ikev2_sa_t *ikev2_sa_getbyaddr(const struct sockaddr *restrict,
    const struct sockaddr *restrict);

ikev2_sa_t *ikev2_sa_alloc(struct pkt_s *restrict,
    const struct sockaddr *restrict,
    const struct sockaddr *restrict);

void	ikev2_sa_set_remote_spi(ikev2_sa_t *, uint64_t);
void	ikev2_sa_free(ikev2_sa_t *);
void	ikev2_sa_condemn(ikev2_sa_t *);

void	ikev2_sa_flush(void);

boolean_t ikev2_sa_has_requests(const ikev2_sa_t *restrict);
struct pkt_s *ikev2_sa_get_response(ikev2_sa_t *restrict,
    const struct pkt_s *restrict);

void ikev2_sa_post_event(ikev2_sa_t *, i2sa_evt_t);
boolean_t ikev2_sa_arm_timer(ikev2_sa_t *, hrtime_t, i2sa_evt_t, ...);
void ikev2_sa_disarm_timer(ikev2_sa_t *, i2sa_evt_t, ...);
void ikev2_sa_queuemsg(ikev2_sa_t *, i2sa_msg_type_t, void *);
const char *i2sa_msgtype_str(i2sa_msg_type_t);

ikev2_child_sa_t *ikev2_child_sa_alloc(boolean_t);
void ikev2_child_sa_free(ikev2_sa_t *restrict, ikev2_child_sa_t *restrict);
ikev2_child_sa_t *ikev2_sa_get_child(ikev2_sa_t *, uint32_t, boolean_t);
void ikev2_sa_add_child(ikev2_sa_t *restrict, ikev2_child_sa_t *restrict);
void ikev2_sa_delete_children(ikev2_sa_t *);
void ikev2_sa_delete_child(ikev2_sa_t *restrict, ikev2_child_sa_t *);

void ikev2_sa_clear_req(ikev2_sa_t *restrict, i2sa_req_t *restrict);
void ikev2_sa_init(void);
void ikev2_sa_fini(void);

#ifdef  __cplusplus
}
#endif

#endif /* _IKEV2_SA_H */
