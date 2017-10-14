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
 * Copyright 2017 Jason King.
 * Copyright (c) 2017, Joyent, Inc.
 */

/*
 * Manipulation and storage of IKEv2 Security Associations (SAs).
 */
#include <umem.h>
#include <errno.h>
#include <ipsec_util.h>
#include <libperiodic.h>
#include <limits.h>
#include <locale.h>
#include <note.h>
#include <stddef.h>
#include <strings.h>
#include <sys/debug.h>
#include <sys/list.h>
#include <sys/random.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <umem.h>
#include "config.h"
#include "defs.h"
#include "ikev2_cookie.h"
#include "ikev2_pkt.h"
#include "ikev2_proto.h"
#include "ikev2_sa.h"
#include "ilist.h"
#include "pkcs11.h"
#include "pkt.h"
#include "worker.h"

struct i2sa_bucket {
	mutex_t		lock;	/* bucket lock */
	ilist_t		chain;	/* hash chain of ikev2_sa_t's */
};

typedef struct i2sa_cmp_s {
	const struct sockaddr_storage	*ic_laddr;
	const struct sockaddr_storage	*ic_raddr;
	const pkt_t			*ic_init_pkt;
	uint64_t			ic_l_spi;
	uint64_t			ic_r_spi;
} i2sa_cmp_t;

size_t ikev2_sa_buckets = 16;

static volatile uint_t	half_open;	/* # of larval/half open IKEv2 SAs */
static uint_t		num_buckets;	/* Use same value for all hashes */
static uint32_t		remote_noise;	/* random noise for rhash */
static i2sa_bucket_t	*hash[I2SA_NUM_HASH];
static umem_cache_t	*i2sa_cache;
static umem_cache_t	*i2c_cache;

#define	I2SA_KEY_I2SA		"i2sa"
#define	I2SA_KEY_LADDR		"local_addr"
#define	I2SA_KEY_LPORT		"local_port"
#define	I2SA_KEY_RADDR		"remote_addr"
#define	I2SA_KEY_RPORT		"remote_port"
#define	I2SA_KEY_LSPI		"local_spi"
#define	I2SA_KEY_RSPI		"remote_spi"
#define	I2SA_KEY_INITIATOR	"sa_initiator"

#define	IKEV2_SA_HASH_SPI(spi) \
    P2PHASE_TYPED((spi), num_buckets, uint64_t)

#define	IKEV2_SA_RHASH(ss, spi) \
    P2PHASE_TYPED(i2sa_rhash((ss), (spi)), num_buckets, uint64_t)

static uint32_t	i2sa_rhash(const struct sockaddr_storage *, uint64_t);
static int i2sa_compare(const ikev2_sa_t *, const i2sa_cmp_t *);

static ikev2_sa_t *i2sa_verify(ikev2_sa_t *restrict, uint64_t,
    const struct sockaddr_storage *restrict,
    const struct sockaddr_storage *restrict);
static boolean_t i2sa_add_to_hash(i2sa_hash_t, ikev2_sa_t *);

static void i2sa_unlink(ikev2_sa_t *);
static void i2sa_p1_expire(void *);

static boolean_t i2sa_key_add_addr(ikev2_sa_t *, const char *, const char *,
    const struct sockaddr_storage *);
static int i2sa_ctor(void *, void *, int);
static void i2sa_dtor(void *, void *);

static void inc_half_open(void);
static void dec_half_open(void);

/*
 * Attempt to find an IKEv2 SA that matches the given criteria, or return
 * NULL if not found.
 */
ikev2_sa_t *
ikev2_sa_get(uint64_t l_spi, uint64_t r_spi,
    const struct sockaddr_storage *restrict l_addr,
    const struct sockaddr_storage *restrict r_addr,
    const pkt_t *restrict init_pkt)
{
	i2sa_bucket_t *bucket = NULL;
	ikev2_sa_t *sa = NULL, *node = NULL;
	i2sa_cmp_t cmp = {
		.ic_l_spi = l_spi,
		.ic_r_spi = r_spi,
		.ic_init_pkt = init_pkt,
		.ic_laddr = l_addr,
		.ic_raddr = r_addr
	};

	/*
	 * XXX: We need to support searching based strictly on local and remote
	 * addresses without a remote SPI for matching ACQUIRES to existing IKE
	 * SAs
	 */

	if (l_spi != 0) {
		/*
		 * We assign the local SPIs, so if it is set (!= 0), that
		 * should be sufficient to find the IKE SA.
		 */
		bucket = hash[I2SA_LSPI] + IKEV2_SA_HASH_SPI(l_spi);
	} else {
		/* Otherwise need to look at the other parameters */
		bucket = hash[I2SA_RHASH] + IKEV2_SA_RHASH(r_addr, r_spi);
	}

	mutex_enter(&bucket->lock);
	for (node = ilist_head(&bucket->chain);
	    node != NULL;
	    node = ilist_next(&bucket->chain, node)) {
		int rc = i2sa_compare(node, &cmp);

		if (rc < 0)
			continue;

		if (rc == 0)
			sa = node;
		/*
		 * The list is sorted, so if we reach a node > than what
		 * we're looking for, it's not there.
		 */
		break;
	}

	if (sa != NULL)
		I2SA_REFHOLD(sa);
	mutex_exit(&bucket->lock);

	return (i2sa_verify(sa, r_spi, l_addr, r_addr));
}

/*
 * Allocate a larval IKEv2 SA.
 *
 * Obtains a unique local SPI and assigns it to the SA and adds the SA to
 * the local SPI hash.  If the packet used to trigger the creation of the SA
 * is given, take over management of it.  Also create an SA expiration timer.
 *
 * If we initiated the SA creation, the remote SPI will not be known initially.
 * Once the protocol has proceeded enough to determine the remote SPI,
 * ikev2_sa_set_rspi() should be called.
 *
 * Parameters:
 * 	initiator	Was this SA locally initiated
 * 	init_pkt	The packet that trigged the creation of the SA.
 * 	laddr,
 * 	raddr		The local and remote addresses of this SA.
 *
 * On successful create, the refheld larval IKEv2 SA is returned.  In addition,
 * the IKEv2 SA queue is locked on return.
 *
 * On failure, NULL is returned.  Caller maintains responsibility for
 * init_pkt in this instance.
 *
 * XXX: We could probably refactor this so that the presence of the initiator
 * packet indicates the request was remotely initiated -- when we initiate,
 * we create the IKE SA then the IKE_SA_INIT initiator packet.
 */
ikev2_sa_t *
ikev2_sa_alloc(boolean_t initiator,
    pkt_t *restrict init_pkt,
    const struct sockaddr_storage *restrict laddr,
    const struct sockaddr_storage *restrict raddr)
{
	ikev2_sa_t	*i2sa = NULL;
	config_t	*cfg = NULL;
	hrtime_t	expire = 0;

	(void) bunyan_trace(log, "Attempting to create new larval IKE SA",
	    BUNYAN_T_BOOLEAN, I2SA_KEY_INITIATOR, initiator,
	    ss_bunyan(laddr), I2SA_KEY_LADDR, ss_addr(laddr),
	    ss_bunyan(raddr), I2SA_KEY_RADDR, ss_addr(raddr),
	    BUNYAN_T_END);

	cfg = config_get();
	expire = cfg->cfg_expire_timer;
	CONFIG_REFRELE(cfg);

	if ((i2sa = umem_cache_alloc(i2sa_cache, UMEM_DEFAULT)) == NULL)
		return (NULL);

	/* Keep anyone else out while we initialize */
	mutex_enter(&i2sa->i2sa_queue_lock);
	mutex_enter(&i2sa->i2sa_lock);

	i2sa->i2sa_tid = thr_self();

	ASSERT((init_pkt == NULL) ||
	    (init_pkt->hdr.exch_type == IKEV2_EXCHANGE_IKE_SA_INIT));

	i2sa->flags |= (initiator) ? I2SA_INITIATOR : 0;

	(void) memcpy(&i2sa->laddr, laddr, sizeof (i2sa->laddr));
	(void) memcpy(&i2sa->raddr, raddr, sizeof (i2sa->raddr));

	/*
	 * Generate a random local SPI and try to add it.  Almost always this
	 * will succeed on the first attempt.  However if on the rare occasion
	 * we generate a duplicate (or even far, far rarer chance 0 is
	 * returned), just retry until we pick a value that's not in use.
	 */
	NOTE(CONSTCOND)
	while (1) {
		uint64_t spi = 0;

		arc4random_buf(&spi, sizeof (spi));

		/*
		 * Incredibly unlikely we'll ever randomly generate 0, but
		 * if we do, just try again.
		 */
		if (spi == 0)
			continue;

		if (initiator)
			i2sa->i_spi = spi;
		else
			i2sa->r_spi = spi;

		if (i2sa_add_to_hash(I2SA_LSPI, i2sa)) {
			VERIFY3U(i2sa->refcnt, ==, 1);

			i2sa->init_i = init_pkt;

			/* refhold for caller */
			I2SA_REFHOLD(i2sa);
			break;
		}
	};

	inc_half_open();

	/* 0x + 64bit hex value + NUL */
	char buf[19] = { 0 };

	/*
	 * For protocol processing, the SPIs are treated as opaque values,
	 * however for debugging/diagnostic/admin purposes, we want to output
	 * them in native byte order so the SPI values will match
	 * what other implementations and tools (such as wireshark) display
	 */
	(void) snprintf(buf, sizeof (buf), "0x%016" PRIX64,
	    ntohll(I2SA_LOCAL_SPI(i2sa)));

	if (bunyan_child(log, &i2sa->i2sa_log,
	    BUNYAN_T_POINTER, I2SA_KEY_I2SA, i2sa,
	    BUNYAN_T_STRING, I2SA_KEY_LSPI, buf,
	    ss_bunyan(laddr), I2SA_KEY_LADDR, ss_addr(laddr),
	    BUNYAN_T_UINT32, I2SA_KEY_LPORT, ss_port(laddr),
	    ss_bunyan(raddr), I2SA_KEY_RADDR, ss_addr(raddr),
	    BUNYAN_T_UINT32, I2SA_KEY_RPORT, ss_port(raddr),
	    BUNYAN_T_BOOLEAN, I2SA_KEY_INITIATOR, initiator,
	    BUNYAN_T_END) != 0) {
		bunyan_error(log, "Cannot create IKE SA logger",
		    BUNYAN_T_END);
		goto fail;
	}

	/*
	 * If we're the initiator, we don't know the remote SPI until after
	 * the remote peer responds.  However if we are the responder,
	 * we know what it is and can set it now.
	 */
	if (!initiator) {
		ikev2_sa_set_remote_spi(i2sa,
		    pkt_header(init_pkt)->initiator_spi);
	}

	I2SA_REFHOLD(i2sa);	/* ref for periodic */
	if (periodic_schedule(wk_periodic, expire, PERIODIC_ONESHOT,
	    i2sa_p1_expire, i2sa, &i2sa->i2sa_p1_timer) != 0) {
		(void) bunyan_error(i2sa->i2sa_log,
		    "Cannot create IKEv2 SA P1 expiration timer",
		    BUNYAN_T_STRING, "err", strerror(errno),
		    BUNYAN_T_INT32, "errno", errno,
		    BUNYAN_T_END);
		goto fail;
	}
	i2sa->i2sa_tid = 0;
	mutex_exit(&i2sa->i2sa_lock);

	/*
	 * Leave i2sa_queue_lock held so caller has exclusive access to SA
	 * upon return.
	 */

	(void) bunyan_debug(i2sa->i2sa_log, "New larval IKE SA created",
	    BUNYAN_T_POINTER, "sa", i2sa,
	    BUNYAN_T_END);

	return (i2sa);

fail:
	i2sa_unlink(i2sa);
	i2sa->i2sa_tid = 0;
	mutex_exit(&i2sa->i2sa_lock);
	mutex_exit(&i2sa->i2sa_queue_lock);

	/*
	 * When refcnt goes from 1->0, i2sa will get freed, so do last one
	 * explicitly
	 */
	while (i2sa->refcnt > 1)
		I2SA_REFRELE(i2sa);
	I2SA_REFRELE(i2sa);

	(void) bunyan_debug(log, "Larval IKE SA creation failed", BUNYAN_T_END);
	return (NULL);
}

/*
 * Invoked when an SA has expired.  REF from timer is passed to this
 * function.
 */
static void
i2sa_p1_expire(void *data)
{
	ikev2_sa_t *i2sa = data;
	int rc;

	(void) bunyan_info(i2sa->i2sa_log, "Larval IKE SA timeout",
	    BUNYAN_T_END);

	mutex_enter(&i2sa->i2sa_queue_lock);
	i2sa->i2sa_events |= I2SA_EVT_P1_EXPIRE;
	ikev2_dispatch(i2sa);
	mutex_exit(&i2sa->i2sa_queue_lock);

	I2SA_REFRELE(i2sa);
}

void
ikev2_sa_flush(void)
{
	/* TODO: implement me */
}

void
ikev2_sa_condemn(ikev2_sa_t *i2sa)
{
	parsedmsg_t *pmsg = NULL;

	VERIFY(!MUTEX_HELD(&i2sa->i2sa_queue_lock));
	VERIFY(MUTEX_HELD(&i2sa->i2sa_lock));

	(void) bunyan_info(i2sa->i2sa_log, "Condemning IKE SA", BUNYAN_T_END);
	i2sa->flags |= I2SA_CONDEMNED;

	I2SA_REFHOLD(i2sa);
	i2sa_unlink(i2sa);

	mutex_exit(&i2sa->i2sa_lock);
	mutex_enter(&i2sa->i2sa_queue_lock);
	mutex_enter(&i2sa->i2sa_lock);

	/* If we havent seen these fire yet, cancel them */
	if (i2sa->i2sa_xmit_timer != 0 &&
	    !(i2sa->i2sa_events & I2SA_EVT_PKT_XMIT)) {
		VERIFY0(periodic_cancel(wk_periodic, i2sa->i2sa_xmit_timer));
	}
	if (i2sa->i2sa_p1_timer != 0 &&
	    !(i2sa->i2sa_events & I2SA_EVT_P1_EXPIRE)) {
		VERIFY0(periodic_cancel(wk_periodic, i2sa->i2sa_p1_timer));
	}
	if (i2sa->i2sa_softlife_timer != 0 &&
	    !(i2sa->i2sa_events & I2SA_EVT_SOFT_EXPIRE)) {
		VERIFY0(periodic_cancel(wk_periodic,
		    i2sa->i2sa_softlife_timer));
	}
	if (i2sa->i2sa_hardlife_timer != 0 &&
	    !(i2sa->i2sa_events & I2SA_EVT_HARD_EXPIRE)) {
		(void) periodic_cancel(wk_periodic, i2sa->i2sa_hardlife_timer);
	}

	i2sa->i2sa_p1_timer = i2sa->i2sa_softlife_timer =
	    i2sa->i2sa_xmit_timer = i2sa->i2sa_hardlife_timer = 0;

	/* Drop the queue lock so any pending activity can drain */
	mutex_exit(&i2sa->i2sa_queue_lock);

	/*
	 * Since packets keep a reference to the SA they are associated with,
	 * we must free them here so that their references go away
	 */
	if (i2sa->init_i != i2sa->last_resp_sent &&
	    i2sa->init_i != i2sa->last_sent)
		ikev2_pkt_free(i2sa->init_i);

	if (i2sa->init_r != i2sa->last_resp_sent &&
	    i2sa->init_r != i2sa->last_sent)
		ikev2_pkt_free(i2sa->init_r);

	ikev2_pkt_free(i2sa->last_resp_sent);
	ikev2_pkt_free(i2sa->last_sent);
	ikev2_pkt_free(i2sa->last_recvd);
	i2sa->init_i = NULL;
	i2sa->init_r = NULL;
	i2sa->last_resp_sent = NULL;
	i2sa->last_sent = NULL;
	i2sa->last_recvd = NULL;

	pmsg = list_head(&i2sa->i2sa_pending);
	while (pmsg != NULL) {
		parsedmsg_t *next = list_next(&i2sa->i2sa_pending, pmsg);
		sadb_msg_t *samsg = pmsg->pmsg_samsg;

		/* Fail/cancel any pending acquires from the kernel */
		if (samsg->sadb_msg_pid == 0 &&
		    samsg->sadb_msg_type == SADB_ACQUIRE) {
			/*
			 * The kernel currently only cares that errno != 0,
			 * but this seems like the closest error code to
			 * what's happening, just to be as informative as
			 * possible.
			 */
			pfkey_send_error(samsg, ECANCELED);
		}

		list_remove(&i2sa->i2sa_pending, pmsg);
		parsedmsg_free(pmsg);
		pmsg = next;
	}

	/* XXX: remove child SAs */

	mutex_exit(&i2sa->i2sa_lock);
	mutex_enter(&i2sa->i2sa_queue_lock);
	mutex_enter(&i2sa->i2sa_lock);

	for (size_t i = 0; i < I2SA_QUEUE_DEPTH; i++) {
		switch (i2sa->i2sa_queue[i].i2m_type) {
		case I2SA_MSG_NONE:
			break;
		case I2SA_MSG_PKT:
			ikev2_pkt_free(i2sa->i2sa_queue[i].i2m_data);
			break;
		case I2SA_MSG_PFKEY:
			parsedmsg_free(i2sa->i2sa_queue[i].i2m_data);
			break;
		}
		i2sa->i2sa_queue[i].i2m_type = I2SA_MSG_NONE;
		i2sa->i2sa_queue[i].i2m_data = NULL;
	}

	mutex_exit(&i2sa->i2sa_queue_lock);
	I2SA_REFRELE(i2sa);
	/* XXX: should we do anything else here? */
}

/*
 * Should normally only be called as a result of I2SA_REFRELE()
 */
void
ikev2_sa_free(ikev2_sa_t *i2sa)
{
	if (i2sa == NULL)
		return;

	VERIFY3U(i2sa->refcnt, ==, 0);
	VERIFY3P(i2sa->init_i, ==, NULL);
	VERIFY3P(i2sa->init_r, ==, NULL);
	VERIFY3P(i2sa->last_resp_sent, ==, NULL);
	VERIFY3P(i2sa->last_sent, ==, NULL);
	VERIFY3P(i2sa->last_recvd, ==, NULL);

	if (i2sa->i2sa_rule != NULL)
		CONFIG_REFRELE(i2sa->i2sa_rule->rule_config);

	/* All unauthenticated IKEv2 SAs are considered larval */
	if (!(i2sa->flags & I2SA_AUTHENTICATED))
		dec_half_open();

#define	DESTROY(x, y) pkcs11_destroy_obj(#y, &(x)->y, i2sa->i2sa_log)
	DESTROY(i2sa, dh_pubkey);
	DESTROY(i2sa, dh_privkey);
	DESTROY(i2sa, dh_key);
	DESTROY(i2sa, sk_d);
	DESTROY(i2sa, sk_ai);
	DESTROY(i2sa, sk_ar);
	DESTROY(i2sa, sk_ei);
	DESTROY(i2sa, sk_er);
	DESTROY(i2sa, sk_pi);
	DESTROY(i2sa, sk_pr);
	DESTROY(i2sa, psk);
#undef  DESTROY

	/* TODO: free child SAs */

	bunyan_fini(i2sa->i2sa_log);

	i2sa_dtor(i2sa, NULL);
	(void) i2sa_ctor(i2sa, NULL, 0);
	umem_cache_free(i2sa_cache, i2sa);
}

void
ikev2_sa_set_hashsize(uint_t newamt)
{
	i2sa_bucket_t *old[I2SA_NUM_HASH];
	size_t nold = num_buckets;
	int i, hashtbl;
	boolean_t startup = B_FALSE;

	VERIFY(!IS_WORKER);

	for (i = 0; i < I2SA_NUM_HASH; i++)
		old[i] = hash[i];

	if (old[0] != NULL) {
		startup = B_FALSE;
		worker_suspend();
	}

	/* Round up to a power of two if not already */
	if (!ISP2(newamt)) {
		--newamt;
		for (i = 1; i <= 16; i++)
			newamt |= (newamt >> i);
		++newamt;
	}
	VERIFY(ISP2(newamt));

	bunyan_debug(log, "Creating IKE SA hash buckets",
	    BUNYAN_T_UINT32, "numbuckets", (uint32_t)newamt,
	    BUNYAN_T_BOOLEAN, "startup", startup,
	    BUNYAN_T_END);

	for (i = 0; i < I2SA_NUM_HASH; i++)
		hash[i] = NULL;

	/* Allocate new buckets */
	for (i = 0; i < I2SA_NUM_HASH; i++) {
		size_t amt = newamt * sizeof (i2sa_bucket_t);
		VERIFY3U(amt, >, sizeof (i2sa_bucket_t));
		VERIFY3U(amt, >=, newamt);

		hash[i] = umem_zalloc(amt, UMEM_DEFAULT);
		if (hash[i] == NULL)
			goto nomem;

		size_t offset = 0;

		switch (i) {
		case I2SA_LSPI:
			offset = offsetof(ikev2_sa_t, i2sa_lspi_node);
			break;
		case I2SA_RHASH:
			offset = offsetof(ikev2_sa_t, i2sa_rspi_node);
			break;
		}

		for (size_t j = 0; j < newamt; j++) {
			i2sa_bucket_t *b = &hash[i][j];

			ilist_create(&b->chain, sizeof (ikev2_sa_t), offset);
			VERIFY0(mutex_init(&b->lock, LOCK_ERRORCHECK, NULL));
		}
	}

	/* New tables means a new fudge factor.  Pick one randomly. */
	remote_noise = arc4random();

	i = num_buckets;

	/* Set this so the hash functions work on the new buckets */
	num_buckets = newamt;

	if (startup)
		return;

	/*
	 * At this point, we've allocated all the necessary structures, so
	 * we can just move everything over to the new buckets.  Since the
	 * only remaining reference to the old number of buckets here is i,
	 * we work backwards to free each chain, and invert the normal
	 * inner/outer loop order.
	 */
	while (--i >= 0) {
		for (hashtbl = 0; hashtbl < I2SA_NUM_HASH; hashtbl++) {
			ilist_t *oldlist;
			ikev2_sa_t *i2sa;

			oldlist = &old[hashtbl][i].chain;

			while ((i2sa = ilist_remove_head(oldlist)) != NULL) {
				VERIFY(i2sa_add_to_hash(hashtbl, i2sa));
				/* Remove ref from old list */
				I2SA_REFRELE(i2sa);
			}

			VERIFY0(mutex_destroy(&old[hashtbl][i].lock));
			VERIFY(ilist_is_empty(oldlist));
		}
	}

	for (hashtbl = 0; hashtbl < I2SA_NUM_HASH; hashtbl++)
		umem_free(old[hashtbl], sizeof (i2sa_bucket_t) * nold);

	worker_resume();
	return;

nomem:
	if (startup)
		errx(EXIT_FAILURE, "out of memory");

	/* This will probably fail too, but worth a shot */
	(void) bunyan_error(log, "out of memory", BUNYAN_T_STRING);

	/*
	 * Free what the new stuff we've constructed so far, and put the
	 * old buckets back into place
	 */
	for (hashtbl = 0; hashtbl < I2SA_NUM_HASH; hashtbl++) {
		if (hash[hashtbl] == NULL)
			continue;
		for (i = 0; i < newamt; i++)
			VERIFY(ilist_is_empty(&hash[hashtbl][i].chain));

		umem_free(hash[hashtbl], newamt * sizeof (i2sa_bucket_t));
		hash[hashtbl] = old[hashtbl];
	}

	worker_resume();
}

/*
 * Set the remote SPI of an IKEv2 SA and add to the rhash
 */
void
ikev2_sa_set_remote_spi(ikev2_sa_t *i2sa, uint64_t remote_spi)
{
	VERIFY(IS_WORKER);
	VERIFY(MUTEX_HELD(&i2sa->i2sa_lock));

	/* Never a valid SPI value */
	VERIFY3U(remote_spi, !=, 0);

	/*
	 * A bit confusing at times, but if we are the initiator of the
	 * SA, the responder (ikev2_sa_t->remote_spi) is the remote spi,
	 * otherwise we are the responder, so the remote spi is the
	 * initiator (ikev2_sa_t->i_spi)
	 */
	if (i2sa->flags & I2SA_INITIATOR) {
		/* Should not be set already */
		VERIFY3U(i2sa->r_spi, ==, 0);
		i2sa->r_spi = remote_spi;
	} else {
		/* Should not be set already */
		VERIFY3U(i2sa->i_spi, ==, 0);
		i2sa->i_spi = remote_spi;
	}

	VERIFY(i2sa_add_to_hash(I2SA_RHASH, i2sa));
	char buf[19];	/* 0x + 64bit hex value + NUL */

	(void) snprintf(buf, sizeof (buf), "0x%016" PRIX64,
	    ntohll(I2SA_REMOTE_SPI(i2sa)));
	(void) bunyan_key_add(i2sa->i2sa_log,
	    BUNYAN_T_STRING, I2SA_KEY_RSPI, buf, BUNYAN_T_END);

	(void) bunyan_trace(i2sa->i2sa_log, "Set remote SPI", BUNYAN_T_END);
}

static i2sa_bucket_t *
i2sa_get_bucket(i2sa_hash_t hashtype, ikev2_sa_t *i2sa)
{
	i2sa_bucket_t *bucket = hash[hashtype];
	size_t n = 0;

	switch (hashtype) {
	case I2SA_LSPI:
		n = IKEV2_SA_HASH_SPI(I2SA_LOCAL_SPI(i2sa));
		break;
	case I2SA_RHASH:
		n = IKEV2_SA_RHASH(&i2sa->raddr, I2SA_REMOTE_SPI(i2sa));
		break;
	}
	VERIFY3U(n, <, num_buckets);

	return (bucket + n);
}


/*
 * Add an IKEv2 SA to the given hash.
 *
 * Returns:
 * 	B_TRUE	successfully added, hash holds ref to IKEv2 SA
 * 	B_FALSE	IKEv2 SA already exists in hash, no ref held.
 *
 */
static boolean_t
i2sa_add_to_hash(i2sa_hash_t hashtbl, ikev2_sa_t *i2sa)
{
	i2sa_bucket_t	*bucket;
	ikev2_sa_t	*node = NULL;
	int		rc = 1;

	bucket = i2sa_get_bucket(hashtbl, i2sa);

	mutex_enter(&bucket->lock);

	for (node = ilist_head(&bucket->chain);
	    node != NULL;
	    node = ilist_next(&bucket->chain, node)) {
		i2sa_cmp_t cmp = {
			.ic_laddr = &node->laddr,
			.ic_raddr = &node->raddr,
			.ic_init_pkt = I2SA_REMOTE_INIT(node),
			.ic_l_spi = I2SA_LOCAL_SPI(node),
			.ic_r_spi = I2SA_REMOTE_SPI(node)
		};

		rc = i2sa_compare(i2sa, &cmp);
		if (rc >= 0)
			break;
	}

	if (rc == 0) {
		/*
		 * Found a match, should only happen while choosing
		 * a local SPI value and we happen to pick one already
		 * in use.
		 */

		VERIFY3P(node, !=, i2sa);

		/*
		 * XXX: Should we do anything different for an rhash
		 * match?
		 */
		mutex_exit(&bucket->lock);
		return (B_FALSE);
	}

	I2SA_REFHOLD(i2sa);	/* ref for chain */
	i2sa->bucket[hashtbl] = bucket;
	ilist_insert_before(&bucket->chain, node, i2sa);
	mutex_exit(&bucket->lock);

	return (B_TRUE);
}

static ikev2_sa_t *
i2sa_verify(ikev2_sa_t *restrict i2sa, uint64_t rem_spi,
    const struct sockaddr_storage *laddr,
    const struct sockaddr_storage *raddr)
{
	if (i2sa == NULL)
		return (NULL);

	/*
	 * If we initiate an IKE_SA_INIT request, when we receive a non-error
	 * (cookie, new DH pair, no proposal chosen) response, our IKE SA
	 * will not yet have it's remote SPI set as the response will be
	 * the first time the remote SPI is known to us.  That means, in
	 * that situation, our remote SPI == 0, but we will be called with
	 * rem_spi set to the value chosen by the peer.  As such we don't
	 * want to fail verification when given a remote SPI value and ours
	 * hasn't been set yet.
	 */
	if (I2SA_REMOTE_SPI(i2sa) != 0 && I2SA_REMOTE_SPI(i2sa) != rem_spi) {
		char spistr[19];
		(void) snprintf(spistr, sizeof (spistr), "0x%" PRIX64, rem_spi);
		(void) bunyan_error(i2sa->i2sa_log,
		    "Found an IKEv2 SA, but remote SPI does not match",
		    BUNYAN_T_STRING, "spi", spistr,
		    BUNYAN_T_END);
		goto bad_match;
	}

	if (laddr != NULL && !SA_ADDR_EQ(laddr, &i2sa->laddr)) {
		(void) bunyan_error(i2sa->i2sa_log,
		    "Found an IKEv2 SA, but local address does not match",
		    ss_bunyan(laddr), "addr", ss_addr(laddr),
		    BUNYAN_T_END);
		goto bad_match;
	}

	if (raddr != NULL && !SA_ADDR_EQ(raddr, &i2sa->raddr)) {
		(void) bunyan_error(i2sa->i2sa_log,
		    "Found an IKEv2 SA, but remote address does not match",
		    ss_bunyan(raddr), "addr", ss_addr(raddr),
		    BUNYAN_T_END);
		goto bad_match;
	}

	/*
	 * XXX KEBE ASKS - if remote port changes, do remap?
	 * Probably have caller do this after packet is really legit.
	 */

	/* XXX KEBE SAYS FILL IN OTHER REALITY CHECKS HERE. */

	(void) bunyan_trace(i2sa->i2sa_log, "IKEv2 SA found",
	    BUNYAN_T_STRING, "func", __func__,
	    BUNYAN_T_POINTER, "i2sa", i2sa,
	    BUNYAN_T_END);

	VERIFY(!MUTEX_HELD(&i2sa->i2sa_lock));
	VERIFY(!MUTEX_HELD(&i2sa->i2sa_queue_lock));
	return (i2sa);

bad_match:
	I2SA_REFRELE(i2sa);
	return (NULL);
}

static void
i2sa_hash_remove(size_t hashtbl, ikev2_sa_t *i2sa)
{
	i2sa_bucket_t *bucket;

	VERIFY3U(hashtbl, <, I2SA_NUM_HASH);

	switch (hashtbl) {
	case I2SA_LSPI:
		if (!list_link_active(&i2sa->i2sa_lspi_node))
			return;
		break;
	case I2SA_RHASH:
		if (!list_link_active(&i2sa->i2sa_rspi_node))
			return;
		break;
	}

	bucket = i2sa->bucket[hashtbl];

	mutex_enter(&bucket->lock);
	ilist_remove(&bucket->chain, i2sa);
	i2sa->bucket[hashtbl] = NULL;
	mutex_exit(&bucket->lock);

	I2SA_REFRELE(i2sa);
}

static void
i2sa_unlink(ikev2_sa_t *i2sa)
{
	for (size_t i = 0; i < I2SA_NUM_HASH; i++)
		i2sa_hash_remove(i, i2sa);
}

/*
 * Generate a hash value for a remote SA based off the
 * address and remote SPI.
 */
static uint32_t
i2sa_rhash(const struct sockaddr_storage *ss, uint64_t spi)
{
	uint32_t rc = remote_noise;
	const uint32_t *ptr = (const uint32_t *)&spi;
	sockaddr_u_t ssu;

	rc ^= ptr[0];
	rc ^= ptr[1];

	ssu.sau_ss = (struct sockaddr_storage *)ss;
	if (ss->ss_family == AF_INET6) {
		ptr = (const uint32_t *)&ssu.sau_sin6->sin6_addr;
		rc ^= ptr[0];
		rc ^= ptr[1];
		rc ^= ptr[2];
		rc ^= ptr[3];
	} else {
		ASSERT(ss->ss_family == AF_INET);
		rc ^= ssu.sau_sin->sin_addr.s_addr;
	}

	return (rc);
}

/*
 * Increase the count of larval SAs.  If we reach our threshold for larval SAs,
 * enable the use of cookies.
 */
static void
inc_half_open(void)
{
	if (atomic_inc_uint_nv(&half_open) == ikev2_cookie_threshold)
		ikev2_cookie_enable();
}

/*
 * Decrease the count of larval SAs.  Disable cookies if the count falls
 * below the threshold
 */
static void
dec_half_open(void)
{
	/*
	 * Instead of merely disabling cookies once we're below
	 * ikev2_cookie_threshold half-open IKE SAs, we wait for
	 * IKEV2_COOKIE_OFF_ADD additional half-open IKE SAs to
	 * disappear to add a small amount of hysteresis and prevent
	 * constantly flopping on and off once we're at the threshold.
	 */
	if (atomic_dec_uint_nv(&half_open) ==
	    ikev2_cookie_threshold - IKEV2_COOKIE_OFF_ADJ)
		ikev2_cookie_disable();
}

/*
 * Add a message to the queue of the given IKEv2 SA.  Must be called
 * with sa->i2sa_queue_lock held.  Returns B_TRUE if message was successfully
 * added to the queue, B_FALSE if the queue was full.  If the given SA is
 * not already processing messages on another thread, it will also process
 * anything queued.  Returns with sa->i2sa_queue_lock released.
 */
boolean_t
ikev2_sa_queuemsg(ikev2_sa_t *sa, i2sa_msg_type_t type, void *data)
{
	VERIFY(IS_WORKER);
	VERIFY(MUTEX_HELD(&sa->i2sa_queue_lock));

	if (I2SA_QUEUE_FULL(sa)) {
		mutex_exit(&sa->i2sa_queue_lock);
		return (B_FALSE);
	}

	i2sa_msg_t *msg = &sa->i2sa_queue[sa->i2sa_queue_start];

	msg->i2m_type = type;
	msg->i2m_data = data;
	sa->i2sa_queue_start++;
	sa->i2sa_queue_start %= I2SA_QUEUE_DEPTH;
	ikev2_dispatch(sa);
	mutex_exit(&sa->i2sa_queue_lock);

	return (B_TRUE);
}

static int
i2sa_ctor(void *buf, void *dummy, int flags)
{
	NOTE(ARGUNUSED(dummy, flags))

	ikev2_sa_t *i2sa = buf;

	(void) memset(i2sa, 0, sizeof (*i2sa));
	i2sa->msgwin = 1;

	VERIFY0(mutex_init(&i2sa->i2sa_lock, USYNC_THREAD|LOCK_ERRORCHECK,
	    NULL));
	VERIFY0(mutex_init(&i2sa->i2sa_queue_lock, USYNC_THREAD|LOCK_ERRORCHECK,
	    NULL));

	list_link_init(&i2sa->i2sa_lspi_node);
	list_link_init(&i2sa->i2sa_rspi_node);
	list_create(&i2sa->i2sa_pending, sizeof (parsedmsg_t),
	    offsetof(parsedmsg_t, pmsg_node));
	list_create(&i2sa->i2sa_child_sas, sizeof (ikev2_child_sa_t),
	    offsetof(ikev2_child_sa_t, i2c_node));
	return (0);
}

static void
i2sa_dtor(void *buf, void *dummy)
{
	NOTE(ARGUNUSED(dummy))

	ikev2_sa_t *i2sa = (ikev2_sa_t *)buf;

	VERIFY0(mutex_destroy(&i2sa->i2sa_lock));
	VERIFY0(mutex_destroy(&i2sa->i2sa_queue_lock));
	VERIFY(!list_link_active(&i2sa->i2sa_lspi_node));
	VERIFY(!list_link_active(&i2sa->i2sa_rspi_node));
	VERIFY(list_is_empty(&i2sa->i2sa_pending));
	VERIFY(list_is_empty(&i2sa->i2sa_child_sas));
	list_destroy(&i2sa->i2sa_pending);
	list_destroy(&i2sa->i2sa_child_sas);
}

static int
i2c_ctor(void *buf, void *dummy, int flags)
{
	NOTE(ARGUNUSED(dummy, flags))

	ikev2_child_sa_t *i2c = buf;

	(void) memset(i2c, 0, sizeof (*i2c));
	list_link_init(&i2c->i2c_node);
	return (0);
}

static void
i2c_dtor(void *buf, void *dummy)
{
	NOTE(ARGUNUSED(dummy))

	ikev2_child_sa_t *i2c = buf;

	VERIFY(!list_link_active(&i2c->i2c_node));
}

static int
sockaddr_compare(const struct sockaddr_storage *restrict l,
    const struct sockaddr_storage *restrict r)
{
	sockaddr_u_t lu;
	sockaddr_u_t ru;
	int cmp;

	if (l->ss_family > r->ss_family)
		return (1);
	if (l->ss_family < r->ss_family)
		return (-1);

	lu.sau_ss = (struct sockaddr_storage *)l;
	ru.sau_ss = (struct sockaddr_storage *)r;

	if (l->ss_family == AF_INET) {
		cmp = memcmp(&lu.sau_sin->sin_addr, &ru.sau_sin->sin_addr,
		    sizeof (lu.sau_sin->sin_addr));
		if (cmp > 0)
			return (1);
		if (cmp < 0)
			return (-1);

		if (lu.sau_sin->sin_port > ru.sau_sin->sin_port)
			return (1);
		if (lu.sau_sin->sin_port < ru.sau_sin->sin_port)
			return (-1);
		return (0);
	}

	ASSERT(l->ss_family == AF_INET6);

	cmp = memcmp(&lu.sau_sin6->sin6_addr, &ru.sau_sin6->sin6_addr,
	    sizeof (lu.sau_sin6->sin6_addr));
	if (cmp > 0)
		return (1);
	if (cmp < 0)
		return (-1);

	if (lu.sau_sin6->sin6_port > ru.sau_sin6->sin6_port)
		return (1);
	if (lu.sau_sin6->sin6_port < ru.sau_sin6->sin6_port)
		return (-1);
	return (0);
}

static int
i2sa_compare(const ikev2_sa_t *sa, const i2sa_cmp_t *cmp)
{
	if (cmp->ic_l_spi != 0) {
		/*
		 * Since we assign the local SPI, we enforce that
		 * they are globally unique
		 */
		if (I2SA_LOCAL_SPI(sa) > cmp->ic_l_spi)
			return (1);
		if (I2SA_LOCAL_SPI(sa) < cmp->ic_l_spi)
			return (-1);
		return (0);
	}

	VERIFY3U(cmp->ic_r_spi, !=, 0);

	if (I2SA_REMOTE_SPI(sa) > cmp->ic_r_spi)
		return (1);
	if (I2SA_REMOTE_SPI(sa) < cmp->ic_r_spi)
		return (-1);

	/* More likely to be different, so check these first */
	int rc = sockaddr_compare(&sa->raddr, cmp->ic_raddr);
	if (rc > 0)
		return (1);
	if (rc < 0)
		return (-1);

	/* A multihomed system might have different local addresses */
	rc = sockaddr_compare(&sa->laddr, cmp->ic_laddr);
	if (rc > 0)
		return (1);
	if (rc < 0)
		return (-1);

	/*
	 * RFC5996 2.1 - We cannot merely rely on the remote SPI and
	 * address as clients behind NATs might choose the same SPI by chance.
	 * We must in addition look at the initial packet.  This is only
	 * an issue for half-opened remotely initiated SAs, as this is the
	 * only time the local SPI is not yet known.
	 */
	rc = memcmp(I2SA_REMOTE_INIT(sa)->pkt_raw,
	    cmp->ic_init_pkt->pkt_raw,
	    MIN(pkt_len(I2SA_REMOTE_INIT(sa)), pkt_len(cmp->ic_init_pkt)));
	if (rc != 0)
		return ((rc < 0) ? -1 : 1);
	if (pkt_len(I2SA_REMOTE_INIT(sa)) < pkt_len(cmp->ic_init_pkt))
		return (-1);
	if (pkt_len(I2SA_REMOTE_INIT(sa)) > pkt_len(cmp->ic_init_pkt))
		return (1);

	return (0);
}

static boolean_t
i2sa_key_add_addr(ikev2_sa_t *i2sa, const char *addr_key, const char *port_key,
    const struct sockaddr_storage *addr)
{
	sockaddr_u_t sau;
	sau.sau_ss = (struct sockaddr_storage *)addr;
	int rc = 0;

	switch (addr->ss_family) {
	case AF_INET:
		rc = bunyan_key_add(i2sa->i2sa_log,
		    BUNYAN_T_IP, addr_key, &sau.sau_sin->sin_addr,
		    BUNYAN_T_UINT32, port_key, (uint32_t)sau.sau_sin->sin_port,
		    BUNYAN_T_END);
		break;
	case AF_INET6:
		rc = bunyan_key_add(i2sa->i2sa_log,
		    BUNYAN_T_IP6, addr_key, &sau.sau_sin6->sin6_addr,
		    BUNYAN_T_UINT32, port_key,
		    (uint32_t)sau.sau_sin6->sin6_port,
		    BUNYAN_T_END);
		break;
	default:
		INVALID("addr->ss_family");
	}

	return ((rc == 0) ? B_TRUE : B_FALSE);
}

const char *
i2sa_msgtype_str(i2sa_msg_type_t type)
{
#define	STR(x)	case x: return (#x);
	switch (type) {
	STR(I2SA_MSG_NONE);
	STR(I2SA_MSG_PKT);
	STR(I2SA_MSG_PFKEY);
	}
#undef STR

	INVALID("type");
	/*NOTREACHED*/
	return (NULL);
}

void
ikev2_sa_init(void)
{
	if ((i2sa_cache = umem_cache_create("IKEv2 SAs", sizeof (ikev2_sa_t),
	    0, i2sa_ctor, i2sa_dtor, NULL, NULL, NULL, 0)) == NULL)
		err(EXIT_FAILURE, "Unable to create IKEv2 SA cache");

	if ((i2c_cache = umem_cache_create("IKEv2 Child SAs",
	    sizeof (ikev2_child_sa_t), 0, i2c_ctor, i2c_dtor, NULL, NULL, NULL,
	    0)) == NULL)
		err(EXIT_FAILURE, "Unable to create IKEv2 Child SA cache");

	/* XXX: Change to tunable */
	ikev2_sa_set_hashsize(ikev2_sa_buckets);
}

void
ikev2_sa_fini(void)
{
	umem_cache_destroy(i2sa_cache);
	umem_cache_destroy(i2c_cache);
}
