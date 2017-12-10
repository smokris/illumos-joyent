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
#include "ike.h"
#include "ikev2_cookie.h"
#include "ikev2_pkt.h"
#include "ikev2_proto.h"
#include "ikev2_sa.h"
#include "pfkey.h"
#include "pkcs11.h"
#include "pkt.h"
#include "worker.h"

/*
 * An arbitrary prime number pulled from the ether
 */
#define	I2SA_NBUCKETS	73

static volatile uint_t	half_open;	/* # of larval/half open IKEv2 SAs */
static uint64_t		remote_noise;	/* random noise for rspi hash */
static uint64_t		addr_noise;	/* random noise for the addr hash */

			/* protects all 3 hashes */
static rwlock_t		i2sa_hash_lock = DEFAULTRWLOCK;
static refhash_t	*i2sa_lspi_refhash;
static refhash_t	*i2sa_rspi_refhash;
static refhash_t	*i2sa_addr_refhash;

static umem_cache_t	*i2sa_cache;
static umem_cache_t	*i2c_cache;

static uint64_t	i2sa_lspi_hash(const void *);
static uint64_t i2sa_rspi_hash(const void *);
static uint64_t i2sa_addr_hash(const void *);

static int i2sa_lspi_cmp(const void *, const void *);
static int i2sa_rspi_cmp(const void *, const void *);
static int i2sa_addr_cmp(const void *, const void *);

static void i2sa_unlink(ikev2_sa_t *);
static void i2sa_p1_expire(void *);

static boolean_t i2sa_key_add_addr(ikev2_sa_t *, const char *, const char *,
    const struct sockaddr_storage *);
static int i2sa_ctor(void *, void *, int);
static void i2sa_dtor(void *, void *);

static void inc_half_open(void);
static void dec_half_open(void);

ikev2_sa_t *
ikev2_sa_getbylspi(uint64_t spi, boolean_t initiator)
{
	ikev2_sa_t *i2sa = NULL;
	ikev2_sa_t cmp_sa = {
		.flags = initiator ? I2SA_INITIATOR : 0,
		.i_spi = initiator ? spi : 0,
		.r_spi = initiator ? 0 : spi
	};

	VERIFY0(rw_rdlock(&i2sa_hash_lock));
	i2sa = refhash_lookup(i2sa_lspi_refhash, &cmp_sa);
	VERIFY0(rw_unlock(&i2sa_hash_lock));

	if (i2sa != NULL) {
		(void) bunyan_key_add(log,
		    BUNYAN_T_POINTER, LOG_KEY_I2SA, i2sa,
		    BUNYAN_T_END);
	}

	return (i2sa);
}

ikev2_sa_t *
ikev2_sa_getbyrspi(uint64_t spi,
    const struct sockaddr_storage *restrict laddr,
    const struct sockaddr_storage *restrict raddr,
    const pkt_t *restrict init_pkt)
{
	ikev2_sa_t *i2sa = NULL;
	ikev2_sa_t cmp_sa = {
		.i_spi = spi,
		.init_i = (pkt_t *)init_pkt
	};

	sockaddr_copy(laddr, &cmp_sa.laddr, B_FALSE);
	sockaddr_copy(raddr, &cmp_sa.raddr, B_FALSE);

	VERIFY0(rw_rdlock(&i2sa_hash_lock));
	i2sa = refhash_lookup(i2sa_rspi_refhash, &cmp_sa);
	VERIFY0(rw_unlock(&i2sa_hash_lock));

	if (i2sa != NULL) {
		(void) bunyan_key_add(log,
		    BUNYAN_T_POINTER, LOG_KEY_I2SA, i2sa,
		    BUNYAN_T_END);
	}

	return (i2sa);
}

ikev2_sa_t *
ikev2_sa_getbyaddr(const struct sockaddr_storage *restrict src,
   const struct sockaddr_storage *restrict dst)
{
	ikev2_sa_t *i2sa = NULL;
	ikev2_sa_t cmp_sa = { 0 };

	sockaddr_copy(src, &cmp_sa.laddr, B_FALSE);
	sockaddr_copy(dst, &cmp_sa.raddr, B_FALSE);

	VERIFY0(rw_rdlock(&i2sa_hash_lock));
	i2sa = refhash_lookup(i2sa_addr_refhash, &cmp_sa);
	VERIFY0(rw_unlock(&i2sa_hash_lock));

	if (i2sa != NULL) {
		(void) bunyan_key_add(log,
		    BUNYAN_T_POINTER, LOG_KEY_I2SA, i2sa,
		    BUNYAN_T_END);
	}

	return (i2sa);
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
 *	init_pkt	The packet that trigged the creation of the SA or NULL
 *			if we initiated.
 *	laddr,
 *	raddr		The local and remote addresses of this SA.
 *
 * On successful create, the refheld larval IKEv2 SA is returned.  In addition,
 * the IKEv2 SA queue is locked on return.
 *
 * On failure, NULL is returned.  Caller maintains responsibility for
 * init_pkt in this instance.
 */
ikev2_sa_t *
ikev2_sa_alloc(pkt_t *restrict init_pkt,
    const struct sockaddr_storage *restrict laddr,
    const struct sockaddr_storage *restrict raddr)
{
	ikev2_sa_t	*i2sa = NULL;
	config_t	*cfg = NULL;
	hrtime_t	expire = 0;
	boolean_t	initiator = (init_pkt == NULL) ? B_TRUE : B_FALSE;

	(void) bunyan_trace(log, "Attempting to create new larval IKE SA",
	    BUNYAN_T_BOOLEAN, LOG_KEY_INITIATOR, initiator,
	    ss_bunyan(laddr), LOG_KEY_LADDR, ss_addr(laddr),
	    ss_bunyan(raddr), LOG_KEY_RADDR, ss_addr(raddr),
	    BUNYAN_T_END);

	cfg = config_get();
	expire = cfg->cfg_expire_timer;
	CONFIG_REFRELE(cfg);

	if ((i2sa = umem_cache_alloc(i2sa_cache, UMEM_DEFAULT)) == NULL) {
		STDERR(error, "No memory to create IKEv2 SA");
		return (NULL);
	}

	/* Keep anyone else out while we initialize */
	mutex_enter(&i2sa->i2sa_queue_lock);
	mutex_enter(&i2sa->i2sa_lock);

	i2sa->i2sa_tid = thr_self();

	i2sa->flags |= initiator ? I2SA_INITIATOR : 0;

	bcopy(laddr, &i2sa->laddr, sizeof (*laddr));
	bcopy(raddr, &i2sa->raddr, sizeof (*raddr));

	/*
	 * Use the port given to us if specified, otherwise use the default.
	 * Take advantage of port being at the same offset for IPv4/v6
	 */
	VERIFY(laddr->ss_family == AF_INET || laddr->ss_family == AF_INET6);
	if (ss_port(laddr) == 0) {
		((struct sockaddr_in *)&i2sa->laddr)->sin_port =
		    htons(IPPORT_IKE);
	}
	if (ss_port(raddr) == 0) {
		((struct sockaddr_in *)&i2sa->raddr)->sin_port =
		    htons(IPPORT_IKE);
	}

	/*
	 * Generate a random local SPI and try to add it.  Almost always this
	 * will succeed on the first attempt.  However if on the rare occasion
	 * we generate a duplicate (or even far, far, rarer chance 0 is
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

		VERIFY0(rw_wrlock(&i2sa_hash_lock));
		if (refhash_lookup(i2sa_lspi_refhash, i2sa) != NULL) {
			VERIFY0(rw_unlock(&i2sa_hash_lock));
			continue;
		}

		refhash_insert(i2sa_lspi_refhash, i2sa);
		I2SA_REFHOLD(i2sa);

		refhash_insert(i2sa_addr_refhash, i2sa);
		I2SA_REFHOLD(i2sa);

		VERIFY3U(i2sa->refcnt, ==, 2);

		i2sa->init_i = init_pkt;

		/* refhold for caller */
		I2SA_REFHOLD(i2sa);

		VERIFY0(rw_unlock(&i2sa_hash_lock));
		break;
	};

	key_add_ike_spi(LOG_KEY_LSPI, I2SA_LOCAL_SPI(i2sa));
	(void) bunyan_trace(log, "Allocated local SPI", BUNYAN_T_END);

	/*
	 * If we're the initiator, we don't know the remote SPI until after
	 * the remote peer responds.  However if we are the responder,
	 * we know what it is and can set it now.  We also want to bump the
	 * half open count to enable cookies if too many half-open inbound
	 * connections are out there.
	 */
	if (!initiator) {
		inc_half_open();
		ikev2_sa_set_remote_spi(i2sa,
		    pkt_header(init_pkt)->initiator_spi);
	}

	mutex_exit(&i2sa->i2sa_queue_lock);

	I2SA_REFHOLD(i2sa);	/* ref for periodic */
	if (!ikev2_sa_arm_timer(i2sa, I2SA_EVT_P1_EXPIRE, expire)) {
		STDERR(error, "Cannot create IKEv2 SA P1 expiration timer");
		i2sa_unlink(i2sa);
		i2sa->i2sa_tid = 0;
		mutex_exit(&i2sa->i2sa_lock);

		/*
		 * When refcnt goes from 1 -> 0, i2sa will be freed, so do
		 * last refrele explicitly to avoid the loop check.
		 */
		while (i2sa->refcnt > 1)
			I2SA_REFRELE(i2sa);
		I2SA_REFRELE(i2sa);

		(void) bunyan_debug(log, "Larval IKE SA creation failed",
		    BUNYAN_T_END);
		return (NULL);
	}

	mutex_exit(&i2sa->i2sa_lock);

	mutex_enter(&i2sa->i2sa_queue_lock);
	mutex_enter(&i2sa->i2sa_lock);
	i2sa->i2sa_tid = 0;
	mutex_exit(&i2sa->i2sa_lock);

	/*
	 * Leave i2sa_queue_lock held so caller has exclusive access to SA
	 * upon return.
	 */
	(void) bunyan_debug(log, "New larval IKE SA created",
	    BUNYAN_T_POINTER, LOG_KEY_I2SA, i2sa,
	    BUNYAN_T_END);

	return (i2sa);
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

	key_add_ike_spi(LOG_KEY_LSPI, I2SA_LOCAL_SPI(i2sa));
	key_add_ike_spi(LOG_KEY_RSPI, I2SA_REMOTE_SPI(i2sa));

	(void) bunyan_info(log, "Larval IKE SA (P1) timeout", BUNYAN_T_END);
	ikev2_sa_post_event(i2sa, I2SA_EVT_P1_EXPIRE);

	(void) bunyan_key_remove(log, LOG_KEY_LSPI);
	(void) bunyan_key_remove(log, LOG_KEY_RSPI);

	I2SA_REFRELE(i2sa);
}

void
ikev2_sa_flush(void)
{
	/* TODO: implement me */
}

/*
 * Arm an IKEv2 SA timer to fire the given event reltime nanoseconds from now.
 * This is intended to be called during normal IKEv2 SA processing (hence
 * the VERIFY checks) with only the i2sa_lock held.  Returns B_TRUE if
 * timer was successfully armed.
 */
boolean_t
ikev2_sa_arm_timer(ikev2_sa_t *i2sa, i2sa_evt_t event, hrtime_t reltime)
{
	VERIFY(!MUTEX_HELD(&i2sa->i2sa_queue_lock));
	VERIFY(MUTEX_HELD(&i2sa->i2sa_lock));
	VERIFY3U(i2sa->i2sa_tid, ==, thr_self());

	periodic_id_t *idp = NULL;
	periodic_func_t *cb = NULL;

	switch (event) {
	case I2SA_EVT_NONE:
		INVALID(event);
		/*NOTREACHED*/
		break;
	case I2SA_EVT_PKT_XMIT:
		idp = &i2sa->i2sa_xmit_timer;
		cb = ikev2_retransmit_cb;
		break;
	case I2SA_EVT_P1_EXPIRE:
		idp = &i2sa->i2sa_p1_timer;
		cb = i2sa_p1_expire;
		break;
	case I2SA_EVT_SOFT_EXPIRE:
		idp = &i2sa->i2sa_softlife_timer;
		INVALID("not yet");
		break;
	case I2SA_EVT_HARD_EXPIRE:
		idp = &i2sa->i2sa_hardlife_timer;
		INVALID("not yet");
		break;
	}

	mutex_exit(&i2sa->i2sa_lock);
	mutex_enter(&i2sa->i2sa_queue_lock);
	mutex_enter(&i2sa->i2sa_lock);

	int rc = periodic_schedule(wk_periodic, reltime, PERIODIC_ONESHOT,
	    cb, i2sa, idp);
	if (rc != 0)
		VERIFY3S(errno, ==, ENOMEM);

	mutex_exit(&i2sa->i2sa_queue_lock);
	return ((rc == 0) ? B_TRUE : B_FALSE);
}

/*
 * Disarm the given timer.  Returns B_TRUE if the event was disarmed.
 * If the event fired during the call to ikev2_sa_disarm_timer, B_FALSE
 * is returned and the event is cleared from i2sa_events.
 * This should be called from a normal processing context (IKEv2 SA pinned,
 * i2sa_queue_lock not held, etc).
 */
boolean_t
ikev2_sa_disarm_timer(ikev2_sa_t *i2sa, i2sa_evt_t event)
{
	VERIFY(!MUTEX_HELD(&i2sa->i2sa_queue_lock));
	VERIFY(MUTEX_HELD(&i2sa->i2sa_lock));
	VERIFY3U(i2sa->i2sa_tid, ==, thr_self());

	int rc = 0;
	periodic_id_t id = 0, *idp = NULL;
	boolean_t fired = B_FALSE;

	switch (event) {
	case I2SA_EVT_NONE:
		INVALID(event);
		/*NOTREACHED*/
		break;
	case I2SA_EVT_PKT_XMIT:
		idp = &i2sa->i2sa_xmit_timer;
		break;
	case I2SA_EVT_P1_EXPIRE:
		idp = &i2sa->i2sa_p1_timer;
		break;
	case I2SA_EVT_SOFT_EXPIRE:
		idp = &i2sa->i2sa_softlife_timer;
		break;
	case I2SA_EVT_HARD_EXPIRE:
		idp = &i2sa->i2sa_hardlife_timer;
		break;
	}

	/*
	 * If the timer callback is executing on another thread while
	 * periodic_cancel() is called, the periodic_cancel() call will block
	 * until the callback completes.  Since every callback function needs
	 * to acquire i2sa_queue_lock to post the event, we must call
	 * periodic_cancel() without holding i2sa_queue_lock.  However posting
	 * an event will also clear it's id, so we must cache the current value
	 * before dropping   However posting an event will also clear it's id,
	 * so we must cache the current value before dropping.
	 *
	 * We rely on libperiodic not recycling the id of the timer we're
	 * cancelling in the short time between when we cache it and when we
	 * call periodic_cancel().  If such recycling where to happen, we could
	 * end up cancelling the wrong timer.
	 *
	 * As libperiodic currently uses a 2^32 sized id space, it would
	 * (short of deliberate coersion of the scheduler or process) require
	 * a system to be making such glacial progress as to effectively be
	 * dead and unusable, so this seems like a reasonable assumption.
	 */
	mutex_exit(&i2sa->i2sa_lock);

	mutex_enter(&i2sa->i2sa_queue_lock);
	id = *idp;
	mutex_exit(&i2sa->i2sa_queue_lock);

	if (id != 0 && (rc = periodic_cancel(wk_periodic, id)) != 0)
		VERIFY3S(errno, ==, ENOENT);

	mutex_enter(&i2sa->i2sa_queue_lock);

	if (id == 0 || i2sa->i2sa_events & event) {
		fired = B_TRUE;
		i2sa->i2sa_events &= ~event;
	}
	*idp = 0;

	mutex_enter(&i2sa->i2sa_lock);
	mutex_exit(&i2sa->i2sa_queue_lock);

	return (!fired);
}

/*
 * Post that an event has fired.  Should be called by a callback handler
 * without any IKE SA locks held.  It will attempt to dispatch the event after
 * posting it (which may fail and the event merely queued if the IKEv2 SA has
 * already been pinned to a thread).
 */
void
ikev2_sa_post_event(ikev2_sa_t *i2sa, i2sa_evt_t event)
{
	VERIFY(!MUTEX_HELD(&i2sa->i2sa_lock));

	I2SA_REFHOLD(i2sa);

	mutex_enter(&i2sa->i2sa_queue_lock);

	i2sa->i2sa_events |= event;
	switch (event) {
	case I2SA_EVT_NONE:
		INVALID(event);
		/*NOTREACHED*/
		break;
	case I2SA_EVT_PKT_XMIT:
		i2sa->i2sa_xmit_timer = 0;
		break;
	case I2SA_EVT_P1_EXPIRE:
		i2sa->i2sa_p1_timer = 0;
		break;
	case I2SA_EVT_SOFT_EXPIRE:
		i2sa->i2sa_softlife_timer = 0;
		break;
	case I2SA_EVT_HARD_EXPIRE:
		i2sa->i2sa_hardlife_timer = 0;
		break;
	}

	ikev2_dispatch(i2sa);
	mutex_exit(&i2sa->i2sa_queue_lock);

	I2SA_REFRELE(i2sa);
}

/*
 * Get the existing response for this packet if we have it, otherwise
 * return NULL
 */
pkt_t *
ikev2_sa_get_response(ikev2_sa_t *restrict i2sa, const pkt_t *req)
{
	VERIFY(MUTEX_HELD(&i2sa->i2sa_lock));
	VERIFY(!I2P_RESPONSE(req));

	uint32_t req_id = pkt_header(req)->msgid;

	if (i2sa->last_resp_sent == NULL)
		return (NULL);

	if (pkt_header(i2sa->last_resp_sent)->msgid == req_id)
		return (i2sa->last_resp_sent);

	return (NULL);
}

/*
 * Condemning an IKEv2 SA is somewhat complicated.  If the IKEv2 SA has not
 * yet been authenticated, we can completely tear it down and release it
 * when we condemn it.  However, once the IKEv2 SA has been authenticated, we
 * cannot tear it down completely once we've condemned it.  For example, if
 * during the IKE_AUTH exchange we successfully authenticate our peer, but
 * cannot establish the accompanying child SA for whatever reason, we cannot
 * immediately tear down the IKE SA -- a separate INFORMATIONAL exchange must
 * take place to delete the IKE SA.  If we initiate the exchange, we will also
 * want to wait up to the timeout for a reply, so we must be able to
 * still process replies.
 *
 * As such, once the IKEv2 SA has been authenticated, condemnation is a two
 * step process.   The first step will merely set the I2SA_CONDEMNED flag
 * which will indicate that any new requests to this IKEv2 SA from the kernel
 * as well as attempts for new work should be rejected.  Once any necessary
 * exchanges are complete, ikev2_sa_condemn is called once again to complete
 * tearing down the IKEv2 SA.
 */
void
ikev2_sa_condemn(ikev2_sa_t *i2sa)
{
	VERIFY(!MUTEX_HELD(&i2sa->i2sa_queue_lock));
	VERIFY(MUTEX_HELD(&i2sa->i2sa_lock));
	VERIFY3U(i2sa->i2sa_tid, ==, thr_self());

	(void) bunyan_info(log, "Condemning IKE SA (Step 1)", BUNYAN_T_END);

	if (!(i2sa->flags & I2SA_CONDEMNED) &&
	    (i2sa->flags & I2SA_AUTHENTICATED)) {
		i2sa->flags |= I2SA_CONDEMNED;
		return;
	}

	(void) bunyan_info(log, "Condemning IKE SA (Step 2)", BUNYAN_T_END);

	I2SA_REFHOLD(i2sa);
	i2sa_unlink(i2sa);

	/*
	 * The ref for the packet retransmit timer is held by i2sa->last_sent,
	 * so it will get released (if needed) later.
	 */
	(void) ikev2_sa_disarm_timer(i2sa, I2SA_EVT_PKT_XMIT);

	if (ikev2_sa_disarm_timer(i2sa, I2SA_EVT_P1_EXPIRE))
		I2SA_REFRELE(i2sa);
	if (ikev2_sa_disarm_timer(i2sa, I2SA_EVT_SOFT_EXPIRE))
		I2SA_REFRELE(i2sa);
	if (ikev2_sa_disarm_timer(i2sa, I2SA_EVT_HARD_EXPIRE))
		I2SA_REFRELE(i2sa);

	/*
	 * Since packets keep a reference to the SA they are associated with,
	 * we must free them here so that their references go away
	 */
	if (i2sa->init_i != i2sa->last_sent)
		ikev2_pkt_free(i2sa->init_i);
	i2sa->init_i = NULL;

	if (i2sa->init_r != i2sa->last_resp_sent)
		ikev2_pkt_free(i2sa->init_r);
	i2sa->init_r = NULL;

	ikev2_pkt_free(i2sa->last_resp_sent);
	i2sa->last_resp_sent = NULL;

	ikev2_pkt_free(i2sa->last_sent);
	i2sa->last_sent = NULL;

	ikev2_pkt_free(i2sa->last_recvd);
	i2sa->last_recvd = NULL;

	ikev2_child_sa_t *i2c = refhash_first(i2sa->i2sa_child_sas);

	while (i2c != NULL) {
		ikev2_child_sa_t *i2c_next;

		i2c_next = refhash_next(i2sa->i2sa_child_sas, i2c);
		refhash_remove(i2sa->i2sa_child_sas, i2c);
		i2c = i2c_next;
	}

	mutex_exit(&i2sa->i2sa_lock);
	mutex_enter(&i2sa->i2sa_queue_lock);
	mutex_enter(&i2sa->i2sa_lock);

	for (size_t i = 0; i < I2SA_QUEUE_DEPTH; i++) {
		parsedmsg_t *pmsg = NULL;
		sadb_msg_t *samsg = NULL;

		switch (i2sa->i2sa_queue[i].i2m_type) {
		case I2SA_MSG_NONE:
			break;
		case I2SA_MSG_PKT:
			ikev2_pkt_free(i2sa->i2sa_queue[i].i2m_data);
			break;
		case I2SA_MSG_PFKEY:
			pmsg = i2sa->i2sa_queue[i].i2m_data;
			samsg = pmsg->pmsg_samsg;
			break;
		}
		i2sa->i2sa_queue[i].i2m_type = I2SA_MSG_NONE;
		i2sa->i2sa_queue[i].i2m_data = NULL;

		if (samsg != NULL && samsg->sadb_msg_pid == 0 &&
		    samsg->sadb_msg_type == SADB_ACQUIRE) {
			/*
			 * The kernel currently only cares that errno != 0,
			 * but this seems like the closest error code to
			 * what's happening, just to be as informative as
			 * possible.
			 */
			pfkey_send_error(samsg, ECANCELED);
		}

		parsedmsg_free(pmsg);
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

	config_id_free(i2sa->local_id);
	config_id_free(i2sa->remote_id);

	/* All unauthenticated IKEv2 SAs are considered larval */
	if ((i2sa->flags & (I2SA_AUTHENTICATED|I2SA_INITIATOR)) !=
	    (I2SA_AUTHENTICATED|I2SA_INITIATOR))
		dec_half_open();

#define	DESTROY(x, y) pkcs11_destroy_obj(#y, &(x)->y)
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

	i2sa_dtor(i2sa, NULL);
	(void) i2sa_ctor(i2sa, NULL, 0);
	umem_cache_free(i2sa_cache, i2sa);
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

	VERIFY0(rw_wrlock(&i2sa_hash_lock));
	refhash_insert(i2sa_rspi_refhash, i2sa);
	VERIFY0(rw_unlock(&i2sa_hash_lock));

	key_add_ike_spi(LOG_KEY_RSPI, remote_spi);

	(void) bunyan_trace(log, "Set remote SPI", BUNYAN_T_END);
}

static void
i2sa_unlink(ikev2_sa_t *i2sa)
{
	VERIFY0(rw_wrlock(&i2sa_hash_lock));

	refhash_remove(i2sa_lspi_refhash, i2sa);
	I2SA_REFRELE(i2sa);

	refhash_remove(i2sa_addr_refhash, i2sa);
	I2SA_REFRELE(i2sa);

	if (I2SA_REMOTE_SPI(i2sa) != 0) {
		refhash_remove(i2sa_rspi_refhash, i2sa);
		I2SA_REFRELE(i2sa);
	}

	VERIFY0(rw_unlock(&i2sa_hash_lock));
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

ikev2_child_sa_t *
ikev2_child_sa_alloc(boolean_t inbound)
{
	ikev2_child_sa_t *csa = NULL;

	if ((csa = umem_cache_alloc(i2c_cache, UMEM_DEFAULT)) == NULL)
		return (NULL);

	csa->i2c_birth = gethrtime();
	csa->i2c_inbound = inbound;
	return (csa);
}

void
ikev2_child_sa_free(ikev2_sa_t *restrict i2sa, ikev2_child_sa_t *restrict csa)
{
	if (csa == NULL)
		return;

	VERIFY(!refhash_obj_valid(i2sa->i2sa_child_sas, csa));
	bzero(csa, sizeof (*csa));
	umem_cache_free(i2c_cache, csa);
}

ikev2_child_sa_t *
ikev2_sa_get_child(ikev2_sa_t *i2sa, uint32_t spi, boolean_t inbound)
{
	ikev2_child_sa_t cmp = {
		.i2c_inbound = inbound,
		.i2c_spi = spi
	};

	return (refhash_lookup(i2sa->i2sa_child_sas, &cmp));
}

void
ikev2_sa_add_child(ikev2_sa_t *restrict i2sa, ikev2_child_sa_t *restrict i2c)
{
	refhash_insert(i2sa->i2sa_child_sas, i2c);
}

static uint64_t
i2c_hash(const void *arg)
{
	const ikev2_child_sa_t *i2c = arg;
	uint64_t val = i2c->i2c_spi;

	if (i2c->i2c_inbound)
		val |= (1ULL << 32);
	return (val);
}

static int
i2c_cmp(const void *larg, const void *rarg)
{
	const ikev2_child_sa_t *l = larg;
	const ikev2_child_sa_t *r = rarg;

	if (l->i2c_spi < r->i2c_spi)
		return (-1);
	if (l->i2c_spi > r->i2c_spi)
		return (1);

	if (l->i2c_inbound && !r->i2c_inbound)
		return (-1);
	if (!l->i2c_inbound && r->i2c_inbound)
		return (1);

	return (0);
}

static void
i2c_refdtor(void *arg)
{
	ikev2_child_sa_t *i2c = arg;

	bzero(i2c, sizeof (*i2c));
	umem_cache_free(i2c_cache, i2c);
}

static int
i2sa_ctor(void *buf, void *dummy __unused, int flags __unused)
{
	NOTE(ARGUNUSED(dummy, flags))

	ikev2_sa_t *i2sa = buf;

	bzero(i2sa, sizeof (*i2sa));
	i2sa->msgwin = 1;

	VERIFY0(mutex_init(&i2sa->i2sa_lock, USYNC_THREAD|LOCK_ERRORCHECK,
	    NULL));
	VERIFY0(mutex_init(&i2sa->i2sa_queue_lock, USYNC_THREAD|LOCK_ERRORCHECK,
	    NULL));

	i2sa->i2sa_child_sas = refhash_create(I2SA_NBUCKETS, i2c_hash, i2c_cmp,
	    i2c_refdtor, sizeof (ikev2_child_sa_t),
	    offsetof(ikev2_child_sa_t, i2c_link), 0, UMEM_DEFAULT);

	return ((i2sa->i2sa_child_sas == NULL) ? 1 : 0);
}

static void
i2sa_dtor(void *buf, void *dummy __unused)
{
	NOTE(ARGUNUSED(dummy))

	ikev2_sa_t *i2sa = (ikev2_sa_t *)buf;

	VERIFY0(mutex_destroy(&i2sa->i2sa_lock));
	VERIFY0(mutex_destroy(&i2sa->i2sa_queue_lock));
	refhash_destroy(i2sa->i2sa_child_sas);
	i2sa->i2sa_child_sas = NULL;
}

static int
i2c_ctor(void *buf, void *dummy __unused, int flags __unused)
{
	NOTE(ARGUNUSED(dummy, flags))

	ikev2_child_sa_t *i2c = buf;

	bzero(i2c, sizeof (*i2c));
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
		rc = bunyan_key_add(log,
		    BUNYAN_T_IP, addr_key, &sau.sau_sin->sin_addr,
		    BUNYAN_T_UINT32, port_key, (uint32_t)sau.sau_sin->sin_port,
		    BUNYAN_T_END);
		break;
	case AF_INET6:
		rc = bunyan_key_add(log,
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

static uint64_t
i2sa_lspi_hash(const void *arg)
{
	const ikev2_sa_t *i2sa = arg;

	return (I2SA_LOCAL_SPI(i2sa));
}

static int
i2sa_lspi_cmp(const void *larg, const void *rarg)
{
	const ikev2_sa_t *l = larg;
	const ikev2_sa_t *r = rarg;
	uint64_t l_lspi = I2SA_LOCAL_SPI(l);
	uint64_t r_lspi = I2SA_LOCAL_SPI(r);

	if (l_lspi < r_lspi)
		return (-1);
	if (l_lspi > r_lspi)
		return (1);
	return (0);
}

/*
 * For hashing/lookup based on the remote spi, it is possible multiple peers
 * could choose the same SPI value.  In addition, it is also possible peers
 * could be behind the same NAT address.  To disambiguate, we follow
 * RFC7296 2.1 and look at the remote SPI, the addresses, and the init packet
 * to locate an IKEv2 SA.
 *
 * We only ever have to use this on a retransmit of the IKE_SA_INIT packet from
 * an remotely initiated IKE SA (due to packet loss, new KE group requested,
 * COOKIE request, etc) as that is the only instance where our local spi is
 * not included in the IKEv2 header -- we always prefer to lookup on the
 * local spi when present.
 *
 * Specifically we use the remote peer's nonce value as it should be randomly
 * generated, and at least 16 bytes long, so the chances of a collision
 * here are even smaller than with the remote SPI.  It should be noted that
 * this is all done in an effort to minimize the amount of processing that
 * is done and discarded.  If these fail, we'll just end up with some larval
 * ikev2_sa_t's (and some of the IKE_SA_INIT processing that goes with them)
 * that will eventually time out.
 */
static uint64_t
i2sa_rspi_hash(const void *arg)
{
	const ikev2_sa_t *i2sa = arg;
	const uint8_t *addrp[2] = { 0 };
	uint64_t hash = remote_noise;
	uint8_t *hashp = (uint8_t *)&hash;
	size_t addrlen = 0, hashidx = 0;
	pkt_payload_t *ni = NULL;

	hash ^= I2SA_REMOTE_SPI(i2sa);

	addrlen = ss_addrlen(&i2sa->laddr);
	addrp[0] = ss_addr(&i2sa->laddr);
	addrp[1] = ss_addr(&i2sa->raddr);

	for (size_t i = 0; i < 2; i++) {
		for (size_t j = 0; j < addrlen; j++) {
			hashp[hashidx++] ^= addrp[i][j];
			hashidx %= sizeof (hash);
		}
	}

	ni = pkt_get_payload(i2sa->init_i, IKEV2_PAYLOAD_NONCE, NULL);

	for (size_t i = 0; i < ni->pp_len; i++) {
		hashp[hashidx++] ^= ni->pp_ptr[i];
		hashidx %= sizeof (hash);
	}

	return (hash);
}

static int
i2sa_rspi_cmp(const void *larg, const void *rarg)
{
	const ikev2_sa_t *l = larg;
	const ikev2_sa_t *r = rarg;
	uint64_t l_rspi = I2SA_REMOTE_SPI(l);
	uint64_t r_rspi = I2SA_REMOTE_SPI(r);
	pkt_payload_t *ni_l = NULL, *ni_r = NULL;

	if (l_rspi < r_rspi)
		return (-1);
	if (l_rspi > r_rspi)
		return (1);

	int cmp = sockaddr_cmp(&l->laddr, &r->raddr);
	if (cmp != 0)
		return (cmp);

	cmp = sockaddr_cmp(&r->raddr, &r->raddr);
	if (cmp != 0)
		return (cmp);

	ni_l = pkt_get_payload(l->init_i, IKEV2_PAYLOAD_NONCE, NULL);
	ni_r = pkt_get_payload(r->init_i, IKEV2_PAYLOAD_NONCE, NULL);

	cmp = memcmp(ni_l->pp_ptr, ni_r->pp_ptr,
	    MIN(ni_l->pp_len, ni_r->pp_len));
	if (cmp != 0)
		return (cmp);

	if (ni_l->pp_len < ni_r->pp_len)
		return (-1);
	if (ni_r->pp_len > ni_r->pp_len)
		return (1);
	return (0);
}

static uint64_t
i2sa_addr_hash(const void *arg)
{
	const ikev2_sa_t *i2sa = arg;
	const uint8_t *addrp[2] = { 0 };
	uint64_t hash = addr_noise;
	uint8_t *hashp = (uint8_t *)&hash;
	size_t addrlen = 0, hashidx = 0;

	addrlen = ss_addrlen(&i2sa->laddr);
	addrp[0] = ss_addr(&i2sa->laddr);
	addrp[1] = ss_addr(&i2sa->raddr);

	for (size_t i = 0; i < 2; i++) {
		for (size_t j = 0; j < addrlen; j++) {
			hashp[hashidx++] ^= addrp[i][j];
			hashidx %= sizeof (hash);
		}
	}

	return (hash);
}

static int
i2sa_addr_cmp(const void *larg, const void *rarg)
{
	const ikev2_sa_t *l = larg;
	const ikev2_sa_t *r = rarg;
	int cmp;

	cmp = sockaddr_cmp(&l->laddr, &r->raddr);
	if (cmp != 0)
		return (cmp);
	return (sockaddr_cmp(&l->raddr, &r->raddr));
}

static void
dummy_dtor(void *arg __unused)
{
}

void
ikev2_sa_init(void)
{
	if ((i2sa_cache = umem_cache_create("IKEv2 SAs", sizeof (ikev2_sa_t),
	    0, i2sa_ctor, i2sa_dtor, NULL, NULL, NULL, 0)) == NULL)
		err(EXIT_FAILURE, "Unable to create IKEv2 SA cache");

	if ((i2c_cache = umem_cache_create("IKEv2 Child SAs",
	    sizeof (ikev2_child_sa_t), 0, i2c_ctor, NULL, NULL, NULL, NULL,
	    0)) == NULL)
		err(EXIT_FAILURE, "Unable to create IKEv2 Child SA cache");

	arc4random_buf(&remote_noise, sizeof (remote_noise));
	arc4random_buf(&addr_noise, sizeof (addr_noise));

	i2sa_lspi_refhash = refhash_create(I2SA_NBUCKETS, i2sa_lspi_hash,
	    i2sa_lspi_cmp, dummy_dtor, sizeof (ikev2_sa_t),
	    offsetof(ikev2_sa_t, i2sa_lspi_link), 0, UMEM_NOFAIL);

	i2sa_rspi_refhash = refhash_create(I2SA_NBUCKETS, i2sa_rspi_hash,
	    i2sa_rspi_cmp, dummy_dtor, sizeof (ikev2_sa_t),
	    offsetof(ikev2_sa_t, i2sa_rspi_link), 0, UMEM_NOFAIL);

	i2sa_addr_refhash = refhash_create(I2SA_NBUCKETS, i2sa_addr_hash,
	    i2sa_addr_cmp, dummy_dtor, sizeof (ikev2_sa_t),
	    offsetof(ikev2_sa_t, i2sa_addr_link), 0, UMEM_NOFAIL);
}

void
ikev2_sa_fini(void)
{
	umem_cache_destroy(i2sa_cache);
	umem_cache_destroy(i2c_cache);
	refhash_destroy(i2sa_lspi_refhash);
	refhash_destroy(i2sa_rspi_refhash);
	refhash_destroy(i2sa_addr_refhash);
}
