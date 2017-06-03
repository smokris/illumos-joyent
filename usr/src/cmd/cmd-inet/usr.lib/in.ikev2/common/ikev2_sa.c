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
 * Copyright 2014 Jason King.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Manipulation and storage of IKEv2 Security Associations (SAs).
 */
#include <umem.h>
#include <pthread.h>
#include <errno.h>
#include <strings.h>
#include <locale.h>
#include <stddef.h>
#include <ipsec_util.h>
#include <sys/types.h>
#include <sys/sysmacros.h>
#include <sys/debug.h>
#include <limits.h>

#include "defs.h"
#include "timer.h"
#include "ikev2_sa.h"

#define	IKEV2_SA_HASH_SPI(spi) \
    P2PHASE_TYPED(spi, num_buckets, uint64_t)
#define	IKEV2_SA_RHASH(ss, spi) \
    P2PHASE_TYPED(i2sa_rhash((ss), (spi)), num_buckets, uint64_t)

struct i2sa_bucket_s {
	pthread_mutex_t		lock;	/* bucket lock */
	uu_list_t		*chain;	/* hash chain of ikev2_sa_t's */
};

typedef struct i2sa_cmp_arg_s {
	const buf_t	*init_pkt;
	boolean_t	lspi_hash;	/* comparing local/rhash chain */
} i2sa_cmp_arg_t;

static volatile uint_t	half_open;	/* # of larval/half open IKEv2 SAs */
static uint_t		num_buckets;	/* Use same value for both buckets */
static i2sa_bucket_t	*hash[N_HTABLE];
static uint32_t		remote_noise;	/* random noise for rhash */
static uu_list_pool_t	*lspi_list_pool;
static uu_list_pool_t	*rhash_list_pool;
static umem_cache_t	*i2sa_cache;


static void	i2sa_init(ikev2_sa_t *);
static uint32_t	i2sa_rhash(const struct sockaddr_storage *, uint64_t);

static ikev2_sa_t *i2sa_verify(ikev2_sa_t *restrict, uint64_t,
    const struct sockaddr_storage *, const struct sockaddr_storage *);
static boolean_t i2sa_add_to_hash(ikev2_sa_t *, boolean_t);
static void	i2sa_unlink(ikev2_sa_t *);

static void inc_half_open(void);
static void dec_half_open(void);

ikev2_sa_t *
ikev2_sa_get(uint64_t l_spi, uint64_t r_spi,
    const struct sockaddr_storage *restrict l_addr,
    const struct sockaddr_storage *restrict r_addr,
    const buf_t *restrict init_pkt)
{
	i2sa_bucket_t *bucket;
	ikev2_sa_t *sa;
	ikev2_sa_t ref = { 0 };
	i2sa_cmp_arg_t arg = { 0 };

	/*
	 * This only necessary to correctly map local/remote SPI to
	 * initiator / responder SPI
	 */
	ref.flags = I2SA_INITIATOR;
	ref.i_spi = l_spi;
	ref.r_spi = r_spi;
	(void) memcpy(&ref.laddr, l_addr, sizeof (*l_addr));
	(void) memcpy(&ref.raddr, r_addr, sizeof (*r_addr));

	if (l_spi != 0) {
		arg.local_hash = B_TRUE;
		bucket = sas_by_lspi + IKEV2_SA_HASH_SPI(l_spi);
	} else {
		arg.local_hash = B_FALSE;
		arg.init_pkt = init_pkt;
		bucket = sas_by_rhash + IKEV2_SA_RHASH(r_addr, r_spi);
	}

	VERIFY(pthread_mutex_lock(&bucket->lock) == 0);
	sa = (ikev2_sa_t *)uu_list_find(bucket->chain, &ref, &arg, NULL);
	if (sa != NULL)
		I2SA_REFHOLD(sa);
	VERIFY(pthread_mutex_unlock(&bucket->lock) == 0);

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
 * On successful create, the larval IKEv2 SA is returned.
 * On failure, NULL is returned.  Caller maintains responsibility for
 * init_pkt in this instance.
 */
ikev2_sa_t *
ikev2_sa_alloc(boolean_t initiator,
    pkt_t *restrict init_pkt,
    const struct sockaddr_storage *restrict laddr,
    const struct sockaddr_storage *restrict raddr)
{
	ikev2_sa_t	*i2sa = NULL;

	if ((i2sa = umem_cache_alloc(i2sa_cache, UMEM_DEFAULT)) == NULL)
		return (NULL);

	/* Keep anyone else out while we initialize */
	VERIFY(pthread_mutex_lock(&i2sa->lock) == 0);

	ASSERT((init_pkt == NULL) ||
	    (init_pkt->hdr.exch_type == IKEV2_EXCHANGE_IKE_SA_INIT));

	i2sa->flags |= (initiator) ? I2SA_INITIATOR : 0;

	(void) memcpy(&i2sa->laddr, laddr, sizeof (*laddr));
	(void) memcpy(&i2sa->raddr, raddr, sizeof (*raddr));

	/* Get a random number for the local SPI that's currently unusued */
	while (1) {
		/*CONSTCOND*/
		uint64_t spi;

		/* 0 is never valid, exteremely unlikely, but easy to handle */
		if ((spi = random_low_64()) == 0)
			continue;

		if (initiator)
			i2sa->i_spi = spi;
		else
			i2sa->r_spi = spi;

		if (i2sa_add_to_hash(LSPI, i2sa)) {
			ASSERT(i2sa->refcnt == 1);

			/* XXX: refhold i2sa in init_pkt */
			i2sa->init = init_pkt;

			/* refhold for caller */
			I2SA_REFHOLD(i2sa);
			break;
		}
	};

	inc_half_open();

	/*
	 * Start SA expiration timer.
	 * XXX: Should this be reset after we've successfully authenticated?
	 */

	I2SA_REFHOLD(i2sa);	/* for the timer */
	if (!schedule_timeout(TE_SA_EXPIRE, i2sa_expire_cb, i2sa,
	    /* XXX: fixme */ 999 * NANOSEC)) {
		/* XXX: log error */

		I2SA_REFRELE(i2sa); /* timer */
		I2SA_REFRELE(i2sa); /* caller */

		/* remove from hashes, should also free SA */
		i2sa_unlink(i2sa);
		return (NULL);
	}

	return (i2sa);
}

/*
 * Invoked when an SA has expired.  SA is refheld from timer.
 */
static void
i2sa_expire_cb(void *data)
{
	ikev2_sa_t *i2sa = (ikev2_sa_t *)data;

	/* XXX: todo */
	I2SA_REFRELE(i2sa);
}

void
ikev2_sa_flush(void)
{
}

void
ikev2_sa_condemn(ikev2_sa_t *i2sa)
{
}

void
ikev2_sa_free(ikev2_sa_t *i2sa)
{
	if (i2sa == NULL)
		return;

	ASSERT(i2sa->refcnt == 0);

	/* All unauthenticated IKEv2 SAs are considered larval */
	if (!(i2sa->flags & I2SA_AUTHENTICATED))
		dec_half_open();

        /*
         * XXX: we have potential circular references here
         * as ikev2_pkt_t->sa and i2sa->init,
         * i2sa->last_{resp_sent,sent,recvd} reference each other.
         *
         * We will need to sit and thing about the lifecycles of
         * these packets to make sure when we want this SA to go
         * away for any reason, everything is properly cleaned up.
         *
         * For now, my thought is to punt until after the
         * IKE_SA_INIT and IKE_AUTH exchanges are written, as that
         * will likely help identify the best approach to resolving this.
         */
        ikev2_pkt_free(i2sa->init);
        ikev2_pkt_free(i2sa->last_resp_sent);
        ikev2_pkt_free(i2sa->last_sent);
        ikev2_pkt_free(i2sa->last_recvd);

#define DESTROY(x, y) pkcs11_destroy_obj(#y, &(x)->y, D_OP)
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
#undef  DESTROY

        csa = i2sa->child_sas;
        while (csa != NULL) {
                next = csa->next;
                free(csa);
                csa = next;
        }

        i2sa_init(i2sa);
        umem_cache_free(i2sa_cache, i2sa);
}

/* XXX: fixme */
void
ikev2_sa_set_hashsize(uint_t numbuckets)
{
	i2sa_bucket_t *old_lspi = sas_by_lspi;
	i2sa_bucket_t *old_rhash = sas_by_rhash;
	int i;
	boolean_t startup;

	if (sas_by_lspi == NULL)
		startup = B_TRUE;
	else
		start = B_FALSE;

	/* XXX: suspend threads if !startup */

	/* round up to a power of two if not already */
	if (!ISP2(numbuckets)) {
		ASSERT(sizeof (uint_t) == 4);

		--numbuckets;
		for (i = 1; i <= 16; i++)
			numbuckets |= (numbuckets >> i);
		++numbuckets;
	}
	VERIFY(ISP2(numbuckets));

	/* Allocate new buckets */
	sas_by_lspi = calloc(numbuckets, sizeof (i2sa_bucket_t));
	sas_by_rhash = calloc(numbuckets, sizeof (i2sa_bucket_t));
	if (sas_by_lspi == NULL || sas_by_rhash == NULL)
		goto nomem;

	uint32_t flags = UU_LIST_SORTED;

#ifdef DEBUG
	flags |= UU_LIST_DEBUG;
#endif

	for (i = 0; i < numbuckets; i++) {
		sas_by_lspi[i].chain = uu_list_create(lspi_list_pool,
		    NULL, flags);
		sas_by_rhash[i].chain = uu_list_create(rhash_list_pool,
		    NULL, flags);

		if (sas_by_lspi[i].chain == NULL ||
		    sas_by_rhash[i].chain == NULL)
			goto nomem;

		VERIFY(pthread_mutex_init(&sas_by_lspi[i].lock, NULL) == 0);
		VERIFY(pthread_mutex_init(&sas_by_rhash[i].lock, NULL) == 0);
	}

	/* New tables means a new fudge factor.  Pick one randomly. */
	remote_noise = random_low_32();

	i = num_buckets;

	/* Set this so the hash functions work on the new buckets */
	num_buckets = numbuckets;

	if (startup)
		return;

	/* Move IKEv2 SAs to new buckets, work from last bucket to first */
	while (--i >= 0) {
		ikev2_sa_t *i2sa;
		void *cookie;

		cookie = NULL;
		for (i2sa = uu_list_teardown(old_lspi[i].chain, &cookie);
		    i2sa != NULL;
		    i2sa = uu_list_teardown(old_lspi[i].chain, &cookie)) {
			i2sa_add_to_hash(i2sa, B_TRUE);

			/* Remove ref from old hash */
			I2SA_REFRELE(i2sa);
		}

		cookie = NULL;
		for (i2sa = uu_list_teardown(old_rhash[i].chain, &cookie);
		    i2sa != NULL;
		    i2sa = uu_list_teardown(old_rhash[i].chain, &cookie)) {
			i2sa_add_to_hash(i2sa, B_FALSE);

			/* Remove ref from old hash */
			I2SA_REFRELE(i2sa);
		}

		VERIFY(pthread_mutex_destroy(&old_lspi[i].lock) == 0);
		VERIFY(pthread_mutex_destroy(&old_rhash[i].lock) == 0);

		uu_list_destroy(old_lspi[i].chain);
		uu_list_destroy(old_rhash[i].chain);
	}

	free(old_lspi);
	free(old_rhash);

	/* XXX: resume threads */
	return;

nomem:
	if (startup)
		EXIT_FATAL("Exiting due to insufficient memory");

	/* XXX: write msg */

	for (i = 0; i < numbuckets; i++) {
		if (sas_by_lspi[i].chain != NULL)
			uu_list_destroy(sas_by_lspi[i].chain);
		if (sas_by_rhash[i].chain != NULL)
			uu_list_destroy(sas_by_rhash[i].chain);
	}
	free(sas_by_lspi);
	free(sas_by_rhash);
	sas_by_lspi = old_lspi;
	sas_by_rhash = old_rhash;

	/* XXX: resume threads */
}

/*
 * Set the remote SPI of an IKEv2 SA and add to the rhash
 */
void
ikev2_sa_set_rspi(ikev2_sa_t *i2sa, uint64_t rem_spi)
{
	/* better not be set already */
	ASSERT(i2sa->r_spi == 0);

	/* never a valid SPI value */
	ASSERT(r_spi != 0);

	/*
	 * A bit confusing at times, but if we are the initiator of the
	 * SA, the responder (ikev2_sa_t->r_spi) is the remote spi,
	 * otherwise we are the responder, so the remote spi is the
	 * initiator (ikev2_sa_t->i_spi)
	 */
	if (i2sa->flags & I2SA_INITIATOR)
		i2sa->r_spi = rem_spi;
	else
		i2sa->i_spi = rem_spi;

	VERIFY(i2sa_add_to_hash(RHASH, i2sa));
}

static i2sa_bucket_t *
i2sa_get_bucket(int hidx, ikev2_sa_t *i2sa)
{
	i2sa_bucket_t *bucket;

	VERIFY3S(hidx, <, N_HTABLE);

	bucket = hash[hidx];
	switch (hidx) {
	case LSPI:
		bucket += IKEV2_SA_HASH_SPI(I2SA_LOCAL_SPI(i2sa));
		break;
	case RHASH:
		bucket += IKEV2_SA_RHASH(&i2sa->raddr, I2SA_REMOTE_SPI(i2sa));
		break;
	}
	return (bucket);
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
i2sa_add_to_hash(int hidx, ikev2_sa_t *i2sa)
{
	i2sa_bucket_t	*bucket;
	void		*node;
	i2sa_cmp_arg_t	arg;
	uu_list_index_t idx;

	VERIFY3S(hidx, <, N_HTABLE);

	bucket = i2sa_get_bucket(hidx, i2sa);
	VERIFY(pthread_mutex_lock(&bucket->lock) == 0);

	arg.local_hash = local;
	arg.init_pkt = NULL;

	/* Set idx to where the SA should be inserted */
	node = uu_list_find(bucket->chain, i2sa, &arg, &idx);
	if (node != NULL) {
		/*
		 * Found a match, should only happen while choosing
		 * a local SPI value and we happen to pick one already
		 * in use.
		 */

		VERIFY(node != i2sa);
		/*
		 * XXX: Should we do anything different for an rhash
		 * match?
		 */
		VERIFY(pthread_mutex_unlock(&bucket->lock) == 0);
		return (B_FALSE);
	}

	I2SA_REFHOLD(i2sa);	/* ref for chain */

	VERIFY3S(hidx, <, N_HTABLE);
	i2sa->bucket[hidx] = bucket;
	uu_list_insert(bucket->chain, i2sa, idx);
	VERIFY(pthead_mutex_unlock(&bucket->lock) == 0);

	return (B_TRUE);
}

static ikev2_sa_t *
i2sa_verify(ikev2_sa_t *restrict i2sa, uint64_t rem_spi,
    const struct sockaddr_storage *laddr,
    const struct sockaddr_storage *raddr)
{
	if (i2sa == NULL)
		return (NULL);

	if (rem_spi != 0 && I2SA_REMOTE_SPI(i2sa) != rem_spi) {
		/* XXX: log message */
		goto bad_match;
	}

	if (laddr != NULL && !SA_ADDR_EQ(laddr, &i2sa->laddr)) {
		/* XXX: log message */
		goto bad_match;
	}

	if (raddr != NULL && !SA_ADDR_EQ(raddr, &i2sa->raddr)) {
		/* XXX: log message */
		goto bad_match;
	}

        /*
         * XXX KEBE ASKS - if remote port changes, do remap?
         * Probably have caller do this after packet is really legit.
         */

        /* XXX KEBE SAYS FILL IN OTHER REALITY CHECKS HERE. */

	/* XXX: log full match */
	return (i2sa);

bad_match:
	I2SA_REFRELE(i2sa);
	return (NULL);
}

static void
i2sa_hash_remove(int hidx, ikev2_sa_t *i2sa)
{
	i2sa_bucket_t *bucket;

	VERIFY3S(hidx, <, N_HTABLE);
	ASSERT(MUTEX_HELD(i2sa));

	/* We shouldn't be holding the lock if this is the last reference */
	ASSERT(i2sa->refcnt > 1);

	bucket = i2sa_get_bucket(hidx, i2sa);
	VERIFY(pthread_mutex_lock(&bucket->lock) == 0);
	uu_list_remove(bucket->chain, i2sa);
	i2sa->bucket[hidx] = NULL;
	VERIFY(pthread_mutex_unlock(&bucket->lock) == 0);
	I2SA_REFRELE(i2sa);
}

static void
i2sa_unlink(ikev2_sa_t *i2sa)
{
	ASSERT(MUTEX_HELD(i2sa));
	for (int i = 0; i < N_HTABLE; i++)
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

	rc ^= ptr[0];
	rc ^= ptr[1];

	if (ss->ss_family == AF_INET6) {
		const struct sockaddr_sin6 *s6 =
			(const struct sockaddr_sin6 *)ss;

		ptr = (const uint32_t *)s6->sin6_addr;
		rc ^= ptr[0];
		rc ^= ptr[1];
		rc ^= ptr[2];
		rc ^= ptr[3];
	} else {
		const struct sockaddr_sin *s4 =
			(const struct sockaddr_sin *)ss;

		ASSERT(ss->ss_family == AF_INET);
		rc ^= s4->sin_addr.s_addr;
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
	atomic_inc_uint(&half_open);
	/* XXX: todo - cookie check */
}

/*
 * Decrease the count of larval SAs.  Disable cookies if the count falls
 * below the threshold
 */
static void
dec_half_open(void)
{
	atomic_dec_uint(&half_open);

	/*
	 * XXX: add cookie check.  Should have some hysteresis to avoid
	 * flapping.
	 */
}

/*
 * Reset all the fields of an IKEv2 SA.  Used during umem construction, as
 * well as before an SA is returned to the umem cache, per umem requirements.
 */
static void
i2sa_init(ikev2_sa_t *i2sa)
{
	uchar_t *zero_start;
	size_t len;

	zero_start = (uchar_t *)i2sa + I2SA_ZERO_OFFSET;
	(void) memset(zero_start, 0, I2SA_ZERO_LEN);
	i2sa->msgwin = 1;
}

static int
i2sa_ctor(void *buf, void *dummy, int flags)
{
	_NOTE(ARGUNUSUED(dummy, flags))

	ikev2_sa_t *i2sa = (ikev2_sa_t *)&buf;

	VERIFY(pthread_mutex_init(&i2sa->lock, NULL) == 0);
	uu_list_node_init(buf, &i2sa->node_lspi, i2sa_list_pool);
	uu_list_node_fini(buf, &i2sa->node_rhash, i2sa_list_pool);

	i2sa_init(i2sa);
	return (0);
}

static void
i2sa_dtor(void *buf, void *dummy)
{
	_NOTE(ARGUNUSUED(dummy))

	ikev2_sa_t *i2sa = (ikev2_sa_t *)buf;

	VERIFY(pthread_mutex_destroy(&i2sa->lock) == 0);
	uu_list_node_fini(buf, &i2sa->node_lspi, i2sa_list_pool);
	uu_list_node_fini(buf, &i2sa->node_rhash, i2sa_list_pool);
}

static int
sockaddr_compare(const struct sockaddr_storage *restrict l,
    const struct sockaddr_storage *restrict r)
{
	if (l->ss_family > r->ss_family)
		return (1);
	if (l->ss_family < r->ss_family)
		return (-1);

	const struct sockaddr_in *l4 =
		(const struct sockaddr_in *)l;
	const struct sockaddr_in *r4 =
		(const struct sockaddr_in *)r;
	int cmp;

	if (l->ss_family == AF_INET) {
		cmp = memcmp(l4->sin_addr, r4->sin_addr, XX);
		if (cmp > 0)
			return (1);
		if (cmp < 0)
			return (-1);
	} else {
		const struct sockaddr_in6 *l6 =
			(const struct sockaddr_in6 *)l;
		const struct sockaddr_in6 *r6 =
			(const struct sockaddr_in6 *)r;

		cmp = memcmp(l6->sin6_addr, r6->sin6_addr, XX);

		if (cmp > 0)
			return (1);
		if (cmp < 0)
			return (-1);
	}

	/* the port is stored in the same offset for both IPv4 and IPv6 */
	if (l4->sin_port > r4->sin_port)
		return (1);
	if (l4->sin_port < r4->sin_port)
		return (-1);

	return (0);
}

static int
i2sa_compare(void *larg, void *rarg, void *arg)
{
	ikev2_sa_t *l = (ikev2_sa_t *)larg;
	ikev2_sa_t *r = (ikev2_sa_t *)rarg;
	i2sa_cmp_arg_t *cmp = (i2sa_cmp_arg_t *)arg;

	if (arg->local_hash) {
		/*
		 * Since we assign the local SPI, we enforce that
		 * they are globally unique
		 */
		ASSERT(l->bucket_lock_lspi == r->bucket_lock_spi);
		ASSERT(MUTEX_HELD(l->bucket_lock_spi));

		if (I2SA_LOCAL_SPI(l) > I2SA_LOCAL_SPI(r))
			return (1);
		if (I2SA_LOCAL_SPI(l) > I2SA_LOCAL_SPI(r))
			return (-1);
		return (0);
	}

	ASSERT(l->bucket_lock_rhash == r->bucket_lock_rhash);
	ASSERT(MUTEX_HELD(l->bucket_lock_rhash));

	if (I2SA_REMOTE_SPI(l) > I2SA_REMOTE_SPI(r))
		return (1);
	if (I2SA_REMOTE_SPI(l) < I2SA_REMOTE_SPI(r))
		return (-1);

	int cmp;

	/* more likely to be different, so check these first */
	cmp = sockaddr_compare(l->raddr, r->raddr);
	if (cmp > 0)
		return (1);
	if (cmp < 0)
		return (-1);

	/* a multihomed system might have different local addresses */
        cmp = sockaddr_compare(l->laddr, r->addr);
	if (cmp > 0)
		return (1);
	if (cmp < 0)
		return (-1);

	/*
	 * RFC5996 2.1 - We cannot merely rely on the remote SPI and
	 * address as clients behind NATs might choose the same SPI by chance.
	 * We must in addition look at the initial packet.  This is only
	 * an issue for half-opened remotely initiated SAs, as this the
	 * only time the local SPI is not yet known.
	 */

	/* XXX: complete me!! */

	/* NOTE: If we are comparing against a 'reference' ikev2_sa_t
	 * (e.g. we are searching for a specific IKEv2 SA and not
	 * an insertion location), arg->init_pkt will not be NULL.
	 */

	return (0);
}

void
ikev2_sa_init(void)
{
	uint32_t flag = UU_LIST_SORTED;

	VERIFY((i2sa_cache = umem_cache_create("IKEv2 SAs",
	    sizeof (ikev2_sa_t), i2sa_ctor, i2sa_dtor, NULL, NULL, NULL,
	    0)) != NULL);

#ifdef DEBUG
	flag |= UU_LIST_POOL_DEBUG;
#endif

	VERIFY((lspi_list_pool = 
	    uu_list_pool_create("IKEv2 local SPI hash chains",
	    sizeof (ikev2_sa_t), offsetof(ikev2_sa_t, node_lspi),
	    i2sa_compare, flag)) != NULL);

	VERIFY((rhash_list_pool =
	    uu_list_pool_create("IKEv2 remote SPI hash chains",
	    sizeof (ikev2_sa_t), offsetof(ikev2_sa_t, node_rash),
	    i2sa_compare, flag)) != NULL);
}

void
ikev2_sa_fini(void)
{
	umem_cache_destroy(i2sa_cache);
	uu_list_pool_destroy(lspi_list_pool);
	uu_list_pool_destroy(rhash_list_pool);
}

