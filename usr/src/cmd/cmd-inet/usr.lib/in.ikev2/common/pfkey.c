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
#include <alloca.h>
#include <arpa/inet.h>
#include <atomic.h>
#include <bunyan.h>
#include <errno.h>
#include <locale.h>
#include <note.h>
#include <sys/list.h>
#include <sys/types.h>
#include <sys/stropts.h>	/* For I_NREAD */
#include <sys/sysmacros.h>
#include <ipsec_util.h>
#include <netdb.h>
#include <netinet/in.h>
#include <net/pfkeyv2.h>
#include <port.h>
#include <stdio.h>
#include <string.h>
#include <synch.h>
#include <time.h>
#include "config.h"
#include "defs.h"
#include "ikev2.h"
#include "ikev2_common.h"
#include "ikev2_pkt.h"
#include "ikev2_sa.h"
#include "inbound.h"
#include "pfkey.h"
#include "pkcs11.h"
#include "worker.h"

/*
 * pf_key(7P) operates by exchanging messages over a special socket (creatively
 * named pfkey in this file).  Our model is that worker threads that need to
 * interact with the kernel's SADB via pfkey will create the appropriate
 * message, and then use pfkey_send_msg() to send it to the kernel and receive
 * it's response (or an error).  In the background there is a (currently)
 * single dedicated thread for receiving pf_key(7P) messages from the kernel.
 * This thread will match up replies with the requests sent via pfkey_send_msg()
 * to determine the correct worker to wake up (as pfkey_send_msg() will block
 * via a CV until it has either received a reply or has timed out).  Since
 * pf_key(7P) is message and not stream based, once the socket is readable,
 * (a dedicated event port waiting on a POLLIN event is used for this), the
 * pfkey thread itself should never be blocked waiting for I/O.
 *
 * The kernel typically replies to a request within milliseconds,
 * however certain operations (e.g. DUMP) can delay replies.  To prevent
 * callers from possibly blocking forever (in case a reply was somehow missed,
 * or dropped), a timeout is defined that should be long enough for any DUMP
 * operation to complete.  Any request that takes longer than this should be
 * considered failed by the caller.
 *
 * The current timeout value is a guess, and might need to be adjusted based
 * on live experience.
 */
#define	PFKEY_TIMEOUT	5	/* in seconds */

#define	PFKEY_K_SRCADDR	"sadb_src_addr"
#define	PFKEY_K_DSTADDR	"sadb_dst_addr"
#define	PFKEY_K_ISRCADDR "sadb_inner_src_addr"
#define	PFKEY_K_IDSTADDR "sadb_inner_dst_addr"
#define	PFKEY_K_NLOC "sadb_natt_loc"
#define	PFKEY_K_NREM "sadb_natt_rem"
#define	PFKEY_K_SPI "sadb_sa_spi"
#define	PFKEY_K_AUTH "sadb_sa_auth"
#define	PFKEY_K_ENCR "sadb_sa_encr"
#define	PFKEY_K_PORT "_port"
#define	PFKEY_K_PAIR "sadb_pair_spi"

static const char *pfkey_keys[] = {
	PFKEY_K_SRCADDR,
	PFKEY_K_DSTADDR,
	PFKEY_K_ISRCADDR,
	PFKEY_K_IDSTADDR,
	PFKEY_K_NLOC,
	PFKEY_K_NREM,
	PFKEY_K_SRCADDR PFKEY_K_PORT,
	PFKEY_K_DSTADDR PFKEY_K_PORT,
	PFKEY_K_ISRCADDR PFKEY_K_PORT,
	PFKEY_K_IDSTADDR PFKEY_K_PORT,
	PFKEY_K_NLOC PFKEY_K_PORT,
	PFKEY_K_NREM PFKEY_K_PORT,
	PFKEY_K_AUTH,
	PFKEY_K_ENCR,
	PFKEY_K_SPI,
	PFKEY_K_PAIR,
};

#define	PFKEY_MSG_LEN(msg, ext) \
    SADB_8TO64((size_t)((uint8_t *)ext - (uint8_t *)msg))

typedef struct pfreq {
	list_node_t	pr_node;
	uint32_t	pr_msgid;
	mutex_t		pr_lock;
	cond_t		pr_cv;
	sadb_msg_t	*pr_msg;
	boolean_t	pr_recv;
} pfreq_t;

/* pfreq lock protects pfreq_list */
static mutex_t	pfreq_lock = ERRORCHECKMUTEX;
static list_t	pfreq_list;

/* PF_KEY socket. */
static int pfsock;

/* our event port */
static int pfport;

static thread_t pftid;

/* our msgids */
static volatile uint32_t msgid = 0;

static void handle_reply(sadb_msg_t *);
static void handle_delete(sadb_msg_t *);
static void handle_flush(sadb_msg_t *);
static void handle_expire(sadb_msg_t *);
static void handle_acquire(sadb_msg_t *, boolean_t);
static void handle_register(sadb_msg_t *);

int ikev2_auth_to_pfkey(ikev2_xf_auth_t);
int ikev2_encr_to_pfkey(ikev2_xf_encr_t);

/* Deal with algorithm name lookups */

static const char *
alg_to_string(int doi_number, const algindex_t *algindex)
{
	int i;

	for (i = 0; algindex[i].desc; i++)
		if (doi_number == algindex[i].doi_num)
			return (algindex[i].desc);
	return ("unknown");
}

char *
kef_alg_to_string(int algnum, int protonum, char *algname)
{
	struct ipsecalgent *testentry;
	int error;

	testentry = getipsecalgbynum(algnum, protonum, &error);
	if (testentry == NULL || testentry->a_names[0] == NULL)
		(void) snprintf(algname, 80, "unknown");
	else
		(void) snprintf(algname, 80, "%s", testentry->a_names[0]);

	/* safe to use on a NULL pointer */
	(void) freeipsecalgent(testentry);
	return (algname);
}

/*
 * The passed in parsedmsg_t looks like this (see defs.h):
 *
 * {
 *	*pmsg_next
 *	*pmsg_samsg
 *	*pmsg_exts[0][1][2][3].....[SADB_EXT_MAX + 2]
 *	*pmsg_sss  (struct sockaddr_storage *)
 *	*pmsg_dss  (struct sockaddr_storage *)
 *	*pmsg_isss (struct sockaddr_storage *)
 *	*pmsg_idss (struct sockaddr_storage *)
 *	*pmsg_nlss (struct sockaddr_storage *)
 *	*pmsg_nrss (struct sockaddr_storage *)
 * } parsedmsg_t;
 *
 * This function parses through the whole samsg looking for valid PF_KEY
 * extensions. Each extension type found is saved in the pmsg_exts array.
 * As the parsedmsg_t is initialised as zero's when entering the function, it's
 * easy to check later to see which extensions exist in the samsg by
 * checking for NULL.
 *
 * Some extensions will have a sockaddr_storage associated with the type
 * EG: SADB_EXT_ADDRESS_SRC, in these cases a pointer to the appropriate
 * structure in samsg is set in the parsedmsg_t.
 *
 * After parsing the whole samsg, the optional arguments (which is a list
 * of required extensions) are checked for in the parsedmsg_t. If all of the
 * required extensions are valid then the function returns B_TRUE.
 *
 * Even if the required extensions are not in the samsg (and the function
 * returns B_FALSE) the pmsg->pmsg_exts array will still contain the headers
 * that were in the samsg.
 *
 * Assume the kernel knows what it's doing with messages that get passed up.
 * The variable arguments are a list of ints with SADB_EXT_* values.
 */
static boolean_t
vextract_exts(sadb_msg_t *samsg, parsedmsg_t *pmsg, int numexts, va_list ap)
{
	sadb_ext_t *ext, *end;
	sadb_ext_t **exts = pmsg->pmsg_exts;
	int current_ext;
	boolean_t rc = B_TRUE;

	(void) memset(pmsg, 0, sizeof (parsedmsg_t));

	end = (sadb_ext_t *)(((uint64_t *)samsg) + samsg->sadb_msg_len);
	ext = (sadb_ext_t *)(samsg + 1);
	pmsg->pmsg_samsg = samsg;

	while (ext < end) {
		exts[ext->sadb_ext_type] = ext;
		if (ext->sadb_ext_type == SADB_EXT_ADDRESS_SRC)
			pmsg->pmsg_sss = (struct sockaddr_storage *)
			    (((sadb_address_t *)ext) + 1);
		if (ext->sadb_ext_type == SADB_EXT_ADDRESS_DST)
			pmsg->pmsg_dss = (struct sockaddr_storage *)
			    (((sadb_address_t *)ext) + 1);
		if (ext->sadb_ext_type == SADB_X_EXT_ADDRESS_INNER_SRC)
			pmsg->pmsg_isss = (struct sockaddr_storage *)
			    (((sadb_address_t *)ext) + 1);
		if (ext->sadb_ext_type == SADB_X_EXT_ADDRESS_INNER_DST)
			pmsg->pmsg_idss = (struct sockaddr_storage *)
			    (((sadb_address_t *)ext) + 1);
		if (ext->sadb_ext_type == SADB_X_EXT_ADDRESS_NATT_REM)
			pmsg->pmsg_nrss = (struct sockaddr_storage *)
			    (((sadb_address_t *)ext) + 1);
		if (ext->sadb_ext_type == SADB_X_EXT_ADDRESS_NATT_LOC)
			pmsg->pmsg_nlss = (struct sockaddr_storage *)
			    (((sadb_address_t *)ext) + 1);

		ext = (sadb_ext_t *)(((uint64_t *)ext) + ext->sadb_ext_len);

	}

	while (numexts-- > 0) {
		current_ext = va_arg(ap, int);
		if (exts[current_ext] == NULL) {
			rc = B_FALSE;
			break;
		}
	}

	return (rc);
}

static boolean_t
extract_exts(sadb_msg_t *samsg, parsedmsg_t *pmsg, int numexts, ...)
{
	va_list ap;
	boolean_t ret;

	va_start(ap, numexts);
	ret = vextract_exts(samsg, pmsg, numexts, ap);
	va_end(ap);
	return (ret);
}

static void
pfkey_arm(int s)
{
	/* At this point, we can safely re-schedule the socket for reading. */
	if (port_associate(pfport, PORT_SOURCE_FD, s, POLLIN, NULL) < 0) {
		STDERR(error, "port_associate() failed",
		    BUNYAN_T_INT32, "fd", (int32_t)s, BUNYAN_T_END);
		exit(EXIT_FAILURE);
	}
}

static void
pfkey_inbound(int s)
{
	sadb_msg_t *samsg;
	ssize_t rc;
	int length;

	if (ioctl(s, I_NREAD, &length) < 0) {
		STDERR(error, "ioctl(I_NREAD) failed");
		pfkey_arm(s);
		return;
	}

	if (length == 0) {
		(void) bunyan_info(log, "ioctl: zero length message",
		    BUNYAN_T_STRING, LOG_KEY_FUNC, __func__,
		    BUNYAN_T_STRING, LOG_KEY_FILE, __FILE__,
		    BUNYAN_T_INT32, LOG_KEY_LINE, __LINE__,
		    BUNYAN_T_END);
		pfkey_arm(s);
		return;
	}

	samsg = malloc(length);
	if (samsg == NULL) {
		(void) bunyan_error(log, "No memory for pfkey message",
		    BUNYAN_T_END);
		pfkey_arm(s);
		return;
	}

	rc = read(s, samsg, length);
	if (rc <= 0) {
		if (rc == -1) {
			STDERR(error, "read failed");
			/* XXX: Should I exit()? */
		}
		free(samsg);
		pfkey_arm(s);
		return;
	}

	/* At this point, we can safely re-schedule the socket for reading. */
	pfkey_arm(s);

	sadb_log(BUNYAN_L_DEBUG, "SADB message received", samsg);

	/*
	 * XXX KEBE SAYS for now don't print the full inbound message.  An
	 * "ipseckey monitor" instance is useful here.
	 */

	/*
	 * If it might be a reply to us, handle it.
	 */
	if (samsg->sadb_msg_pid == getpid()) {
		handle_reply(samsg);
		return;
	}

	/*
	 * Silently pitch the message if it's an error reply to someone else.
	 */
	if (samsg->sadb_msg_errno != 0) {
		(void) bunyan_debug(log, "Reply not for us, dropped",
		    BUNYAN_T_END);
		free(samsg);
		return;
	}

	/*
	 * At this point, we have a kernel-emitted message.  Typically this
	 * will be an ACQUIRE, EXPIRE, or DELETE/DELPAIR.  Other ones include
	 * FLUSH (which if we follow in.iked semantics, will nuke all IKE SA
	 * state) and REGISTER (indicating a change in kernel algorithm
	 * support).
	 */

	switch (samsg->sadb_msg_type) {
	case SADB_ACQUIRE:
		handle_acquire(samsg, B_TRUE);
		return;
	case SADB_EXPIRE:
		handle_expire(samsg);
		return;
	case SADB_DELETE:
	case SADB_X_DELPAIR:
		handle_delete(samsg);
		return;
	case SADB_FLUSH:
		handle_flush(samsg);
		return;
	case SADB_REGISTER:
		handle_register(samsg);
		/*
		 * Explicitly free it here because handle_register() is also
		 * called from pfkey_init(), which has samsg on the stack
		 * instead.
		 */
		free(samsg);
		return;
	}

	(void) bunyan_debug(log, "SADB message type unknown, ignored.",
	    BUNYAN_T_UINT32, "msg_type_val", (uint32_t)samsg->sadb_msg_type,
	    BUNYAN_T_END);
	free(samsg);
}

/*
 * Send an sadb message to pfkey.  The response is allocated and placed into
 * *pmsg.  Optionally, a list of extensions can be given.  Returns B_TRUE
 * is message was successful and any expected extensions passed in are
 * present.  This function should only be called by threads in the worker
 * pool.  It will sleep until a response is received by a pfkey thread and
 * is then woken up by the pfkey thread.
 *
 * On failure, B_FALSE is returned, however there are two distinct
 * possibilities to check:
 *
 * 1. Pfkey error
 *	If there was some problem with the request itself, the kernel may send
 *	a response with sadb_msg_errno and possible sadb_x_msg_diagnostic set.
 *	As this may be useful to the caller, if this occurs, *pmsg is still
 *	allocated.  It may or may not include any of the expected or passed in
 *	extensions.
 * 2. System error
 *	If there was a problem allocated the response or in sending the
 *	message (i.e. write(2) failure), *pmsg will be NULL and errno
 *	should be set by the failing function.
 */
boolean_t
pfkey_send_msg(sadb_msg_t *msg, parsedmsg_t **pmsg, int numexts, ...)
{
	pfreq_t req = { 0 };
	size_t len = SADB_64TO8(msg->sadb_msg_len);
	ssize_t n;
	int rc;
	timestruc_t amt;
	va_list ap;
	boolean_t ret = B_TRUE;

	VERIFY(IS_WORKER);

	if ((*pmsg = malloc(sizeof (parsedmsg_t))) == NULL)
		return (B_FALSE);

	VERIFY0(cond_init(&req.pr_cv, USYNC_THREAD, NULL));
	VERIFY0(mutex_init(&req.pr_lock, USYNC_THREAD|LOCK_ERRORCHECK, NULL));
	req.pr_msgid = msg->sadb_msg_seq;

	mutex_enter(&pfreq_lock);
	list_insert_tail(&pfreq_list, &req);
	mutex_exit(&pfreq_lock);

	sadb_log(BUNYAN_L_TRACE, "Sending pfkey request", msg);

	n = write(pfsock, msg, len);
	if (n != len) {
		if (n < 0) {
			STDERR(error, "pf_key write failed");
		} else {
			(void) bunyan_error(log,
			    "pf_key truncated write",
			    BUNYAN_T_UINT32, "len", len,
			    BUNYAN_T_INT32, "n", (int32_t)n,
			    BUNYAN_T_END);
		}

		mutex_enter(&pfreq_lock);
		list_remove(&pfreq_list, &req);
		mutex_exit(&pfreq_lock);
		ret = B_FALSE;
		goto done;
	}

	amt.tv_sec = time(NULL) + PFKEY_TIMEOUT;
	amt.tv_nsec = 0;

	mutex_enter(&req.pr_lock);
	while (!req.pr_recv) {
		rc = cond_timedwait(&req.pr_cv, &req.pr_lock, &amt);
		mutex_exit(&req.pr_lock);

		switch (rc) {
		case 0:
		case EINTR:
			continue;
		case ETIME:
			free(*pmsg);
			*pmsg = NULL;
			bunyan_error(log, "pf_key timeout",
			    BUNYAN_T_UINT32, "msgid", req.pr_msgid,
			    BUNYAN_T_END);

			errno = ETIME;
			ret = B_FALSE;
			goto done;
		default:
			TSTDERR(rc, fatal,
			    "cond_timedwait() unexpected failure");
			abort();
		}
	}

	va_start(ap, numexts);
	ret = vextract_exts(req.pr_msg, *pmsg, numexts, ap);
	va_end(ap);

done:
	mutex_destroy(&req.pr_lock);
	cond_destroy(&req.pr_cv);
	return (ret);
}

void
pfkey_msg_init(const sadb_msg_t *restrict src, sadb_msg_t *restrict samsg,
    uint8_t type, uint8_t satype)
{
	samsg->sadb_msg_version = PF_KEY_V2;
	samsg->sadb_msg_type = type;
	samsg->sadb_msg_errno = 0;
	samsg->sadb_msg_satype = satype;
	samsg->sadb_msg_len = SADB_8TO64(sizeof (*samsg));
	samsg->sadb_msg_reserved = 0;
	if (src != NULL) {
		samsg->sadb_msg_seq = src->sadb_msg_seq;
		samsg->sadb_msg_pid = src->sadb_msg_pid;
	} else {
		samsg->sadb_msg_seq = atomic_inc_32_nv(&msgid);
		samsg->sadb_msg_pid = getpid();
	}
}

/*
 * Inform the kernel of an error.
 * src is the pfkey message the error is a response to, reason is
 * the reason for the error
 */
void
pfkey_send_error(const sadb_msg_t *src, uint8_t reason)
{
	sadb_msg_t msg = { 0 };
	ssize_t n;

	/* Errors consists of just the sadb header */
	pfkey_msg_init(src, &msg, src->sadb_msg_type, src->sadb_msg_satype);
	msg.sadb_msg_errno = reason;

	n = write(pfsock, &msg, sizeof (sadb_msg_t));
	if (n != sizeof (sadb_msg_t))
		STDERR(error, "Unable to send PFKEY error notification");
}

/*
 * Add an sadb_address_t extension to a pfkey message.  Caller must fill
 * in SADB address type (SRC, INNER_DST, etc.).  Caller must guarantee memory
 * pointed to by saaddr is sufficiently large to hold sadb_address_t + the
 * actual address.
 *
 * Returns total size of extension (in bytes) -- sadb_address_t and actual
 * address.  It also sets *endp to just after the end of the address (i.e.
 * where the next extension would go).
 */
sadb_ext_t *
pfkey_add_address(sadb_ext_t *restrict ext, uint16_t type,
    const sockaddr_u_t su)
{
	sadb_address_t *addr = (sadb_address_t *)ext;
	sockaddr_u_t msgaddr = {
		.sau_ss = (struct sockaddr_storage *)(addr + 1)
	};
	size_t len = 0;

	switch (type) {
	case SADB_EXT_ADDRESS_SRC:
	case SADB_EXT_ADDRESS_DST:
	case SADB_X_EXT_ADDRESS_NATT_LOC:
	case SADB_X_EXT_ADDRESS_NATT_REM:
	case SADB_X_EXT_ADDRESS_INNER_SRC:
	case SADB_X_EXT_ADDRESS_INNER_DST:
		break;
	default:
		INVALID(type);
	}

	if (su.sau_ss == NULL)
		return (ext);

	switch (su.sau_ss->ss_family) {
	case AF_INET:
		(void) memcpy(msgaddr.sau_sin, su.sau_sin,
		    sizeof (struct sockaddr_in));
		len = P2ROUNDUP(sizeof (struct sockaddr_in),
		    sizeof (uint64_t));
		break;
	case AF_INET6:
		(void) memcpy(msgaddr.sau_sin6, su.sau_sin6,
		    sizeof (struct sockaddr_in6));
		len = P2ROUNDUP(sizeof (struct sockaddr_in6),
		    sizeof (uint64_t));
		break;
	default:
		INVALID(su.sau_ss->ss_family);
	}

	len += sizeof (*addr);
	addr->sadb_address_len = SADB_8TO64(len);
	addr->sadb_address_exttype = type;

	/*XXX:FIXME*/
	addr->sadb_address_prefixlen = 32;

	return ((sadb_ext_t *)((uint8_t *)ext + len));
}

sadb_ext_t *
pfkey_add_sa(sadb_ext_t *restrict ext, uint32_t spi,
    const ikev2_sa_result_t *restrict res)
{
	sadb_sa_t *sa = (sadb_sa_t *)ext;
	int auth = ikev2_auth_to_pfkey(res->sar_auth);
	int encr = ikev2_encr_to_pfkey(res->sar_encr);

	/* We shouldn't negotiate anything we don't support */
	VERIFY3S(auth, >=, 0);
	VERIFY3S(encr, >=, 0);

	sa->sadb_sa_len = SADB_8TO64(sizeof (*sa));
	sa->sadb_sa_exttype = SADB_EXT_SA;
	sa->sadb_sa_spi = spi;
	sa->sadb_sa_auth = (uint8_t)auth;
	sa->sadb_sa_encrypt = (uint8_t)encr;
	return ((sadb_ext_t *)(sa + 1));
}

sadb_ext_t *
pfkey_add_range(sadb_ext_t *restrict ext, uint32_t min, uint32_t max)
{
	sadb_spirange_t *r = (sadb_spirange_t *)ext;

	r->sadb_spirange_len = SADB_8TO64(sizeof (*r));
	r->sadb_spirange_exttype = SADB_EXT_SPIRANGE;
	r->sadb_spirange_min = min;
	r->sadb_spirange_max = max;
	return ((sadb_ext_t *)(r + 1));
}

sadb_ext_t *
pfkey_add_identity(sadb_ext_t *restrict ext, uint16_t type,
    const config_id_t *cid)
{
	sadb_ident_t *id = (sadb_ident_t *)ext;
	size_t len = sizeof (*id) +
	    P2ROUNDUP(config_id_strlen(cid), sizeof (uint64_t));

	switch (type) {
	case SADB_EXT_IDENTITY_SRC:
	case SADB_EXT_IDENTITY_DST:
		id->sadb_ident_exttype = type;
		break;
	default:
		INVALID(type);
	}

	id->sadb_ident_len = SADB_8TO64(len);

	switch (cid->cid_type) {
	case CFG_AUTH_ID_DN:
		id->sadb_ident_type = SADB_X_IDENTTYPE_DN;
		break;
	case CFG_AUTH_ID_DNS:
		id->sadb_ident_type = SADB_IDENTTYPE_FQDN;
		break;
	case CFG_AUTH_ID_GN:
		id->sadb_ident_type = SADB_X_IDENTTYPE_GN;
		break;
	case CFG_AUTH_ID_IPV4:
	case CFG_AUTH_ID_IPV4_RANGE:
	case CFG_AUTH_ID_IPV6:
	case CFG_AUTH_ID_IPV6_RANGE:
		id->sadb_ident_type = SADB_X_IDENTTYPE_ADDR_RANGE;
		break;
	case CFG_AUTH_ID_IPV4_PREFIX:
	case CFG_AUTH_ID_IPV6_PREFIX:
		id->sadb_ident_type = SADB_IDENTTYPE_PREFIX;
		break;
	case CFG_AUTH_ID_EMAIL:
		id->sadb_ident_type = SADB_IDENTTYPE_USER_FQDN;
		break;
	}

	id->sadb_ident_len = SADB_8TO64(len);
	(void) config_id_str(cid, (char *)(id + 1), len);

	return ((sadb_ext_t *)((uint8_t *)ext + len));
}

sadb_ext_t *
pfkey_add_key(sadb_ext_t *restrict ext, uint16_t type, const uint8_t *key,
    size_t keylen)
{
	sadb_key_t *skey = (sadb_key_t *)ext;
	size_t len = sizeof (sadb_key_t) +
	    P2ROUNDUP(keylen, sizeof (uint64_t));

	switch (type) {
	case SADB_EXT_KEY_AUTH:
	case SADB_EXT_KEY_ENCRYPT:
		break;
	default:
		INVALID(type);
	}

	skey->sadb_key_len = SADB_8TO64(len);
	skey->sadb_key_exttype = type;
	skey->sadb_key_bits = SADB_8TO1(keylen);
	(void) memcpy(skey + 1, key, keylen);
	return ((sadb_ext_t *)((uint8_t *)ext + len));
}

sadb_ext_t *
pfkey_add_pair(sadb_ext_t *ext, uint32_t spi)
{
	sadb_x_pair_t *pair = (sadb_x_pair_t *)ext;

	pair->sadb_x_pair_len = SADB_8TO64(sizeof (*pair));
	pair->sadb_x_pair_exttype = SADB_X_EXT_PAIR;
	pair->sadb_x_pair_spi = spi;
	return ((sadb_ext_t *)(pair + 1));
}

sadb_ext_t *
pfkey_add_lifetime(sadb_ext_t *restrict ext)
{
	config_t *cfg = config_get();
	sadb_lifetime_t *life = (sadb_lifetime_t *)ext;

	if (cfg->cfg_p2_lifetime_secs > 0 ||
	    cfg->cfg_p2_lifetime_kb > 0) {
		life->sadb_lifetime_len = SADB_8TO64(sizeof (*life));
		life->sadb_lifetime_exttype = SADB_EXT_LIFETIME_HARD;
		life->sadb_lifetime_addtime = cfg->cfg_p2_lifetime_secs;
		life->sadb_lifetime_bytes = cfg->cfg_p2_lifetime_kb * 1024;
		life++;
	}

	if (cfg->cfg_p2_softlife_secs > 0 ||
	    cfg->cfg_p2_softlife_kb > 0) {
		life->sadb_lifetime_len = SADB_8TO64(sizeof (*life));
		life->sadb_lifetime_exttype = SADB_EXT_LIFETIME_SOFT;
		life->sadb_lifetime_addtime = cfg->cfg_p2_softlife_secs;
		life->sadb_lifetime_bytes = cfg->cfg_p2_softlife_kb * 1024;
		life++;
	}

	if (cfg->cfg_p2_idletime_secs > 0) {
		life->sadb_lifetime_len = SADB_8TO64(sizeof (*life));
		life->sadb_lifetime_exttype = SADB_X_EXT_LIFETIME_IDLE;
		life->sadb_lifetime_addtime = cfg->cfg_p2_idletime_secs;
		life++;
	}

	CONFIG_REFRELE(cfg);
	return ((sadb_ext_t *)life);
}

boolean_t
pfkey_sadb_add_update(const ikev2_sa_t *restrict sa, uint32_t spi,
    const ikev2_sa_result_t *restrict sar, const parsedmsg_t *restrict srcmsg,
    const uint8_t *encrkey, size_t encrlen,
    const uint8_t *authkey, size_t authlen,
    uint32_t pair, boolean_t initiator, boolean_t add)
{
	const sadb_msg_t *sadb_src = NULL;
	parsedmsg_t *pmsg = NULL;
	sadb_msg_t *msg = NULL;
	sadb_ext_t *ext = NULL;
	sadb_sa_t *pfsa = NULL;
	size_t msglen = 0;
	uint8_t satype;
	boolean_t ret = B_FALSE;

	/*
	 * Worst case msg length:
	 *	base, SA, lifetime(HSI), address(SD), address(Is, Id),
	 *	address(Nl, Nr), key(AE), identity(SD), pair
	 *
	 * The sadb_* types are already including padding for 64-bit alignment.
	 */
	msglen = sizeof (*msg) + sizeof (sadb_sa_t) +
	    3 * sizeof (sadb_lifetime_t) +
	    6 * (sizeof (sadb_address_t) + sizeof (struct sockaddr_storage)) +
	    sizeof (sadb_key_t) +
	    P2ROUNDUP(SADB_8TO1(encrlen), sizeof (uint64_t)) +
	    sizeof (sadb_key_t) +
	    P2ROUNDUP(SADB_8TO1(authlen), sizeof (uint64_t)) +
	    sizeof (sadb_ident_t) +
	    P2ROUNDUP(config_id_strlen(sa->local_id), sizeof (uint64_t)) +
	    sizeof (sadb_ident_t) +
	    P2ROUNDUP(config_id_strlen(sa->remote_id), sizeof (uint64_t)) +
	    sizeof (sadb_x_pair_t);

	msg = umem_zalloc(msglen, UMEM_DEFAULT);
	if (msg == NULL) {
		(void) bunyan_error(log, "No memory for pfkey request",
		    BUNYAN_T_END);
		return (B_FALSE);
	}

	if (PMSG_FROM_KERNEL(srcmsg))
		sadb_src = srcmsg->pmsg_samsg;

	satype = ikev2_to_satype(sar->sar_proto);
	pfkey_msg_init(sadb_src, msg, add ? SADB_ADD : SADB_UPDATE, satype);

	ext = (sadb_ext_t *)(msg + 1);
	pfsa = (sadb_sa_t *)ext;
	ext = pfkey_add_sa(ext, spi, sar);
	ext = pfkey_add_lifetime(ext);

	/*
	 * XXX:It's implied that the larval SA we created with GETSPI is the one
	 * we update (thus the source is always the 'local' address).
	 * I'd like to find a better way to express this intent more clearly
	 */
	if (!add) {
		pfsa->sadb_sa_flags |= SADB_X_SAFLAGS_OUTBOUND;

		ext = pfkey_add_address(ext, SADB_EXT_ADDRESS_SRC,
		    srcmsg->pmsg_sau);
		ext = pfkey_add_address(ext, SADB_EXT_ADDRESS_DST,
		    srcmsg->pmsg_dau);
		ext = pfkey_add_address(ext, SADB_X_EXT_ADDRESS_INNER_SRC,
		    srcmsg->pmsg_isau);
		ext = pfkey_add_address(ext, SADB_X_EXT_ADDRESS_INNER_DST,
		    srcmsg->pmsg_idau);
	} else {
		pfsa->sadb_sa_flags |= SADB_X_SAFLAGS_INBOUND;

		ext = pfkey_add_address(ext, SADB_EXT_ADDRESS_SRC,
		    srcmsg->pmsg_dau);
		ext = pfkey_add_address(ext, SADB_EXT_ADDRESS_DST,
		    srcmsg->pmsg_sau);
		ext = pfkey_add_address(ext, SADB_X_EXT_ADDRESS_INNER_SRC,
		    srcmsg->pmsg_idau);
		ext = pfkey_add_address(ext, SADB_X_EXT_ADDRESS_INNER_DST,
		    srcmsg->pmsg_isau);
	}

	ext = pfkey_add_address(ext, SADB_X_EXT_ADDRESS_NATT_LOC,
	    srcmsg->pmsg_nlau);
	ext = pfkey_add_address(ext, SADB_X_EXT_ADDRESS_NATT_REM,
	    srcmsg->pmsg_nrau);

	if (srcmsg->pmsg_nlau.sau_ss != NULL)
		pfsa->sadb_sa_flags |= SADB_X_SAFLAGS_NATT_LOC;
	if (srcmsg->pmsg_nrau.sau_ss != NULL)
		pfsa->sadb_sa_flags |= SADB_X_SAFLAGS_NATT_REM;

	pfsa->sadb_sa_state = SADB_SASTATE_MATURE;

	if (authkey != NULL)
		ext = pfkey_add_key(ext, SADB_EXT_KEY_AUTH, authkey, authlen);
	if (encrkey != NULL) {
		ext = pfkey_add_key(ext, SADB_EXT_KEY_ENCRYPT, encrkey,
		    encrlen);
	}

	ext = pfkey_add_identity(ext, SADB_EXT_IDENTITY_SRC,
	    (initiator && !add) ? sa->local_id : sa->remote_id);
	ext = pfkey_add_identity(ext, SADB_EXT_IDENTITY_DST,
	    (initiator && !add) ? sa->remote_id : sa->local_id);

	if (pair != 0)
		ext = pfkey_add_pair(ext, pair);

	VERIFY(IS_P2ALIGNED(ext, sizeof (uint64_t)));
	msg->sadb_msg_len = PFKEY_MSG_LEN(msg, ext);

	if (!pfkey_send_msg(msg, &pmsg, 1, SADB_EXT_SA) ||
	    pmsg->pmsg_samsg == NULL) {
		parsedmsg_free(pmsg);
		umem_free(msg, msglen);
		return (B_FALSE);
	}

	if (pmsg->pmsg_samsg->sadb_msg_errno != 0) {
		sadb_msg_t *m = pmsg->pmsg_samsg;

		TSTDERR(m->sadb_msg_errno, error,
		    "SADB_ADD failed",
		    BUNYAN_T_STRING, "diagmsg",
		    keysock_diag(m->sadb_x_msg_diagnostic),
		    BUNYAN_T_UINT32, "diagcode",
		    (uint32_t)m->sadb_x_msg_diagnostic);
	} else {
		pfsa = (sadb_sa_t *)pmsg->pmsg_exts[SADB_EXT_SA];
		char type[64] = { 0 };
		char spistr[11] = { 0 }; /* 0x + 32bit hix + NUL */

		(void) sadb_type_str(pmsg->pmsg_samsg->sadb_msg_type, type,
		    sizeof (type));
		(void) snprintf(spistr, sizeof (spistr), "0x%" PRIX32,
		    pfsa->sadb_sa_spi);

		(void) bunyan_debug(log, "Added IPsec SA",
		    BUNYAN_T_STRING, "satype", type,
		    BUNYAN_T_STRING, "spi", spistr,
		    BUNYAN_T_END);

		ret = B_TRUE;
	}

	umem_free(msg, msglen);
	parsedmsg_free(pmsg);
	return (ret);
}

boolean_t
pfkey_getspi(const sadb_msg_t *restrict srcmsg, sockaddr_u_t src,
    sockaddr_u_t dest, uint8_t satype, uint32_t *spi)
{
	parsedmsg_t *resp = NULL;
	uint64_t buffer[128];
	sadb_msg_t *samsg = (sadb_msg_t *)buffer;
	sadb_ext_t *ext = NULL;
	boolean_t ret;

	/*
	 * Use sizeof (struct sockaddr_storage) as worst case address size
	 * for compile time check
	 */
	CTASSERT(sizeof (buffer) >= sizeof (*samsg) +
	    2 * (sizeof (sadb_address_t) + sizeof (struct sockaddr_storage)) +
	    sizeof (sadb_spirange_t));

	*spi = 0;

	VERIFY3U(src.sau_ss->ss_family, ==, dest.sau_ss->ss_family);

	/*
	 * The kernel randomly pics an SPI within the range we pass.  If it
	 * happens to collide with an existing SPI, the GETSPI request will
	 * fail with EEXIST.  We keep trying until we either succeed, or
	 * get an error other than EEXIST.  Technically this means
	 * if we've exhaused our SPI space, we'll loop forever.  However, there
	 * is no definitive way to detect this, and since the address space is
	 * 32 bits, it seems reasonable at this time to assume we will run out
	 * of other resources long before having 2^32 IPsec SAs (larval or
	 * fully formed) is likely.
	 */
	do {
		(void) memset(buffer, 0, sizeof (buffer));

		pfkey_msg_init(srcmsg, samsg, SADB_GETSPI, satype);
		ext = (sadb_ext_t *)(samsg + 1);

		ext = pfkey_add_address(ext, SADB_EXT_ADDRESS_SRC, src);
		ext = pfkey_add_address(ext, SADB_EXT_ADDRESS_DST, dest);
		ext = pfkey_add_range(ext, 1, UINT32_MAX);

		samsg->sadb_msg_len = PFKEY_MSG_LEN(samsg, ext);

		errno = 0;
		if (pfkey_send_msg(samsg, &resp, 1, SADB_EXT_SA)) {
			if (resp == NULL || resp->pmsg_samsg == NULL) {
				parsedmsg_free(resp);
				return (B_FALSE);
			}
		}
	} while (resp->pmsg_samsg->sadb_msg_errno == EEXIST);

	if (resp->pmsg_samsg->sadb_msg_errno != 0) {
		sadb_msg_t *m = resp->pmsg_samsg;

		TSTDERR(m->sadb_msg_errno, error,
		    "SADB_GETSPI failed",
		    BUNYAN_T_STRING, "diagmsg",
		    keysock_diag(m->sadb_x_msg_diagnostic),
		    BUNYAN_T_UINT32, "diagcode",
		    (uint32_t)m->sadb_x_msg_diagnostic);
	} else {
		sadb_sa_t *sa = (sadb_sa_t *)resp->pmsg_exts[SADB_EXT_SA];
		char type[64] = { 0 };
		char spistr[11] = { 0 }; /* 0x + 32-bit hex + NUL */

		*spi = sa->sadb_sa_spi;
		(void) sadb_type_str(satype, type, sizeof (type));

		/* SPI values are usually displayed as hex */
		(void) snprintf(spistr, sizeof (spistr), "0x%" PRIX32, *spi);

		(void) bunyan_debug(log, "Allocated larval IPsec SA",
		    BUNYAN_T_STRING, "satype", type,
		    BUNYAN_T_STRING, "spi", spistr,
		    BUNYAN_T_END);
	}

	ret = (resp->pmsg_samsg->sadb_msg_errno == 0) ? B_TRUE : B_FALSE;
	parsedmsg_free(resp);
	return (ret);
}

boolean_t
pfkey_inverse_acquire(sockaddr_u_t src, sockaddr_u_t dest,
    sockaddr_u_t isrc, sockaddr_u_t idest, parsedmsg_t **resp)
{
	uint64_t buffer[128] = { 0 };
	sadb_msg_t *msg = (sadb_msg_t *)buffer;
	sadb_ext_t *ext = (sadb_ext_t *)(msg + 1);

	/* This also guarantees src and dest aren't NULL */
	VERIFY3U(src.sau_ss->ss_family, ==, dest.sau_ss->ss_family);

	/*
	 * The inner addresses (if present) can be a different address family
	 * than the outer addresses, but the inner source and inner destination
	 * address families should agree with each other.
	 */
	if (isrc.sau_ss != NULL)
		VERIFY3U(isrc.sau_ss->ss_family, ==, idest.sau_ss->ss_family);

	pfkey_msg_init(NULL, msg, SADB_X_INVERSE_ACQUIRE, SADB_SATYPE_UNSPEC);

	ext = pfkey_add_address(ext, SADB_EXT_ADDRESS_SRC, src);
	ext = pfkey_add_address(ext, SADB_EXT_ADDRESS_DST, dest);
	if (isrc.sau_ss != NULL) {
		ext = pfkey_add_address(ext, SADB_X_EXT_ADDRESS_INNER_SRC,
		    isrc);
		ext = pfkey_add_address(ext, SADB_X_EXT_ADDRESS_INNER_DST,
		    idest);
	}

	msg->sadb_msg_len = PFKEY_MSG_LEN(msg, ext);
	errno = 0;
	return (pfkey_send_msg(msg, resp, 1, SADB_X_EXT_EPROP));
}

boolean_t
pfkey_delete(uint8_t satype, uint32_t spi, sockaddr_u_t src, sockaddr_u_t dst,
    boolean_t pair)
{
	uint64_t buf[128] = { 0 };
	sadb_msg_t *msg = (sadb_msg_t *)buf;
	sadb_ext_t *ext = (sadb_ext_t *)(msg + 1);
	parsedmsg_t *pmsg = NULL;
	boolean_t ret = B_FALSE;

	pfkey_msg_init(NULL, msg, pair ? SADB_X_DELPAIR : SADB_DELETE, satype);

	ext = pfkey_add_address(ext, SADB_EXT_ADDRESS_SRC, src);
	ext = pfkey_add_address(ext, SADB_EXT_ADDRESS_DST, dst);

	if (!pfkey_send_msg(msg, &pmsg, 1, SADB_EXT_SA) ||
	    (pmsg->pmsg_samsg != NULL &&
	    pmsg->pmsg_samsg->sadb_msg_errno != 0)) {
		sadb_msg_t *resp = pmsg->pmsg_samsg;

		if (resp != NULL) {
			TSTDERR(resp->sadb_msg_errno, warn,
			    "Error deleting IPsec SA",
			    BUNYAN_T_STRING, "diagmsg",
			    keysock_diag(resp->sadb_x_msg_diagnostic),
			    BUNYAN_T_UINT32, "diagcode",
			    (uint32_t)resp->sadb_x_msg_diagnostic);
		} else {
			(void) bunyan_warn(log, "Error deleting IPsec SA",
			    BUNYAN_T_END);
		}
	} else {
		ret = B_TRUE;
	}

	parsedmsg_free(pmsg);
	return (ret);
}

static void
handle_reply(sadb_msg_t *reply)
{
	pfreq_t *req = NULL;

	mutex_enter(&pfreq_lock);

	req = list_head(&pfreq_list);
	while (req != NULL && req->pr_msgid != reply->sadb_msg_seq)
		req = list_next(&pfreq_list, req);

	if (req != NULL)
		list_remove(&pfreq_list, req);
	mutex_exit(&pfreq_lock);

	if (req == NULL) {
		sadb_log(BUNYAN_L_INFO,
		    "Received a reply to an unknown request", reply);
		free(reply);
		return;
	}

	mutex_enter(&req->pr_lock);
	req->pr_msg = reply;
	req->pr_recv = B_TRUE;
	mutex_exit(&req->pr_lock);
	VERIFY0(cond_signal(&req->pr_cv));
}

static void
handle_flush(sadb_msg_t *samsg)
{
	(void) bunyan_trace(log, "Handling SADB flush message", BUNYAN_T_END);

	/* Return if just AH or ESP SAs are being freed. */
	if (samsg->sadb_msg_satype != SADB_SATYPE_UNSPEC)
		return;

	/* XXX KEBE SAYS FILL ME IN! */

	ikev2_sa_flush();

	/*
	 * If we receive an SADB_FLUSH for all SA types, get rid of any IKE
	 * SAs.
	 */

	free(samsg);
}

/*
 * Handle the PF_KEY SADB_EXPIRE message for idle timeout.
 *
 * XXX KEBE SAYS this'll most likely kick off Dead Peer Detection if we can
 * find an IKE SA.
 */
static void
handle_idle_timeout(sadb_msg_t *samsg)
{
	(void) bunyan_trace(log, "Handling SADB idle expire message",
	    BUNYAN_T_END);

	/* XXX KEBE SAYS FILL ME IN! */
	free(samsg);
}

static void
handle_expire(sadb_msg_t *samsg)
{
	parsedmsg_t pmsg;

	/*
	 * If SOFT expire, see if the SADB_X_SAFLAGS_KM1 (initiator) is set,
	 * if so, consider treating this expire as an ACQUIRE message.
	 *
	 * If HARD expire, treat this message like a DELETE.
	 *
	 * If IDLE expire, see if we need to do a little DPD or not.
	 */

	if (extract_exts(samsg, &pmsg, 1, SADB_EXT_LIFETIME_HARD)) {
		(void) bunyan_debug(log, "Handling SADB hard expire message",
		    BUNYAN_T_END);
		handle_delete(samsg);
		return;
	}

	if (pmsg.pmsg_exts[SADB_X_EXT_LIFETIME_IDLE] != NULL) {
		handle_idle_timeout(samsg);
		return;
	}

	/*
	 * extract_exts() has already filled in pmsg with data from
	 * samsg. pmsg.pmsg_exts[foo] will be NULL if this was
	 * not set in samsg. Bail out if the message appears to be
	 * poorly formed. If everything looks good, create a new
	 * "ACQUIRE like" message and pass off to handle_acquire().
	 */

	if (pmsg.pmsg_exts[SADB_EXT_LIFETIME_SOFT] == NULL) {
		/* XXX: more fields */
		(void) bunyan_info(log, "SADB EXPIRE message is missing both "
		    "hard and soft lifetimes", BUNYAN_T_END);
		/* XXX: ignore? */
	}

	(void) bunyan_debug(log, "Handling SADB soft expire message",
	    BUNYAN_T_END);

	/* XXX KEBE SAYS FILL ME IN! */

	free(samsg);
}

static void
handle_register(sadb_msg_t *samsg)
{
	_NOTE(ARGUNUSED(samsg))
	/* XXX KEBE SAYS FILL ME IN! */

	/*
	 * XXX KEBE wonders if this is as necessary as 2367 first imagined?
	 *
	 * With inverse-ACQUIRE, you know better what algorithms are available
	 * and acceptable.  This may go away or remain a mere stub.
	 */
}

static void
handle_delete(sadb_msg_t *samsg)
{
	(void) bunyan_trace(log, "Handling SADB delete", BUNYAN_T_END);

	/* XXX KEBE SAYS FILL ME IN! */
	free(samsg);
}

/*
 * Handle a PF_KEY ACQUIRE message.  This function, or something that it
 * calls (either directly or via callbacks) must free samsg.
 */
/* XXX KEBE wonders if create_child_sa will be needed here or not. */
static void
handle_acquire(sadb_msg_t *samsg, boolean_t create_child_sa)
{
	/* XXX: for now */
	_NOTE(ARGUNUSED(create_child_sa))

	parsedmsg_t *pmsg;

	pmsg = calloc(1, sizeof (*pmsg));

	(void) bunyan_debug(log, "Handling SADB acquire", BUNYAN_T_END);

	if (!extract_exts(samsg, pmsg, 1, SADB_EXT_PROPOSAL)) {
		(void) bunyan_info(log, "No proposal found in ACQUIRE message",
		    BUNYAN_T_END);
		free(samsg);
		free(pmsg);
		return;
	}

	if (!worker_send_cmd(WC_PFKEY, pmsg)) {
		free(samsg);
		free(pmsg);
	}
}

static void *
pfkey_thread(void *arg)
{
	port_event_t pe;
	boolean_t stop = B_FALSE;

	log = arg;

	(void) bunyan_trace(log, "pfkey thread starting", BUNYAN_T_END);

	while (!stop) {
		char portstr[PORT_SOURCE_STRLEN];

		if (port_get(pfport, &pe, NULL) < 0) {
			STDERR(fatal, "port_get() failed");
			exit(EXIT_FAILURE);
		}

		(void) bunyan_debug(log, "Received port event",
		    BUNYAN_T_INT32, "event", pe.portev_events,
		    BUNYAN_T_STRING, "source",
		    port_source_str(pe.portev_source, portstr,
		    sizeof (portstr)),
		    BUNYAN_T_POINTER, "object", pe.portev_object,
		    BUNYAN_T_POINTER, "cookie", pe.portev_user,
		    BUNYAN_T_END);

		VERIFY3S(pe.portev_source, ==, PORT_SOURCE_FD);

		pfkey_inbound((int)pe.portev_object);
	}

	return (NULL);
}

static void
pfkey_register(uint8_t satype)
{
	uint64_t buffer[128] = { 0 };
	char str[64];
	sadb_msg_t *samsg = (sadb_msg_t *)buffer;
	ssize_t n;
	uint32_t msgid = atomic_inc_32_nv(&msgid);
	pid_t pid = getpid();

	CTASSERT(sizeof (buffer) >= sizeof (*samsg));

	pfkey_msg_init(NULL, samsg, SADB_REGISTER, satype);

	n = write(pfsock, buffer, sizeof (*samsg));
	if (n < 0)
		err(EXIT_FAILURE, "pf_key write error");
	if (n < sizeof (*samsg))
		errx(EXIT_FAILURE, "Unable to write pf_key register message");

	do {
		(void) memset(buffer, 0, sizeof (buffer));
		n = read(pfsock, buffer, sizeof (buffer));
		if (n < 0)
			err(EXIT_FAILURE, "pf_key read failure");
	} while (samsg->sadb_msg_seq != msgid ||
	    samsg->sadb_msg_pid != pid ||
	    samsg->sadb_msg_type != SADB_REGISTER);

	if (samsg->sadb_msg_errno != 0) {
		if (samsg->sadb_msg_errno != EPROTONOSUPPORT)
			errx(EXIT_FAILURE, "pf_key register returned %s (%d).",
			    strerror(samsg->sadb_msg_errno),
			    samsg->sadb_msg_errno);
		(void) bunyan_error(log, "Protocol not supported",
		    BUNYAN_T_STRING, "satype",
		    sadb_type_str(samsg->sadb_msg_satype, str, sizeof (str)),
		    BUNYAN_T_END);
	}

	(void) bunyan_debug(log, "Initial REGISTER with SADB",
	    BUNYAN_T_STRING, "satype",
	    sadb_type_str(samsg->sadb_msg_satype, str, sizeof (str)),
	    BUNYAN_T_END);

	handle_register(samsg);
}

static void
sadb_log_sa(sadb_ext_t *ext)
{
	sadb_sa_t *sa = (sadb_sa_t *)ext;
	char buf[11] = { 0 }; /* 0x + 8 hex digits + NUL */

	(void) snprintf(buf, sizeof (buf), "0x%X", sa->sadb_sa_spi);
	(void) bunyan_key_add(log,
	    BUNYAN_T_STRING, PFKEY_K_SPI, buf,
	    BUNYAN_T_END);
}

static void
sadb_log_pair(sadb_ext_t *ext)
{
	sadb_x_pair_t *pair = (sadb_x_pair_t *)ext;
	char buf[11] = { 0 };

	(void) snprintf(buf, sizeof (buf), "0x%X", pair->sadb_x_pair_spi);
	(void) bunyan_key_add(log,
	    BUNYAN_T_STRING, PFKEY_K_PAIR, buf,
	    BUNYAN_T_END);
}

static void
sadb_log_addr(sadb_ext_t *ext)
{
	const char *name = NULL;
	const char *portname = NULL;
	sadb_address_t *addr = (sadb_address_t *)ext;
	sockaddr_u_t su = { .sau_ss = (struct sockaddr_storage *)(addr + 1) };
	void *ptr = NULL;
	int af = su.sau_ss->ss_family;
	char addrstr[INET6_ADDRSTRLEN + 4] = { 0 };	/* +4 for /xxx */

	switch (addr->sadb_address_exttype) {
	case SADB_EXT_ADDRESS_SRC:
		name = PFKEY_K_SRCADDR;
		portname = PFKEY_K_SRCADDR PFKEY_K_PORT;
		break;
	case SADB_EXT_ADDRESS_DST:
		name = PFKEY_K_DSTADDR;
		portname = PFKEY_K_DSTADDR PFKEY_K_PORT;
		break;
	case SADB_X_EXT_ADDRESS_INNER_SRC:
		name = PFKEY_K_ISRCADDR;
		portname = PFKEY_K_ISRCADDR PFKEY_K_PORT;
		break;
	case SADB_X_EXT_ADDRESS_INNER_DST:
		name = PFKEY_K_IDSTADDR;
		portname = PFKEY_K_IDSTADDR PFKEY_K_PORT;
		break;
	case SADB_X_EXT_ADDRESS_NATT_REM:
		name = PFKEY_K_NLOC;
		portname = PFKEY_K_NLOC PFKEY_K_PORT;
		break;
	case SADB_X_EXT_ADDRESS_NATT_LOC:
		name = PFKEY_K_NREM;
		portname = PFKEY_K_NREM PFKEY_K_PORT;
		break;
	}

	switch (af) {
	case AF_INET:
		ptr = &su.sau_sin->sin_addr;
		break;
	case AF_INET6:
		ptr = &su.sau_sin6->sin6_addr;
		break;
	default:
		INVALID("ss_family");
	}

	if (inet_ntop(af, ptr, addrstr, sizeof (addrstr)) == NULL)
		return;

	if (addr->sadb_address_prefixlen != 0 &&
	    ((af == AF_INET && addr->sadb_address_prefixlen != 32) ||
	    (af == AF_INET6 && addr->sadb_address_prefixlen != 128))) {
		char prefix[5] = { 0 };

		(void) snprintf(prefix, sizeof (prefix), "/%hhu",
		    addr->sadb_address_prefixlen);
		(void) strlcat(addrstr, prefix, sizeof (addrstr));
	}
	(void) bunyan_key_add(log,
	    BUNYAN_T_STRING, name, addrstr,
	    BUNYAN_T_END);

	/* Take advantage of port (sin_port/sin6_port) at the same offset */
	if (su.sau_sin->sin_port == 0)
		return;

	struct protoent *pe = NULL;
	char *portstr = NULL;
	size_t portlen = 6; /* uint16_t as str + NUL */

	if (addr->sadb_address_proto != 0) {
		pe = getprotobynumber(addr->sadb_address_proto);
		portlen += strlen(pe->p_name) + 1; /* +1 for '/' */
	} else {
		portlen += 4; /* 'any/' */
	}

	portstr = alloca(portlen);
	(void) snprintf(portstr, portlen, "%s/%hu",
	    (pe != NULL) ? pe->p_name : "any", ntohs(su.sau_sin->sin_port));

	(void) bunyan_key_add(log,
	    BUNYAN_T_STRING, portname, portstr,
	    BUNYAN_T_END);
}

void
sadb_log(bunyan_level_t level, const char *restrict msg,
    sadb_msg_t *restrict samsg)
{
	bunyan_logfn_t logf = getlog(level);
	sadb_ext_t *ext, *end;
	char op[64];
	char type[64];

	end = (sadb_ext_t *)((uint64_t *)samsg + samsg->sadb_msg_len);
	ext = (sadb_ext_t *)(samsg + 1);

	while (ext < end) {
		switch (ext->sadb_ext_type) {
		case SADB_EXT_SA:
			sadb_log_sa(ext);
			break;
		case SADB_EXT_ADDRESS_SRC:
		case SADB_EXT_ADDRESS_DST:
		case SADB_X_EXT_ADDRESS_INNER_SRC:
		case SADB_X_EXT_ADDRESS_INNER_DST:
		case SADB_X_EXT_ADDRESS_NATT_REM:
		case SADB_X_EXT_ADDRESS_NATT_LOC:
			sadb_log_addr(ext);
			break;
		case SADB_X_EXT_PAIR:
			sadb_log_pair(ext);
			break;
		}

		ext = (sadb_ext_t *)((uint64_t *)ext + ext->sadb_ext_len);
	}

	logf(log, msg,
	    BUNYAN_T_STRING, "msg_type",
	    sadb_op_str(samsg->sadb_msg_type, op, sizeof (op)),
	    BUNYAN_T_STRING, "sa_type",
	    sadb_type_str(samsg->sadb_msg_satype, type, sizeof (type)),
	    BUNYAN_T_UINT32, "msg_pid", samsg->sadb_msg_pid,
	    BUNYAN_T_UINT32, "msg_seq", samsg->sadb_msg_seq,
	    BUNYAN_T_UINT32, "msg_errno_val", (uint32_t)samsg->sadb_msg_errno,
	    BUNYAN_T_STRING, "msg_errno", strerror(samsg->sadb_msg_errno),
	    BUNYAN_T_UINT32, "msg_diagnostic_val",
	    (uint32_t)samsg->sadb_x_msg_diagnostic,
	    BUNYAN_T_STRING, "msg_diagnostic",
	    keysock_diag(samsg->sadb_x_msg_diagnostic),
	    BUNYAN_T_UINT32, "length", (uint32_t)samsg->sadb_msg_len,
	    BUNYAN_T_END);

	for (size_t i = 0; i < ARRAY_SIZE(pfkey_keys); i++)
		(void) bunyan_key_remove(log, pfkey_keys[i]);
}

void
pfkey_init(void)
{
	bunyan_logger_t *newlog = NULL;
	int rc;

	list_create(&pfreq_list, sizeof (pfreq_t), offsetof (pfreq_t, pr_node));

	pfport = port_create();
	if (pfport == -1)
		err(EXIT_FAILURE, "Unable to create pfkey event port");

	pfsock = socket(PF_KEY, SOCK_RAW, PF_KEY_V2);
	if (pfsock == -1)
		err(EXIT_FAILURE, "Unable to create pf_key socket");

	rc = bunyan_child(log, &newlog,
	    BUNYAN_T_INT32, "pfsock", (int32_t)pfsock,
	    BUNYAN_T_END);

	if (rc != 0) {
		errx(EXIT_FAILURE, "Unable to create child logger: %s",
		    strerror(rc));
	}

	pfkey_register(SADB_SATYPE_ESP);
	pfkey_register(SADB_SATYPE_AH);

	rc = thr_create(NULL, 0, pfkey_thread, newlog, 0, &pftid);
	if (rc != 0) {
		errx(EXIT_FAILURE, "Unable to create pfkey thread: %s",
		    strerror(rc));
	}

	pfkey_arm(pfsock);
}

void
parsedmsg_free(parsedmsg_t *pmsg)
{
	if (pmsg == NULL)
		return;
	free(pmsg->pmsg_samsg);
	free(pmsg);
}

/*
 * Convert a pf_key(7P) SADB_SATYPE_* value to the corresponding IKEv2
 * protocol.
 *
 * This is future-proofing things a bit.  If we ever support key exchange
 * for additional SA types, it's unlikely the SADB and IKEv2 values will
 * match, so this provides a single place to do the translation.
 */
ikev2_spi_proto_t
satype_to_ikev2(uint8_t satype)
{
	switch (satype) {
	/* These values match */
	case SADB_SATYPE_UNSPEC:
	case SADB_SATYPE_AH:
	case SADB_SATYPE_ESP:
		return ((ikev2_spi_proto_t)satype);
	default:
		INVALID("satype");
	}
	/*NOTREACHED*/
	return (0);
}

uint8_t
ikev2_to_satype(ikev2_spi_proto_t proto)
{
	switch (proto) {
	case IKEV2_PROTO_NONE:
	case IKEV2_PROTO_AH:
	case IKEV2_PROTO_ESP:
		return ((uint8_t)proto);
	case IKEV2_PROTO_IKE:
	case IKEV2_PROTO_FC_ESP_HEADER:
	case IKEV2_PROTO_FC_CT_AUTH:
		INVALID(proto);
	}
	/*NOTREACHED*/
	return (0);
}

int
ikev2_encr_to_pfkey(ikev2_xf_encr_t encr)
{
	switch (encr) {
	/* These all correspond */
	case IKEV2_ENCR_NONE:
	case IKEV2_ENCR_DES:
	case IKEV2_ENCR_3DES:
	case IKEV2_ENCR_BLOWFISH:
	case IKEV2_ENCR_NULL:
	case IKEV2_ENCR_AES_CBC:
	case IKEV2_ENCR_AES_CCM_8:
	case IKEV2_ENCR_AES_CCM_12:
	case IKEV2_ENCR_AES_CCM_16:
	case IKEV2_ENCR_AES_GCM_8:
	case IKEV2_ENCR_AES_GCM_12:
	case IKEV2_ENCR_AES_GCM_16:
		return (encr);
	case IKEV2_ENCR_AES_CTR:
	case IKEV2_ENCR_NULL_AES_GMAC:
	case IKEV2_ENCR_CAMELLIA_CBC:
	case IKEV2_ENCR_CAMELLIA_CTR:
	case IKEV2_ENCR_CAMELLIA_CCM_8:
	case IKEV2_ENCR_CAMELLIA_CCM_12:
	case IKEV2_ENCR_CAMELLIA_CCM_16:
	case IKEV2_ENCR_DES_IV64:
	case IKEV2_ENCR_DES_IV32:
	case IKEV2_ENCR_XTS_AES:
	case IKEV2_ENCR_RC5:
	case IKEV2_ENCR_IDEA:
	case IKEV2_ENCR_CAST:
	case IKEV2_ENCR_3IDEA:
	case IKEV2_ENCR_RC4:
		return (-1);
	}
	return (-1);
}

int
ikev2_auth_to_pfkey(ikev2_xf_auth_t auth)
{
	switch (auth) {
	case IKEV2_XF_AUTH_NONE:
		return (SADB_AALG_NONE);
	case IKEV2_XF_AUTH_HMAC_SHA2_256_128:
		return (SADB_AALG_SHA256HMAC);
	case IKEV2_XF_AUTH_HMAC_SHA2_384_192:
		return (SADB_AALG_SHA384HMAC);
	case IKEV2_XF_AUTH_HMAC_SHA2_512_256:
		return (SADB_AALG_SHA512HMAC);
	case IKEV2_XF_AUTH_HMAC_MD5_96:
		return (SADB_AALG_MD5HMAC);
	case IKEV2_XF_AUTH_HMAC_SHA1_96:
		return (SADB_AALG_SHA1HMAC);
	case IKEV2_XF_AUTH_AES_CMAC_96:
	case IKEV2_XF_AUTH_AES_128_GMAC:
	case IKEV2_XF_AUTH_AES_192_GMAC:
	case IKEV2_XF_AUTH_AES_256_GMAC:
	case IKEV2_XF_AUTH_DES_MAC:
	case IKEV2_XF_AUTH_KPDK_MD5:
	case IKEV2_XF_AUTH_AES_XCBC_96:
	case IKEV2_XF_AUTH_HMAC_MD5_128:
	case IKEV2_XF_AUTH_HMAC_SHA1_160:
		return (-1);
	}
	return (-1);
}
