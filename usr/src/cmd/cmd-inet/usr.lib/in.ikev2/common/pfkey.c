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

#include <atomic.h>
#include <bunyan.h>
#include <errno.h>
#include <locale.h>
#include <note.h>
#include <sys/list.h>
#include <sys/types.h>
#include <sys/stropts.h>	/* For I_NREAD */
#include <ipsec_util.h>
#include <netdb.h>
#include <net/pfkeyv2.h>
#include <port.h>
#include <stdio.h>
#include <string.h>
#include <synch.h>
#include <time.h>

#include "defs.h"
#include "ikev2.h"
#include "ikev2_pkt.h"
#include "ikev2_sa.h"
#include "inbound.h"
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
#define	PFKEY_TIMEOUT	2	/* in seconds */

typedef struct pfreq {
	list_node_t	pr_node;
	uint32_t	pr_msgid;
	mutex_t		pr_lock;
	cond_t		pr_cv;
	sadb_msg_t	*pr_msg;
	boolean_t	pr_recv;
} pfreq_t;

static bunyan_logger_t	*pflog;

/* pfreq lock protects pfreq_list */
static mutex_t	pfreq_lock = ERRORCHECKMUTEX;
static list_t	pfreq_list;

/* PF_KEY socket. */
static int pfsock;

/* our event port */
static int pfport;

/* our msgids */
static volatile uint32_t msgid = 0;

static void handle_reply(sadb_msg_t *);
static void handle_delete(sadb_msg_t *);
static void handle_flush(sadb_msg_t *);
static void handle_expire(sadb_msg_t *);
static void handle_acquire(sadb_msg_t *, boolean_t);
static void handle_register(sadb_msg_t *);

static void sadb_log(bunyan_logger_t *restrict, bunyan_level_t,
    const char *restrict, sadb_msg_t *restrict);

static const char *pfkey_opcodes[] = {
	"RESERVED", "GETSPI", "UPDATE", "ADD", "DELETE", "GET",
	"ACQUIRE", "REGISTER", "EXPIRE", "FLUSH", "DUMP", "X_PROMISC",
	"X_INVERSE_ACQUIRE", "X_UPDATEPAIR", "X_DELPAIR"
};

static const char *
pfkey_type(unsigned int type)
{
	if (type > SADB_MAX)
		return ("ILLEGAL");
	else
		return (pfkey_opcodes[type]);
}

static const char *pfkey_satypes[] = {
	"UNSPEC", "<undef>", "AH", "ESP", "<undef>", "RSVP", "OSPFV2",
	"RIPV2", "MIP"
};

static const char *
pfkey_satype(unsigned int type)
{
	if (type > SADB_SATYPE_MAX)
		return ("ILLEGAL");
	else
		return (pfkey_satypes[type]);
}

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
	sadb_ext_t *ext;
	sadb_ext_t **exts = pmsg->pmsg_exts;
	int current_ext;
	boolean_t rc = B_TRUE;

	(void) memset(pmsg, 0, sizeof (parsedmsg_t));

	ext = (sadb_ext_t *)(samsg + 1);
	pmsg->pmsg_samsg = samsg;

	do {
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

	} while (((uint8_t *)ext) - ((uint8_t *)samsg) <
	    SADB_64TO8(samsg->sadb_msg_len));

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
		STDERR(error, pflog, "port_associate() failed",
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
		STDERR(error, log, "ioctl(I_NREAD) failed");
		pfkey_arm(s);
		return;
	}

	if (length == 0) {
		bunyan_info(log, "ioctl: zero length message",
		    BUNYAN_T_STRING, "func", __func__,
		    BUNYAN_T_STRING, "file", __FILE__,
		    BUNYAN_T_INT32, "line", __LINE__,
		    BUNYAN_T_END);
		pfkey_arm(s);
		return;
	}

	samsg = malloc(length);
	if (samsg == NULL) {
		bunyan_error(log, "No memory for pfkey message", BUNYAN_T_END);
		pfkey_arm(s);
		return;
	}

	rc = read(s, samsg, length);
	if (rc <= 0) {
		if (rc == -1) {
			STDERR(error, log, "read failed");
			/* XXX: Should I exit()? */
		}
		free(samsg);
		pfkey_arm(s);
		return;
	}

	/* At this point, we can safely re-schedule the socket for reading. */
	pfkey_arm(s);

	sadb_log(log, BUNYAN_L_DEBUG, "SADB message received", samsg);

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
		bunyan_debug(log, "Reply not for us, dropped", BUNYAN_T_END);
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

	bunyan_debug(log, "SADB message type unknown, ignored.",
	    BUNYAN_T_UINT32, "msg_type_val", (uint32_t)samsg->sadb_msg_type,
	    BUNYAN_T_END);
	free(samsg);
}

/*
 * Send 'msg' to pfkey, and wait for a reply.  The kernel is expected to
 * reply within a few ms, so we block waiting for the reply to simplify
 * handling in the caller.
 */
boolean_t
pfkey_send_msg(sadb_msg_t *msg, parsedmsg_t *pmsg, int numexts, ...)
{
	pfreq_t req = { 0 };
	ssize_t n;
	int rc;
	va_list ap;
	boolean_t ret = B_TRUE;

	VERIFY(IS_WORKER);

	VERIFY0(cond_init(&req.pr_cv, USYNC_THREAD, NULL));
	VERIFY0(mutex_init(&req.pr_lock, USYNC_THREAD|LOCK_ERRORCHECK, NULL));

	msg->sadb_msg_seq = req.pr_msgid = atomic_inc_32_nv(&msgid);
	msg->sadb_msg_pid = getpid();

	mutex_enter(&pfreq_lock);
	list_insert_tail(&pfreq_list, &req);
	mutex_exit(&pfreq_lock);

	n = write(pfsock, msg, msg->sadb_msg_len);
	if (n != msg->sadb_msg_len) {
		if (n < 0) {
			STDERR(error, log, "pf_key write failed");
		} else {
			bunyan_error(log, "pf_key truncated write",
			    BUNYAN_T_INT32, "n", (int32_t)n,
			    BUNYAN_T_END);
		}

		mutex_enter(&pfreq_lock);
		list_remove(&pfreq_list, &req);
		mutex_exit(&pfreq_lock);
		ret = B_FALSE;
		goto done;
	}

	mutex_enter(&req.pr_lock);
	while (!req.pr_recv) {
		timestruc_t amt;

		amt.tv_sec = time(NULL) + PFKEY_TIMEOUT;
		amt.tv_nsec = 0;
		rc = cond_reltimedwait(&req.pr_cv, &req.pr_lock, &amt);

		if (rc == ETIME) {
			bunyan_error(log, "pf_key timeout",
			    BUNYAN_T_UINT32, "msgid", req.pr_msgid,
			    BUNYAN_T_END);

			errno = ETIMEDOUT;
			ret = B_FALSE;
			goto done;
		}
	}

	va_start(ap, numexts);
	ret = vextract_exts(req.pr_msg, pmsg, numexts, ap);
	va_end(ap);

done:
	mutex_exit(&req.pr_lock);
	mutex_destroy(&req.pr_lock);
	cond_destroy(&req.pr_cv);
	return (ret);
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
	msg.sadb_msg_len = SADB_8TO64(sizeof (sadb_msg_t));
	msg.sadb_msg_version = PF_KEY_V2;
	msg.sadb_msg_type = src->sadb_msg_type;
	msg.sadb_msg_errno = reason;
	msg.sadb_msg_satype = src->sadb_msg_satype;
	msg.sadb_x_msg_diagnostic = SADB_X_DIAGNOSTIC_NONE;
	msg.sadb_msg_seq = src->sadb_msg_seq;
	msg.sadb_msg_pid = src->sadb_msg_pid;

	n = write(pfsock, &msg, sizeof (sadb_msg_t));
	if (n != sizeof (sadb_msg_t))
		STDERR(error, log, "Unable to send PFKEY error notification");
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
static size_t
pfkey_add_address(sadb_address_t *saaddr, sockaddr_u_t addr, void *endp)
{
	sockaddr_u_t msgaddr = {
		.sau_ss = (struct sockaddr_storage *)(saaddr + 1)
	};
	sockaddr_u_t nextaddr;
	size_t len = 0;

	switch (addr.sau_ss->ss_family) {
	case AF_INET:
		nextaddr.sau_sin = (msgaddr.sau_sin + 1);
		len = sizeof (struct sockaddr_in);
		(void) memcpy(msgaddr.sau_sin, addr.sau_sin, len);
		break;
	case AF_INET6:
		nextaddr.sau_sin6 = (msgaddr.sau_sin6 + 1);
		len = sizeof (struct sockaddr_in6);
		(void) memcpy(msgaddr.sau_sin6, addr.sau_sin6, len);
		break;
	default:
		INVALID("ss_family");
	}

	len += sizeof (*saaddr);
	saaddr->sadb_address_len = SADB_8TO64(len);

	(*(void **)endp) = nextaddr.sau_ss;
	return (len);
}

boolean_t
pfkey_getspi(sockaddr_u_t src, sockaddr_u_t dest, uint8_t satype,
    parsedmsg_t *resp)
{
	uint64_t buffer[128];
	sadb_msg_t *samsg = (sadb_msg_t *)buffer;
	sadb_address_t *sasrc = NULL, *sadest = NULL;
	sadb_spirange_t *range = NULL;
	size_t len = 0;

	/*
	 * Use sizeof (struct sockaddr_storage) as worst case address size
	 * for compile time check
	 */
	CTASSERT(sizeof (buffer) >= sizeof (*samsg) +
	    2 * (sizeof (*sasrc) + sizeof (struct sockaddr_storage)) +
	    sizeof (*range));

	VERIFY3U(src.sau_ss->ss_family, ==, dest.sau_ss->ss_family);

	samsg->sadb_msg_version = PF_KEY_V2;
	samsg->sadb_msg_type = SADB_GETSPI;
	samsg->sadb_msg_satype = satype;
	len += sizeof (*samsg);
	/* pfkey_send_msg() sets pid and msgid for us */

	sasrc = (sadb_address_t *)(samsg + 1);
	sasrc->sadb_address_exttype = SADB_EXT_ADDRESS_SRC;
	sasrc->sadb_address_proto = 0;			/* XXX: fill me in! */
	sasrc->sadb_address_prefixlen = 0;		/* XXX: fill me in! */
	len += pfkey_add_address(sasrc, src, &sadest);

	sadest->sadb_address_exttype = SADB_EXT_ADDRESS_DST;
	sadest->sadb_address_proto = 0;			/* XXX: fill me in! */
	sadest->sadb_address_prefixlen = 0;		/* XXX: fill me in! */
	len += pfkey_add_address(sadest, dest, &range);

	range->sadb_spirange_len = SADB_8TO64(sizeof (*range));
	range->sadb_spirange_exttype = SADB_EXT_SPIRANGE;
	range->sadb_spirange_min = 1;
	range->sadb_spirange_max = UINT32_MAX;
	len += sizeof (*range);

	samsg->sadb_msg_len = SADB_8TO64(len);

	/*
	 * The kernel randomly pics an SPI within the range we pass.  If it
	 * happens to collide with an existing SPI, the GETSPI request will
	 * fail with EEXIST.  We keep trying until we either succeed, or
	 * get an error other than EEXIST.  Technically this means
	 * if we've exhaused our SPI space, we'll loop forever.  However, there
	 * is no definitive way to detect this, and since the address space is
	 * 32 bits, it seems reasonable at this time to assume we will run out
	 * of resources long before we could ever possibly have 2^32 IPsec SAs
	 * (larval or otherwise).
	 *
	 * XXX: The semantics here and with pfkey_send_msg could be improved.
	 * Revisit after other pfkey functions are added.
	 */
	do {
		if (resp->pmsg_samsg != NULL)
			free(resp->pmsg_samsg);
		resp->pmsg_samsg = NULL;
		errno = 0;
		if (!pfkey_send_msg(samsg, resp, 3,
		    SADB_EXT_SA, SADB_EXT_ADDRESS_SRC, SADB_EXT_ADDRESS_DST)) {
			if (errno != 0)
				return (B_FALSE);
		}
	} while (resp->pmsg_samsg->sadb_msg_errno != 0 &&
	    resp->pmsg_samsg->sadb_msg_errno != EEXIST);

	return (resp->pmsg_samsg->sadb_msg_errno == 0 ? B_TRUE : B_FALSE);
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
		sadb_log(pflog, BUNYAN_L_INFO,
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
	bunyan_trace(pflog, "Handling SADB flush message", BUNYAN_T_END);

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
	bunyan_trace(pflog, "Handling SADB idle expire message", BUNYAN_T_END);

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
		bunyan_debug(pflog, "Handling SADB hard expire message",
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
		bunyan_info(pflog, "SADB EXPIRE message is missing both "
		    "hard and soft lifetimes", BUNYAN_T_END);
		/* XXX: ignore? */
	}

	bunyan_debug(pflog, "Handling SADB soft expire message", BUNYAN_T_END);
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
	bunyan_trace(pflog, "Handling SADB delete", BUNYAN_T_END);

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

	parsedmsg_t pmsg;

	bunyan_debug(pflog, "Handling SADB acquire", BUNYAN_T_END);

	if (!extract_exts(samsg, &pmsg, 1, SADB_EXT_PROPOSAL)) {
		bunyan_info(pflog, "No proposal found in ACQUIRE message",
		    BUNYAN_T_END);
		free(samsg);
		return;
	}

	/* XXX KEBE SAYS FILL ME IN! */
	free(samsg);
}

static void *
pfkey_thread(void *arg)
{
	port_event_t pe;
	boolean_t stop = B_FALSE;

	(void) bunyan_trace(pflog, "pfkey thread starting", BUNYAN_T_END);

	while (!stop) {
		if (port_get(pfport, &pe, NULL) < 0) {
			STDERR(fatal, pflog, "port_get() failed");
			exit(EXIT_FAILURE);
		}

		(void) bunyan_debug(pflog, "Received port event",
		    BUNYAN_T_INT32, "event", pe.portev_events,
		    BUNYAN_T_STRING, "source",
		    port_source_str(pe.portev_source),
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
	sadb_msg_t *samsg = (sadb_msg_t *)buffer;
	ssize_t n;
	uint32_t msgid = atomic_inc_32_nv(&msgid);
	pid_t pid = getpid();

	CTASSERT(sizeof (buffer) >= sizeof (*samsg));

	samsg->sadb_msg_version = PF_KEY_V2;
	samsg->sadb_msg_type = SADB_REGISTER;
	samsg->sadb_msg_errno = 0;
	samsg->sadb_msg_satype = satype;
	samsg->sadb_msg_reserved = 0;
	samsg->sadb_msg_seq = msgid;
	samsg->sadb_msg_pid = pid;
	samsg->sadb_msg_len = SADB_8TO64(sizeof (*samsg));

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
		bunyan_error(pflog, "Protocol not supported",
		    BUNYAN_T_UINT32, "msg_satype",
		    (uint32_t)samsg->sadb_msg_satype, BUNYAN_T_END);
	}

	bunyan_debug(pflog, "Initial REGISTER with SADB",
	    BUNYAN_T_STRING, "satype", pfkey_satype(samsg->sadb_msg_satype),
	    BUNYAN_T_END);

	handle_register(samsg);
}

static void
sadb_log(bunyan_logger_t *restrict blog, bunyan_level_t level,
    const char *restrict msg, sadb_msg_t *restrict samsg)
{
	getlog(level)(blog, msg,
	    BUNYAN_T_STRING, "msg_type", pfkey_type(samsg->sadb_msg_type),
	    BUNYAN_T_UINT32, "msg_type_val", (uint32_t)samsg->sadb_msg_type,
	    BUNYAN_T_STRING, "sa_type", pfkey_satype(samsg->sadb_msg_satype),
	    BUNYAN_T_UINT32, "sa_type_val", (uint32_t)samsg->sadb_msg_satype,
	    BUNYAN_T_UINT32, "msg_pid", samsg->sadb_msg_pid,
	    BUNYAN_T_UINT32, "msg_seq", samsg->sadb_msg_seq,
	    BUNYAN_T_UINT32, "msg_errno_val", (uint32_t)samsg->sadb_msg_errno,
	    BUNYAN_T_STRING, "msg_errno", strerror(samsg->sadb_msg_errno),
	    BUNYAN_T_UINT32, "msg_diagnostic_val",
	    (uint32_t)samsg->sadb_x_msg_diagnostic,
	    BUNYAN_T_UINT32, "msg_diagnostic",
	    keysock_diag(samsg->sadb_x_msg_diagnostic),
	    BUNYAN_T_UINT32, "length", (uint32_t)samsg->sadb_msg_len,
	    BUNYAN_T_END);
}

void
pfkey_init(void)
{
	int rc;

	list_create(&pfreq_list, sizeof (pfreq_t), offsetof (pfreq_t, pr_node));

	pfport = port_create();
	if (pfport == -1)
		err(EXIT_FAILURE, "Unable to create pfkey event port");

	pfsock = socket(PF_KEY, SOCK_RAW, PF_KEY_V2);
	if (pfsock == -1)
		err(EXIT_FAILURE, "Unable to create pf_key socket");

	rc = bunyan_child(log, &pflog,
	    BUNYAN_T_INT32, "pfsock", (int32_t)pfsock,
	    BUNYAN_T_END);

	if (rc != 0) {
		errx(EXIT_FAILURE, "Unable to create child logger: %s",
		    strerror(rc));
	}

	pfkey_register(SADB_SATYPE_ESP);
	pfkey_register(SADB_SATYPE_AH);

	pfkey_arm(pfsock);
}
