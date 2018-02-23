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
#include <strings.h>
#include <synch.h>
#include <time.h>
#include "config.h"
#include "defs.h"
#include "ikev2.h"
#include "ikev2_common.h"
#include "ikev2_enum.h"
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
#define	PFKEY_K_ENCR_KEY "encr_key"
#define	PFKEY_K_ENCR_KEYLEN "encr_keylen"
#define	PFKEY_K_AUTH_KEY "auth_key"
#define	PFKEY_K_AUTH_KEYLEN "auth_keylen"
#define	PFKEY_K_FLAGS "sadb_sa_flags"
#define	PFKEY_K_KMC_PROTO "kmc_proto"
#define	PFKEY_K_KMC_COOKIE "kmc_cookie"

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
	PFKEY_K_ENCR_KEY,
	PFKEY_K_ENCR_KEYLEN,
	PFKEY_K_AUTH_KEY,
	PFKEY_K_AUTH_KEYLEN,
	PFKEY_K_FLAGS,
	PFKEY_K_KMC_PROTO,
	PFKEY_K_KMC_COOKIE,
};

#define	PFKEY_MSG_LEN(msg, ext) \
    SADB_8TO64((size_t)((uint8_t *)ext - (uint8_t *)msg))
#define	ROUND64(val) P2ROUNDUP(val, sizeof (uint64_t))

typedef struct pfreq {
	list_node_t	pr_node;
	pid_t		pr_pid;
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

#ifdef notyet
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
#endif

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
	 * For now don't print the full inbound message.  An
	 * "ipseckey monitor" instance is useful here.
	 */

	/*
	 * If it might be a reply to us, handle it.  Anything from the kernel
	 * with our pid is always a reply, however we also send SADB_GETSPI,
	 * SADB_ADD, and SADB_UPDATE messages to the kernel using the pid/seq
	 * of an earlier kernel initiated SADB_ACQUIRE msg when those requests
	 * are made in response to that SADB_ACQUIRE (per PF_KEY(7P)).  The
	 * will not have our pid, but the kernel only ever sends those
	 * messages as replies to a user, so we can safely treat them as
	 * replies.
	 */
	if (samsg->sadb_msg_pid == getpid() ||
	    samsg->sadb_msg_type == SADB_GETSPI ||
	    samsg->sadb_msg_type == SADB_ADD ||
	    samsg->sadb_msg_type == SADB_UPDATE) {
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
	req.pr_pid = msg->sadb_msg_pid;
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
			(void) bunyan_error(log, "pf_key timeout",
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
	VERIFY0(mutex_destroy(&req.pr_lock));
	VERIFY0(cond_destroy(&req.pr_cv));
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
 * Copy an existing extension.  If type != 0, type of the destination
 * extension is explicitly set to the given value (e.g. changing a
 * SADB_EXT_ADDRESS_SRC to SADB_EXT_ADDRESS_DST), otherwise the source
 * extentsion type is preserved.
 */
sadb_ext_t *
pfkey_add_ext(sadb_ext_t *dest, uint16_t type, const sadb_ext_t *src)
{
	if (src == NULL)
		return (dest);

	size_t len = SADB_64TO8(src->sadb_ext_len);

	bcopy(src, dest, len);
	if (type != SADB_EXT_RESERVED)
		dest->sadb_ext_type = type;

	/* LINTED E_BAD_PTR_CAST_ALIGN */
	return ((sadb_ext_t *)((uint8_t *)dest + len));
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
    const struct sockaddr *restrict addr, uint8_t prefixlen, uint8_t proto)
{
	sadb_address_t *sadb_addr = (sadb_address_t *)ext;
	size_t addrlen = 0;
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

	if (addr == NULL)
		return (ext);

	switch (addr->sa_family) {
	case AF_INET:
		addrlen = sizeof (struct sockaddr_in);
		break;
	case AF_INET6:
		addrlen = sizeof (struct sockaddr_in6);
		break;
	default:
		INVALID(su.sau_ss->ss_family);
	}
	bcopy(addr, sadb_addr + 1, addrlen);

	len = sizeof (*sadb_addr) + addrlen;
	sadb_addr->sadb_address_len = SADB_8TO64(len);
	sadb_addr->sadb_address_exttype = type;
	sadb_addr->sadb_address_prefixlen = prefixlen;
	sadb_addr->sadb_address_proto = proto;

	/* LINTED E_BAD_PTR_CAST_ALIGN */
	return ((sadb_ext_t *)((uint8_t *)ext + len));
}

sadb_ext_t *
pfkey_add_sa(sadb_ext_t *restrict ext, uint32_t spi, ikev2_xf_encr_t i2encr,
    ikev2_xf_auth_t i2auth, uint32_t flags)
{
	sadb_sa_t *sa = (sadb_sa_t *)ext;
	int encr = ikev2_encr_to_pfkey(i2encr);
	int auth = ikev2_auth_to_pfkey(i2auth);

	/*
	 * We shouldn't negotiate anything we don't support nor should we
	 * return an out of range value when translating to pf_key values.
	 */
	VERIFY3S(auth, >=, 0);
	VERIFY3S(auth, <=, UINT8_MAX);
	VERIFY3S(encr, >=, 0);
	VERIFY3S(encr, <=, UINT8_MAX);

	sa->sadb_sa_len = SADB_8TO64(sizeof (*sa));
	sa->sadb_sa_exttype = SADB_EXT_SA;
	sa->sadb_sa_spi = spi;
	sa->sadb_sa_auth = (uint8_t)auth;
	sa->sadb_sa_encrypt = (uint8_t)encr;
	sa->sadb_sa_flags = flags;
	sa->sadb_sa_state = SADB_SASTATE_MATURE;

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
	size_t len = sizeof (*id) + ROUND64(config_id_strlen(cid));

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

	/* LINTED E_BAD_PTR_CAST_ALIGN */
	return ((sadb_ext_t *)((uint8_t *)ext + len));
}

sadb_ext_t *
pfkey_add_key(sadb_ext_t *restrict ext, uint16_t type, const uint8_t *key,
    size_t keylen)
{
	sadb_key_t *skey = (sadb_key_t *)ext;
	size_t len = sizeof (sadb_key_t) + ROUND64(keylen);

	switch (type) {
	case SADB_EXT_KEY_AUTH:
	case SADB_EXT_KEY_ENCRYPT:
		break;
	default:
		INVALID(type);
	}

	if (keylen == 0)
		return (ext);

	skey->sadb_key_len = SADB_8TO64(len);
	skey->sadb_key_exttype = type;
	skey->sadb_key_bits = SADB_8TO1(keylen);
	bcopy(key, skey + 1, keylen);

	/* LINTED E_BAD_PTR_CAST_ALIGN */
	return ((sadb_ext_t *)((uint8_t *)ext + len));
}

sadb_ext_t *
pfkey_add_pair(sadb_ext_t *ext, uint32_t spi)
{
	sadb_x_pair_t *pair = (sadb_x_pair_t *)ext;

	if (spi == 0)
		return (ext);

	pair->sadb_x_pair_len = SADB_8TO64(sizeof (*pair));
	pair->sadb_x_pair_exttype = SADB_X_EXT_PAIR;
	pair->sadb_x_pair_spi = spi;
	return ((sadb_ext_t *)(pair + 1));
}

sadb_ext_t *
pfkey_add_lifetime(const config_rule_t *restrict rule, sadb_ext_t *restrict ext)
{
#define	VAL(c, r, v) (((r)->rule_##v != 0) ? (r)->rule_##v : (c)->cfg_##v)
	sadb_lifetime_t *life = (sadb_lifetime_t *)ext;
	uint64_t softlife_secs = VAL(config, rule, p2_softlife_secs);
	uint64_t softlife_kb = VAL(config, rule, p2_softlife_kb);
	uint64_t hardlife_secs = VAL(config, rule, p2_lifetime_secs);
	uint64_t hardlife_kb = VAL(config, rule, p2_lifetime_kb);
	uint64_t idletime_secs = VAL(config, rule, p2_idletime_secs);
#undef VAL

	VERIFY(IS_WORKER);

	if (hardlife_secs > 0 || hardlife_kb > 0) {
		life->sadb_lifetime_len = SADB_8TO64(sizeof (*life));
		life->sadb_lifetime_exttype = SADB_EXT_LIFETIME_HARD;
		life->sadb_lifetime_addtime = hardlife_secs;
		life->sadb_lifetime_bytes = hardlife_kb * 1024;
		life++;
	}

	if (softlife_secs > 0 || softlife_kb > 0) {
		life->sadb_lifetime_len = SADB_8TO64(sizeof (*life));
		life->sadb_lifetime_exttype = SADB_EXT_LIFETIME_SOFT;
		life->sadb_lifetime_addtime = softlife_secs;
		life->sadb_lifetime_bytes = softlife_kb * 1024;
		life++;
	}

	if (idletime_secs > 0) {
		life->sadb_lifetime_len = SADB_8TO64(sizeof (*life));
		life->sadb_lifetime_exttype = SADB_X_EXT_LIFETIME_IDLE;
		life->sadb_lifetime_addtime = idletime_secs;
		life++;
	}

	return ((sadb_ext_t *)life);
}

sadb_ext_t *
pfkey_add_kmc(sadb_ext_t *ext, uint32_t proto, uint64_t cookie)
{
	sadb_x_kmc_t *kmc = (sadb_x_kmc_t *)ext;

	kmc->sadb_x_kmc_len = SADB_8TO64(sizeof (*kmc));
	kmc->sadb_x_kmc_exttype = SADB_X_EXT_KM_COOKIE;
	kmc->sadb_x_kmc_proto = proto;
	kmc->sadb_x_kmc_cookie64 = cookie;

	return ((sadb_ext_t *)(kmc + 1));
}

boolean_t
pfkey_sadb_add_update(ikev2_sa_t *restrict sa,
    ikev2_child_sa_t *restrict csa, const uint8_t *restrict encrkey,
    const uint8_t *restrict authkey, const parsedmsg_t *restrict srcmsg)
{
	parsedmsg_t *pmsg = NULL;
	sadb_msg_t *msg = NULL;
	sadb_ext_t *ext = NULL;
	size_t msglen = 0, encrlen = 0, authlen = 0;
	uint32_t pair = (csa->i2c_pair != NULL) ? csa->i2c_pair->i2c_spi : 0;
	uint32_t flags = 0;
	ts_t *ts_src = I2C_SRC(csa);
	ts_t *ts_dst = I2C_DST(csa);
	struct sockaddr *natt_l = NULL, *natt_r = NULL;
	const config_id_t *id_src = I2C_SRC_ID(sa, csa);
	const config_id_t *id_dst = I2C_DST_ID(sa, csa);
	uint16_t srctype = SADB_X_EXT_ADDRESS_INNER_SRC;
	uint16_t dsttype = SADB_X_EXT_ADDRESS_INNER_DST;
	uint8_t satype = ikev2_to_satype(csa->i2c_satype);
	boolean_t ret = B_FALSE;

	encrlen = SADB_1TO8(csa->i2c_encr_keylen + csa->i2c_encr_saltlen);
	authlen = auth_data(csa->i2c_auth)->ad_keylen;

	/*
	 * Worst case msg length:
	 *	base, SA, lifetime(HSI), address(SD), address(Is, Id),
	 *	address(Nl, Nr), key(AE), identity(SD), pair, kmc
	 *
	 * Note that the sadb_* types are already include padding for 64-bit
	 * alignment, so they don't need to be rounded up.
	 */

	msglen = sizeof (*msg) + sizeof (sadb_sa_t) +
	    3 * sizeof (sadb_lifetime_t) +
	    6 * (sizeof (sadb_address_t) +
	    ROUND64(sizeof (struct sockaddr_storage))) +
	    sizeof (sadb_key_t) + ROUND64(encrlen) +
	    sizeof (sadb_key_t) + ROUND64(authlen) +
	    sizeof (sadb_ident_t) + ROUND64(config_id_strlen(sa->local_id)) +
	    sizeof (sadb_ident_t) + ROUND64(config_id_strlen(sa->remote_id)) +
	    sizeof (sadb_x_pair_t) + sizeof (sadb_x_kmc_t);

	if (sa->flags & I2SA_INITIATOR)
		flags |= IKEV2_SADB_INITIATOR;

	flags |= csa->i2c_inbound ?
	    SADB_X_SAFLAGS_INBOUND : SADB_X_SAFLAGS_OUTBOUND;

	if (!csa->i2c_transport)
		flags |= SADB_X_SAFLAGS_TUNNEL;

	if ((sa->flags & I2SA_NAT_LOCAL) && csa->i2c_transport) {
		flags |= SADB_X_SAFLAGS_NATT_LOC;
		natt_l= SSTOSA(&sa->lnatt);
	}
	if ((sa->flags & I2SA_NAT_REMOTE) && csa->i2c_transport) {
		flags |= SADB_X_SAFLAGS_NATT_REM;
		natt_r = SSTOSA(&sa->rnatt);
	}

	msg = umem_zalloc(msglen, UMEM_DEFAULT);
	if (msg == NULL) {
		(void) bunyan_error(log, "No memory for pfkey request",
		    BUNYAN_T_END);
		return (B_FALSE);
	}

	/*
	 * If the source message originated from the kernel (pid == 0),
	 * we want to use it's pid/seq value so it can tie the SAs we're
	 * creating/updating back to the original packets that triggered
	 * the creation request.
	 */
	pfkey_msg_init(PMSG_FROM_KERNEL(srcmsg) ? srcmsg->pmsg_samsg : NULL,
	    msg, csa->i2c_inbound ? SADB_UPDATE : SADB_ADD, satype);

	ext = (sadb_ext_t *)(msg + 1);
	ext = pfkey_add_sa(ext, csa->i2c_spi, csa->i2c_encr, csa->i2c_auth,
	    flags);
	ext = pfkey_add_lifetime(sa->i2sa_rule, ext);

	if (csa->i2c_transport) {
		srctype = SADB_EXT_ADDRESS_SRC;
		dsttype = SADB_EXT_ADDRESS_DST;
	} else {
		/*
		 * For tunnel mode, reuse the SRC/DST addresses from our
		 * ACQUIRE or INVERSE_ACQUIRE, though we need to flip
		 * SRC/DST for the inbound SA.
		 */
		ext = pfkey_add_ext(ext,
		    csa->i2c_inbound ? SADB_EXT_ADDRESS_DST : 0,
		    srcmsg->pmsg_exts[SADB_EXT_ADDRESS_SRC]);
		ext = pfkey_add_ext(ext,
		    csa->i2c_inbound ? SADB_EXT_ADDRESS_SRC : 0,
		    srcmsg->pmsg_exts[SADB_EXT_ADDRESS_DST]);
	}

	/*
	 * But always want to use the negotiated traffic selectors add the
	 * addresses for the actual traffic being sent.
	 */
	ext = pfkey_add_address(ext, srctype,
	    &ts_src->ts_sa, TS_SADB_PREFIX(ts_src), ts_src->ts_proto);
	ext = pfkey_add_address(ext, dsttype,
	    &ts_dst->ts_sa, TS_SADB_PREFIX(ts_dst), ts_dst->ts_proto);

	/* These are no-ops of the address argument is NULL */
	ext = pfkey_add_address(ext, SADB_X_EXT_ADDRESS_NATT_LOC,
	    (struct sockaddr *)natt_l, 0, 0);
	ext = pfkey_add_address(ext, SADB_X_EXT_ADDRESS_NATT_REM,
	    (struct sockaddr *)natt_r, 0, 0);

	ext = pfkey_add_key(ext, SADB_EXT_KEY_AUTH, authkey, authlen);
	ext = pfkey_add_key(ext, SADB_EXT_KEY_ENCRYPT, encrkey, encrlen);

	ext = pfkey_add_identity(ext, SADB_EXT_IDENTITY_SRC, id_src);
	ext = pfkey_add_identity(ext, SADB_EXT_IDENTITY_DST, id_dst);

	ext = pfkey_add_pair(ext, pair);

	ext = pfkey_add_kmc(ext, SADB_X_KMP_IKEV2, I2SA_LOCAL_SPI(sa));

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
		(void) bunyan_debug(log, "Added IPsec SA",
		    BUNYAN_T_STRING, "satype", ikev2_spi_str(csa->i2c_satype),
		    BUNYAN_T_STRING, "spi",
		    enum_printf("0x%" PRIX32, ntohl(csa->i2c_spi)),
		    BUNYAN_T_END);

		ret = B_TRUE;
	}

	umem_free(msg, msglen);
	parsedmsg_free(pmsg);
	return (ret);
}

boolean_t
pfkey_getspi(const parsedmsg_t *restrict srcmsg, uint8_t satype,
    uint32_t *restrict spip)
{
	uint64_t buffer[128] = { 0 };
	const sadb_msg_t *src_sadb_msg = NULL;
	parsedmsg_t *resp = NULL;
	sadb_ext_t *src = NULL, *dst = NULL, *ext = NULL;
	sadb_msg_t *samsg = (sadb_msg_t *)buffer;
	boolean_t ret;

	/*
	 * Use sizeof (struct sockaddr_storage) as worst case address size
	 * for compile time check
	 */
	CTASSERT(sizeof (buffer) >= sizeof (*samsg) +
	    2 * (sizeof (sadb_address_t) + sizeof (struct sockaddr_storage)) +
	    sizeof (sadb_spirange_t));

	*spip = 0;

	if (PMSG_FROM_KERNEL(srcmsg))
		src_sadb_msg = srcmsg->pmsg_samsg;

	/*
	 * The address extensions in srcmsg are based on outbound traffic,
	 * however we are reserving the inbound SPI, so src/dst are reversed.
	 */
	src = srcmsg->pmsg_exts[SADB_EXT_ADDRESS_DST];
	dst = srcmsg->pmsg_exts[SADB_EXT_ADDRESS_SRC];
	VERIFY3U(srcmsg->pmsg_sss->ss_family, ==, srcmsg->pmsg_dss->ss_family);

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
		bzero(buffer, sizeof (buffer));

		pfkey_msg_init(src_sadb_msg, samsg, SADB_GETSPI, satype);
		ext = (sadb_ext_t *)(samsg + 1);

		ext = pfkey_add_ext(ext, SADB_EXT_ADDRESS_SRC, src);
		ext = pfkey_add_ext(ext, SADB_EXT_ADDRESS_DST, dst);
		ext = pfkey_add_range(ext, 1, UINT32_MAX);

		samsg->sadb_msg_len = PFKEY_MSG_LEN(samsg, ext);

		errno = 0;
		(void) pfkey_send_msg(samsg, &resp, 1, SADB_EXT_SA);
		if (resp == NULL || resp->pmsg_samsg == NULL) {
			parsedmsg_free(resp);
			return (B_FALSE);
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

		*spip = sa->sadb_sa_spi;

		(void) bunyan_debug(log, "Allocated larval IPsec SA",
		    BUNYAN_T_STRING, "satype", pfkey_satype_str(satype),
		    BUNYAN_T_STRING, "spi",
		    enum_printf("0x%" PRIX32, ntohl(*spip)),
		    BUNYAN_T_END);
	}

	ret = (resp->pmsg_samsg->sadb_msg_errno == 0) ? B_TRUE : B_FALSE;
	parsedmsg_free(resp);
	return (ret);
}

boolean_t
pfkey_inverse_acquire(const ts_t *src, const ts_t *dst, const ts_t *isrc,
    const ts_t *idst, parsedmsg_t **resp)
{
	uint64_t buffer[128] = { 0 };
	sadb_msg_t *msg = (sadb_msg_t *)buffer;
	sadb_ext_t *ext = (sadb_ext_t *)(msg + 1);

	VERIFY3U(src->ts_ss.ss_family, ==, dst->ts_ss.ss_family);

	/*
	 * The inner addresses (if present) can be a different address family
	 * than the outer addresses, but the inner source and inner destination
	 * address families should agree with each other.
	 */
	if (isrc != NULL)
		VERIFY3U(isrc->ts_ss.ss_family, ==, idst->ts_ss.ss_family);

	pfkey_msg_init(NULL, msg, SADB_X_INVERSE_ACQUIRE, SADB_SATYPE_UNSPEC);

	ext = pfkey_add_address(ext, SADB_EXT_ADDRESS_SRC,
	    &src->ts_sa, src->ts_prefix, src->ts_proto);
	ext = pfkey_add_address(ext, SADB_EXT_ADDRESS_DST,
	    &dst->ts_sa, dst->ts_prefix, dst->ts_proto);
	if (isrc != NULL) {
		ext = pfkey_add_address(ext, SADB_X_EXT_ADDRESS_INNER_SRC,
		    &isrc->ts_sa, isrc->ts_prefix, isrc->ts_proto);
		ext = pfkey_add_address(ext, SADB_X_EXT_ADDRESS_INNER_DST,
		    &idst->ts_sa, idst->ts_prefix, idst->ts_proto);
	}

	msg->sadb_msg_len = PFKEY_MSG_LEN(msg, ext);
	errno = 0;
	return (pfkey_send_msg(msg, resp, 1, SADB_X_EXT_EPROP));
}

/*
 * XXX: Are there any scenarios where we could do something if SADB_DELETE
 * fails? Or should we change this to return void?
 */
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

	ext = pfkey_add_sa(ext, spi, 0, 0, 0);
	ext = pfkey_add_address(ext, SADB_EXT_ADDRESS_SRC, src.sau_sa, 0, 0);
	ext = pfkey_add_address(ext, SADB_EXT_ADDRESS_DST, dst.sau_sa, 0, 0);

	msg->sadb_msg_len = PFKEY_MSG_LEN(msg, ext);

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
	while (req != NULL) {
		if (req->pr_msgid == reply->sadb_msg_seq &&
		    req->pr_pid == reply->sadb_msg_pid)
			break;

		req = list_next(&pfreq_list, req);
	}

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

#ifdef notyet
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
#endif

/*
 * XXX: We can probably simplify a lot of the handle_* functions here and
 * just do some basic validations and call worker_send_cmd() to queue.
 */
static void
handle_expire(sadb_msg_t *samsg)
{
	parsedmsg_t *pmsg;

	pmsg = calloc(1, sizeof (*pmsg));
	if (pmsg == NULL) {
		(void) bunyan_error(log, "No memory to handle SADB message",
		    BUNYAN_T_END);
		free(samsg);
		return;
	}

	/*
	 * If SOFT expire, see if the SADB_X_SAFLAGS_KM1 (initiator) is set,
	 * if so, consider treating this expire as an ACQUIRE message if
	 * no IKE SA is found.
	 *
	 * If HARD expire, treat this message like a DELETE.
	 *
	 * If IDLE expire, see if we need to do a little DPD or not.
	 */

	if (!extract_exts(samsg, pmsg, 1, SADB_EXT_SA)) {
		(void) bunyan_error(log,
		    "SADB_EXPIRE message is missing an SA extension",
		    BUNYAN_T_END);
		parsedmsg_free(pmsg);
		return;
	}

	if (!worker_send_cmd(WC_PFKEY, pmsg))
		parsedmsg_free(pmsg);
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

	if (!worker_send_cmd(WC_PFKEY, pmsg))
		parsedmsg_free(pmsg);
}

static void *
pfkey_thread(void *arg)
{
	port_event_t pe;
	boolean_t stop = B_FALSE;

	log = arg;

	(void) bunyan_trace(log, "pfkey thread starting", BUNYAN_T_END);

	while (!stop) {
		if (port_get(pfport, &pe, NULL) < 0) {
			STDERR(fatal, "port_get() failed");
			exit(EXIT_FAILURE);
		}

		(void) bunyan_debug(log, "Received port event",
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
		    pfkey_satype_str(samsg->sadb_msg_satype),
		    BUNYAN_T_END);
	}

	(void) bunyan_debug(log, "Initial REGISTER with SADB",
	    BUNYAN_T_STRING, "satype", pfkey_satype_str(samsg->sadb_msg_satype),
	    BUNYAN_T_END);

	handle_register(samsg);
}

static void
sadb_log_sa(sadb_ext_t *ext)
{
	sadb_sa_t *sa = (sadb_sa_t *)ext;
	const char *estr = NULL, *astr = NULL, *flagstr = NULL;
	char buf[11] = { 0 }; /* 0x + 8 hex digits + NUL */

#define	ESTR(x, s) case x: s = #x; break
	switch (sa->sadb_sa_encrypt) {
	ESTR(SADB_EALG_NONE, estr);
	ESTR(SADB_EALG_DESCBC, estr);
	ESTR(SADB_EALG_3DESCBC, estr);
	ESTR(SADB_EALG_BLOWFISH, estr);
	ESTR(SADB_EALG_NULL, estr);
	ESTR(SADB_EALG_AES, estr);
	ESTR(SADB_EALG_AES_CCM_8, estr);
	ESTR(SADB_EALG_AES_CCM_12, estr);
	ESTR(SADB_EALG_AES_CCM_16, estr);
	ESTR(SADB_EALG_AES_GCM_8, estr);
	ESTR(SADB_EALG_AES_GCM_12, estr);
	ESTR(SADB_EALG_AES_GCM_16, estr);
	default:
		estr = enum_printf("%hhu", sa->sadb_sa_encrypt);
		break;
	}

	switch (sa->sadb_sa_auth) {
	ESTR(SADB_AALG_NONE, astr);
	ESTR(SADB_AALG_SHA256HMAC, astr);
	ESTR(SADB_AALG_SHA384HMAC, astr);
	ESTR(SADB_AALG_SHA512HMAC, astr);
	ESTR(SADB_AALG_MD5HMAC, astr);
	ESTR(SADB_AALG_SHA1HMAC, astr);
	default:
		astr = enum_printf("%hhu", sa->sadb_sa_auth);
		break;
	}
#undef ESTR

	flagstr = enum_printf("0x%" PRIx32, sa->sadb_sa_flags);

	/*
	 * ipseckey(1M) treats SPI values in pf_key(7P) messages as being in
	 * network byte order when printing them.  We do the same.
	 */
	(void) snprintf(buf, sizeof (buf), "0x%" PRIx32,
	    ntohl(sa->sadb_sa_spi));

	(void) bunyan_key_add(log,
	    BUNYAN_T_STRING, PFKEY_K_SPI, buf,
	    BUNYAN_T_STRING, PFKEY_K_ENCR, estr,
	    BUNYAN_T_STRING, PFKEY_K_AUTH, astr,
	    BUNYAN_T_STRING, PFKEY_K_FLAGS, flagstr,
	    BUNYAN_T_END);
}

static void
sadb_log_pair(sadb_ext_t *ext)
{
	sadb_x_pair_t *pair = (sadb_x_pair_t *)ext;
	char buf[11] = { 0 };

	(void) snprintf(buf, sizeof (buf), "0x%" PRIx32,
	    ntohl(pair->sadb_x_pair_spi));
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
	const char *portstr = NULL;
	const char *protostr = NULL;
	uint32_t port = ss_port(su.sau_sa);

	if ((pe = getprotobynumber(addr->sadb_address_proto)) == NULL)
		protostr = enum_printf("%hhu", addr->sadb_address_proto);
	else
		protostr = pe->p_name;

	portstr = (port == 0) ? "any" : enum_printf("%u", port);

	size_t plen = strlen(portstr) + strlen(protostr) + 2; /* '/' + NUL */
	char pstr[plen];

	(void) snprintf(pstr, plen, "%s/%s", protostr, portstr);

	(void) bunyan_key_add(log,
	    BUNYAN_T_STRING, portname, pstr, BUNYAN_T_END);
}

static void
sadb_log_key(sadb_ext_t *ext)
{
	const char *kstr = NULL;
	const char *klenstr = NULL;
	sadb_key_t *key = (sadb_key_t *)ext;
	size_t klen = SADB_64TO8(key->sadb_key_len) - sizeof (*key);
	size_t slen = klen * 2 + 1;
	char str[slen];

	switch (ext->sadb_ext_type) {
	case SADB_EXT_KEY_AUTH:
		kstr = PFKEY_K_AUTH_KEY;
		klenstr = PFKEY_K_AUTH_KEYLEN;
		break;
	case SADB_EXT_KEY_ENCRYPT:
		kstr = PFKEY_K_ENCR_KEY;
		klenstr = PFKEY_K_ENCR_KEYLEN;
		break;
	default:
		INVALID(ext->sadb_ext_type);
	}

	if (show_keys)
		(void) writehex((uint8_t *)(key + 1), klen, "", str, slen);
	else
		(void) strlcpy(str, "xxx", slen);

	(void) bunyan_key_add(log,
	    BUNYAN_T_STRING, kstr, str,
	    BUNYAN_T_UINT32, klenstr, key->sadb_key_bits,
	    BUNYAN_T_END);

	explicit_bzero(str, slen);
}

static void
sadb_log_kmc(sadb_ext_t *ext)
{
	sadb_x_kmc_t *kmc = (sadb_x_kmc_t *)ext;
	const char *proto = NULL;
	char kmcstr[19] = { 0 }; /* 0x + 64 bit hex + NUL */

	switch (kmc->sadb_x_kmc_proto) {
	case SADB_X_KMP_MANUAL:
		proto = "MANUAL";
		break;
	case SADB_X_KMP_IKE:
		proto = "IKEv1";
		break;
	case SADB_X_KMP_KINK:
		proto = "KINK";
		break;
	case SADB_X_KMP_IKEV2:
		proto = "IKEv2";
		break;
	default:
		proto = enum_printf("0x%" PRIu32, kmc->sadb_x_kmc_proto);
		break;
	}

	(void) snprintf(kmcstr, sizeof (kmcstr), "0x%" PRIx64,
	    kmc->sadb_x_kmc_cookie64);

	(void) bunyan_key_add(log,
	    BUNYAN_T_STRING, PFKEY_K_KMC_PROTO, proto,
	    BUNYAN_T_STRING, PFKEY_K_KMC_COOKIE, kmcstr,
	    BUNYAN_T_END);
}

void
sadb_log(bunyan_level_t level, const char *restrict msg,
    sadb_msg_t *restrict samsg)
{
	bunyan_logfn_t logf = getlog(level);
	sadb_ext_t *ext, *end;

	end = (sadb_ext_t *)((uint64_t *)samsg + samsg->sadb_msg_len);
	ext = (sadb_ext_t *)(samsg + 1);

	while (ext < end) {
		switch (ext->sadb_ext_type) {
		case SADB_EXT_SA:
			sadb_log_sa(ext);
			break;
		case SADB_EXT_KEY_AUTH:
		case SADB_EXT_KEY_ENCRYPT:
			sadb_log_key(ext);
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
		case SADB_X_EXT_KM_COOKIE:
			sadb_log_kmc(ext);
			break;
		}

		ext = (sadb_ext_t *)((uint64_t *)ext + ext->sadb_ext_len);
	}

	logf(log, msg,
	    BUNYAN_T_STRING, "msg_type",
	    pfkey_op_str(samsg->sadb_msg_type),
	    BUNYAN_T_STRING, "sa_type",
	    pfkey_satype_str(samsg->sadb_msg_satype),
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
		return (SADB_EALG_NONE);
	case IKEV2_ENCR_DES:
		return (SADB_EALG_DESCBC);
	case IKEV2_ENCR_3DES:
		return (SADB_EALG_3DESCBC);
	case IKEV2_ENCR_BLOWFISH:
		return (SADB_EALG_BLOWFISH);
	case IKEV2_ENCR_NULL:
		return (SADB_EALG_NULL);
	case IKEV2_ENCR_AES_CBC:
		return (SADB_EALG_AES);
	case IKEV2_ENCR_AES_CCM_8:
		return (SADB_EALG_AES_CCM_8);
	case IKEV2_ENCR_AES_CCM_12:
		return (SADB_EALG_AES_CCM_12);
	case IKEV2_ENCR_AES_CCM_16:
		return (SADB_EALG_AES_CCM_16);
	case IKEV2_ENCR_AES_GCM_8:
		return (SADB_EALG_AES_GCM_8);
	case IKEV2_ENCR_AES_GCM_12:
		return (SADB_EALG_AES_GCM_12);
	case IKEV2_ENCR_AES_GCM_16:
		return (SADB_EALG_AES_GCM_16);
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
