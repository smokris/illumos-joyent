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

#include <sys/types.h>
#include <net/pfkeyv2.h>
#include <ipsec_util.h>
#include <string.h>
#include <errno.h>
#include <locale.h>
#include <netdb.h>
#include <stdio.h>
#include <note.h>
#include <atomic.h>
#include <pthread.h>
#include <sys/list.h>
#include <sys/stropts.h>	/* For I_NREAD */
#include <bunyan.h>
#include <ucontext.h>

#include "defs.h"
#include "ikev2.h"
#include "ikev2_pkt.h"
#include "ikev2_sa.h"
#include "inbound.h"
#include "pkcs11.h"

struct pfreq;
typedef struct pfreq {
	list_node_t	pr_node;
	pfreq_cb_t	*pr_cb;
	void		*pr_data;
	uint32_t	pr_msgid;
} pfreq_t;

static bunyan_logger_t	*pflog;
static umem_cache_t	*pfreq_cache;
static pthread_mutex_t	pfreq_lock = PTHREAD_MUTEX_INITIALIZER;
static list_t		pfreq_list;

/* PF_KEY socket. */
int pfkey;

/* our msgids */
static volatile uint32_t msgid = 0;

static int pfreq_ctor(void *, void *, int);
static pfreq_t *pfreq_new(pfreq_cb_t *, void *);
static void pfreq_free(pfreq_t *);

static void handle_reply(sadb_msg_t *);
static void handle_delete(sadb_msg_t *);
static void handle_flush(sadb_msg_t *);
static void handle_expire(sadb_msg_t *);
static void handle_acquire(sadb_msg_t *, boolean_t);
static void handle_register(sadb_msg_t *);

static void sadb_log(bunyan_logger_t *restrict, bunyan_level_t,
    const char *restrict, sadb_msg_t *restrict);

#if 0
static ikev2_pay_sa_t *convert_acquire(parsedmsg_t *);
static ikev2_pay_sa_t *convert_ext_acquire(parsedmsg_t *, ikev2_spi_proto_t);
static ikev2_xf_auth_t ikev2_pf_to_auth(int);
#endif

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
extract_exts(sadb_msg_t *samsg, parsedmsg_t *pmsg, int numexts, ...)
{
	sadb_ext_t *ext;
	sadb_ext_t **exts = pmsg->pmsg_exts;
	int current_ext;
	va_list ap;
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

	va_start(ap, numexts);
	while (numexts-- > 0) {
		current_ext = va_arg(ap, int);
		if (exts[current_ext] == NULL) {
			rc = B_FALSE;
			break;
		}
	}
	va_end(ap);

	return (rc);
}

static void
pfkey_inbound(int s)
{
	sadb_msg_t *samsg;
	ssize_t rc;
	int length;

	if (ioctl(s, I_NREAD, &length) < 0) {
		STDERR(error, log, "ioctl(I_NREAD) failed");
		schedule_socket(s, pfkey_inbound);
		return;
	}

	if (length == 0) {
		bunyan_info(log, "ioctl: zero length message",
		    BUNYAN_T_STRING, "func", __func__,
		    BUNYAN_T_STRING, "file", __FILE__,
		    BUNYAN_T_INT32, "line", __LINE__,
		    BUNYAN_T_END);
		schedule_socket(s, pfkey_inbound);
		return;
	}

	samsg = malloc(length);
	if (samsg == NULL) {
		bunyan_error(log, "No memory for pfkey message", BUNYAN_T_END);
		schedule_socket(s, pfkey_inbound);
		return;
	}

	rc = read(s, samsg, length);
	if (rc <= 0) {
		if (rc == -1) {
			STDERR(error, log, "read failed");
			/* XXX: Should I exit()? */
		}
		free(samsg);
		schedule_socket(s, pfkey_inbound);
		return;
	}

	/* At this point, we can safely re-schedule the socket for reading. */
	schedule_socket(s, pfkey_inbound);

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
 * Send a pfkey message 'msg'.  The reply will invoke the callback
 * function 'cb' with data as an argument.
 * Returns B_TRUE if the request is successfully sent,
 * B_FALSE if there was an error.
 */
boolean_t
pfkey_send_msg(sadb_msg_t *msg, pfreq_cb_t *cb, void *data)
{
	pfreq_t *req;
	ssize_t n;

	req = pfreq_new(cb, data);
	if (req == NULL)
		return (B_FALSE);

	msg->sadb_msg_seq = req->pr_msgid;
	msg->sadb_msg_pid = getpid();

	PTH(pthread_mutex_lock(&pfreq_lock));
	list_insert_tail(&pfreq_list, req);
	PTH(pthread_mutex_unlock(&pfreq_lock));

	n = write(pfkey, msg, msg->sadb_msg_len);
	if (n != msg->sadb_msg_len) {
		if (n < 0) {
			STDERR(error, log, "pf_key write failed");
		} else {
			bunyan_error(log, "pf_key truncated write",
			    BUNYAN_T_UINT32, "n", (uint32_t)n,
			    BUNYAN_T_END);
		}

		PTH(pthread_mutex_lock(&pfreq_lock));
		list_remove(&pfreq_list, req);
		PTH(pthread_mutex_unlock(&pfreq_lock));

		pfreq_free(req);
		return (B_FALSE);
	}

	return (B_TRUE);
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

	n = write(pfkey, &msg, sizeof (sadb_msg_t));
	if (n != sizeof (sadb_msg_t))
		STDERR(error, log, "Unable to send PFKEY error notification");
}

static void
handle_reply(sadb_msg_t *reply)
{
	pfreq_t *req = NULL;

	PTH(pthread_mutex_lock(&pfreq_lock));

	req = list_head(&pfreq_list);
	while (req != NULL && req->pr_msgid != reply->sadb_msg_seq)
		req = list_next(&pfreq_list, req);

	if (req != NULL)
		list_remove(&pfreq_list, req);
	PTH(pthread_mutex_unlock(&pfreq_lock));

	if (req == NULL) {
		sadb_log(pflog, BUNYAN_L_INFO,
		    "Received a reply to an unknown request", reply);
		free(reply);
		return;
	}

#if 0
	req->pr_cb(reply, req->pr_data);
#endif
	pfreq_free(req);

	switch (reply->sadb_msg_type) {
	case SADB_ACQUIRE:
	{
		/* Should be a response to our inverse acquire */
		parsedmsg_t pmsg = { 0 };

		if (!extract_exts(reply, &pmsg, 1, SADB_X_EXT_EPROP)) {
			bunyan_info(pflog, "No extended proposal found in "
			    "ACQUIRE reply.", BUNYAN_T_END);
			free(reply);
			return;
		}

		/*
		 * XXX: lookup what we queried based on msgid, extract
		 * SA type and pass to convert_ext_acquire
		 */

		/* XXX: continue CHILD SA processing */
		break;
	}
	default:
		/* XXX: More to come */
		;
	}

	free(reply);
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

static int
pfreq_ctor(void *buf, void *ignore, int flags)
{
	_NOTE(ARGUNUSED(ignore, flags))

	pfreq_t *req = buf;

	(void) memset(buf, 0, sizeof (pfreq_t));
	list_link_init(&req->pr_node);
	return (0);
}

static pfreq_t *
pfreq_new(pfreq_cb_t *cb, void *data)
{
	pfreq_t *req = umem_cache_alloc(pfreq_cache, UMEM_DEFAULT);

	if (req == NULL)
		return (NULL);

	req->pr_msgid = atomic_inc_32_nv(&msgid);
	req->pr_cb = cb;
	req->pr_data = data;
	return (req);
}

static void
pfreq_free(pfreq_t *req)
{
	(void) pfreq_ctor(req, NULL, 0);
	umem_cache_free(pfreq_cache, req);
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

	n = write(pfkey, buffer, sizeof (*samsg));
	if (n < 0)
		err(EXIT_FAILURE, "pf_key write error");
	if (n < sizeof (*samsg))
		errx(EXIT_FAILURE, "Unable to write pf_key register message");

	do {
		(void) memset(buffer, 0, sizeof (buffer));
		n = read(pfkey, buffer, sizeof (buffer));
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

	pfreq_cache = umem_cache_create("pfreq cache", sizeof (pfreq_t),
	    sizeof (uint64_t), pfreq_ctor, NULL, NULL, NULL, NULL, 0);
	if (pfreq_cache == NULL)
		err(EXIT_FAILURE, "Unable to create pfreq cache");

	pfkey = socket(PF_KEY, SOCK_RAW, PF_KEY_V2);
	if (pfkey == -1)
		err(EXIT_FAILURE, "Unable to create pf_key socket");

	rc = bunyan_child(log, &pflog,
	    BUNYAN_T_INT32, "socketfd", (int32_t)pfkey,
	    BUNYAN_T_END);
	if (rc != 0)
		errx(EXIT_FAILURE, "Unable to create child logger: %s",
		    strerror(rc));

	pfkey_register(SADB_SATYPE_ESP);
	pfkey_register(SADB_SATYPE_AH);

	schedule_socket(pfkey, pfkey_inbound);
}
