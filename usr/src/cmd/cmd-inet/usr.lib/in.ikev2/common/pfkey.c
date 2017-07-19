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
#include <sys/stropts.h>	/* For I_NREAD */
#include <libuutil.h>
#include <bunyan.h>

#include "defs.h"
#include "ikev2.h"
#include "ikev2_pkt.h"
#include "ikev2_sa.h"
#include "pkcs11.h"

struct pfreq;
typedef struct pfreq {
	uu_list_node_t	pr_node;
	pfreq_cb_t	*pr_cb;
	void		*pr_data;
	uint32_t	pr_msgid;
} pfreq_t;

static bunyan_logger_t	*pflog;
static uu_list_pool_t	*pfreq_pool;
static umem_cache_t	*pfreq_cache;
static pthread_mutex_t	pfreq_lock = PTHREAD_MUTEX_INITIALIZER;
static uu_list_t	*pfreq_list;

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
pfkey_inbound(int s, void *arg)
{
	_NOTE(ARGUNUSED(arg))

	sadb_msg_t *samsg;
	ssize_t rc;
	int length;

	if (ioctl(s, I_NREAD, &length) < 0) {
		STDERR(error, log, "ioctl(I_NREAD) failed");

		/* XXX KEBE ASKS - will we rapidly return at this point? */
		schedule_socket(s, pfkey_inbound);
		return;
	}

	if (length == 0) {
		bunyan_info(log, "ioctl: zero length message",
		    BUNYAN_T_STRING, "func", __func__,
		    BUNYAN_T_STRING, "file", __FILE__,
		    BUNYAN_T_INT32, "line", __LINE__,
		    BUNYAN_T_END);
		/* XXX KEBE ASKS - will we rapidly return at this point? */
		schedule_socket(s, pfkey_inbound);
		return;
	}

	samsg = malloc(length);
	if (samsg == NULL) {
		STDERR(error, log, "malloc failure");
		schedule_socket(s, pfkey_inbound);
		return;
	}

	rc = read(s, samsg, length);
	if (rc <= 0) {
		if (rc == -1) {
			STDERR(error, log, "read failed");
			/* Should I exit()? */
		}
		free(samsg);
		/* XXX KEBE ASKS - will we rapidly return at this point? */
		schedule_socket(s, pfkey_inbound);
		return;
	}

	/* At this point, we can safely re-schedule the socket for reading. */
	schedule_socket(s, pfkey_inbound);

	bunyan_debug(log, "SADB message received",
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
		bunyan_debug(log, "reply not for us, dropped", BUNYAN_T_END);
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
		 * called from pf_key_init(), which has samsg on the stack
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
	uu_list_index_t idx;
	ssize_t n;

	req = pfreq_new(cb, data);
	if (req == NULL)
		return (B_FALSE);

	msg->sadb_msg_seq = req->pr_msgid;
	msg->sadb_msg_pid = getpid();
	n = write(pfkey, msg, msg->sadb_msg_len);
	if (n != msg->sadb_msg_len) {
		if (n < 0) {
			STDERR(error, log, "pf_key write failed");
		} else {
			bunyan_error(log, "pf_key truncated write",
			    BUNYAN_T_UINT32, "n", (uint32_t)n,
			    BUNYAN_T_END);
		}
		pfreq_free(req);
		return (B_FALSE);
	}

	(void) pthread_mutex_lock(&pfreq_lock);

	(void) uu_list_find(pfreq_list, req, NULL, &idx);
	uu_list_insert(pfreq_list, req, idx);
	(void) pthread_mutex_unlock(&pfreq_lock);

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
	pfreq_t *req;
	uu_list_index_t idx;

	PTH(pthread_mutex_lock(&pfreq_lock));
	req = uu_list_find(pfreq_list, NULL, reply, &idx);
	if (req != NULL)
		uu_list_remove(pfreq_list, req);
	PTH(pthread_mutex_unlock(&pfreq_lock));

	if (req == NULL) {
		/* XXX: log more fields? */
		bunyan_info(pflog, "Received a reply to an unknown request; "
		    "ignorning.",
		    BUNYAN_T_STRING, "msg_type",
		    pfkey_satype(reply->sadb_msg_type),
		    BUNYAN_T_UINT32, "msg_type_val",
		    (uint32_t)reply->sadb_msg_type,
		    BUNYAN_T_INT32, "pid", reply->sadb_msg_pid,
		    BUNYAN_T_UINT32, "seq", reply->sadb_msg_seq,
		    BUNYAN_T_END);
		free(reply);
		return;
	}

	req->pr_cb(reply, req->pr_data);
	pfreq_free(req);

#if 0

	switch (reply->sadb_msg_type) {
	case SADB_ACQUIRE:
	{
		/* Should be a response to our inverse acquire */
		ikev2_pay_sa_t *i2sa_pay;
		parsedmsg_t pmsg;

		if (!extract_exts(reply, &pmsg, 1, SADB_X_EXT_EPROP)) {
			PRTDBG(D_PFKEY, ("No extended proposal found in "
			    "ACQUIRE reply."));
			free(reply);
			return;
		}

		/*
		 * XXX: lookup what we queried based on msgid, extract
		 * SA type and pass to convert_ext_acquire
		 */
		i2sa_pay = convert_ext_acquire(&pmsg, 0);

		/* XXX: continue CHILD SA processing */
		break;
	}
	default:
		/* XXX: More to come */
		;
	}
#endif

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

	ikev2_pay_sa_t *sap;
	parsedmsg_t pmsg;

	bunyan_debug(pflog, "Handling SADB acquire", BUNYAN_T_END);

	if (!extract_exts(samsg, &pmsg, 1, SADB_EXT_PROPOSAL)) {
		bunyan_info(pflog, "No proposal found in ACQUIRE message",
		    BUNYAN_T_END);
		free(samsg);
		return;
	}

	sap = convert_acquire(&pmsg);
	if (sap == NULL) {
		free(samsg);
		return;
	}

	/* XXX KEBE SAYS FILL ME IN! */
	free(samsg);
}

static boolean_t
add_encr_xf(ikev2_prop_t *i2prop, uint8_t alg, uint16_t minbits,
    uint16_t maxbits)
{
	ikev2_xf_t *xf;
	ikev2_xf_attr_t *xf_attr;
	encr_param_t *ep;
	int keylen;

	/* The SADB_EALG_* and IKEV2_XF_ENCR_* values match */
	ep = ikev2_get_encr_param(alg);

	/*
	 * Some algs MUST NOT include a key length attribute, others
	 * should can have a default value is defined for the alg
	 * (e.g. blowfish) if not key length is specified.
	 *
	 * To maximize compatability, we cf course add transforms
	 * sans-keylength for those algs where it shouldn't be included
	 * as well as those with a default key size (but support multiple
	 * sizes) assuming it is in the acceptable range.  For the latter,
	 * we also include an explicit list of key sizes.
	 */
	if (ep->key_min == ep->key_max ||
	    (minbits <= ep->key_default && maxbits >= ep->key_default)) {
		xf = ikev2_xf_alloc(IKEV2_XF_TYPE_ENCR, alg);
		if (xf == NULL) {
			PRTDBG(D_PFKEY, ("No memory for transform."));
			return (B_FALSE);
		}
		ikev2_add_xform(i2prop, xf);
	}

	/* For fixed sizes keys, we're done */
	if (ep->key_min == ep->key_max)
		return (B_TRUE);

	for (keylen = maxbits; keylen >= minbits; keylen -= ep->key_incr) {
		xf_attr = ikev2_xf_attr_alloc();
		if (xf_attr == NULL) {
			PRTDBG(D_PFKEY, ("No memory for transform attribute."));
			return (B_FALSE);
		}

		xf_attr->type = IKEV2_XF_ATTR_KEY_LENGTH;
		xf_attr->tv = B_TRUE;
		xf_attr->val.val = keylen;

		xf = ikev2_xf_alloc(IKEV2_XF_TYPE_ENCR, alg);
		if (xf == NULL) {
			ikev2_xf_attr_free(xf_attr);
			PRTDBG(D_PFKEY, ("No memory for transform."));
			return (B_FALSE);
		}

		/* This should always succeed */
		assert(ikev2_add_xf_attr(xf, xf_attr));
		ikev2_add_xform(i2prop, xf);
	}

	return (B_TRUE);
}

static boolean_t
convert_prop(uint8_t satype, ikev2_pay_sa_t *sap, sadb_prop_t *pfprop)
{
	sadb_comb_t *combs;
	ikev2_prop_t *i2prop;
	ikev2_xf_t *xf;
	int i, numcombs;
	ikev2_spi_proto_t proto;

	assert(pfprop->sadb_prop_exttype == SADB_EXT_PROPOSAL);

	switch (satype) {
	case SADB_SATYPE_AH:
	case SADB_SATYPE_ESP:
		/*
		 * The SADB_SATYPE_* and IKEV2_SPI_* values for AH and ESP
		 * are the same.  Other values (such as FC) are not and
		 * will need to be dealt with if we ever support that.
		 */
		proto = satype;
		break;
	default:
		PRTDBG(D_PFKEY, ("Unsuported ACQUIRE SATYPE %s.",
		    pfkey_satype(satype)));
		return (B_FALSE);
	}

	numcombs = pfprop->sadb_prop_len - SADB_8TO64(sizeof (*pfprop));
	numcombs /= SADB_8TO64(sizeof (*combs));

	combs = (sadb_comb_t *)(pfprop + 1);

	for (i = 0; i < numcombs; i++) {
		i2prop = ikev2_prop_alloc();
		if (i2prop == NULL) {
			PRTDBG(D_PFKEY, ("No memory for IKEv2 proposal."));
			return (B_FALSE);
		}

		i2prop->id = proto;

		xf = ikev2_xf_alloc(IKEV2_XF_TYPE_AUTH,
		    ikev2_pf_to_auth(combs[i].sadb_comb_auth));

		if (xf == NULL) {
			PRTDBG(D_PFKEY, ("No memory for IKEv2 transform."));
			ikev2_prop_free(i2prop);
			return (B_FALSE);
		}

		ikev2_add_xform(i2prop, xf);

		if (!add_encr_xf(i2prop, combs[i].sadb_comb_encrypt,
		    combs[i].sadb_comb_encrypt_minbits,
		    combs[i].sadb_comb_encrypt_maxbits)) {
			ikev2_prop_free(i2prop);
			return (B_FALSE);
		}

		ikev2_add_proposal(sap, i2prop);
	}

	return (B_TRUE);
}

/*
 * Convert an PF_KEY ACQUIRE message into an IKEv2 SA payload
 */
static ikev2_pay_sa_t *
convert_acquire(parsedmsg_t *acq)
{
	ikev2_pay_sa_t *sap;
	sadb_prop_t *pfprop;

	sap = (ikev2_pay_sa_t *)ikev2_pay_alloc(IKEV2_PAYLOAD_SA, B_FALSE);
	if (sap == NULL) {
		PRTDBG(D_PFKEY, ("No memory for SA payload."));
		return (NULL);
	}

	pfprop = (sadb_prop_t *)acq->pmsg_exts[SADB_EXT_PROPOSAL];

	if (!convert_prop(acq->pmsg_samsg->sadb_msg_satype, sap, pfprop)) {
		ikev2_pay_free((ikev2_pay_t *)sap);
		return (NULL);
	}

	return (sap);
}

static boolean_t
convert_algdesc(ikev2_prop_t *i2prop, sadb_x_algdesc_t *algdesc)
{
	ikev2_xf_t *xf;
	int id;

	switch (algdesc->sadb_x_algdesc_algtype) {
	case SADB_X_ALGTYPE_AUTH:
		id = ikev2_pf_to_auth(algdesc->sadb_x_algdesc_alg);
		xf = ikev2_xf_alloc(IKEV2_XF_TYPE_AUTH, id);
		if (xf == NULL) {
			PRTDBG(D_PFKEY, ("No memory for transform"));
			return (B_FALSE);
		}
		ikev2_add_xform(i2prop, xf);
		return (B_TRUE);

	case SADB_X_ALGTYPE_CRYPT:
		if (!add_encr_xf(i2prop, algdesc->sadb_x_algdesc_alg,
		    algdesc->sadb_x_algdesc_minbits,
		    algdesc->sadb_x_algdesc_maxbits))
			return (B_FALSE);
		return (B_TRUE);

	default:
		PRTDBG(D_PFKEY, ("Unsupported algtype %d in extended ACQUIRE.",
		    algdesc->sadb_x_algdesc_algtype));
		/*
		 * XXX: should this stop conversion of the ACQUIRE altogether
		 * or should we just ignore the alg?
		 * for now, we'll ignore.
		 */
		return (B_TRUE);
	}
}

/*
 * Convert an extended acquire into an IKEV2 SA payload
 */
static ikev2_pay_sa_t *
convert_ext_acquire(parsedmsg_t *eacq, ikev2_spi_proto_t proto)
{
	uint64_t *sofar;
	ikev2_pay_sa_t *sap;
	sadb_prop_t *eprop = (sadb_prop_t *)eacq->pmsg_exts[SADB_X_EXT_EPROP];
	sadb_x_ecomb_t *ecomb;
	sadb_x_algdesc_t *algdesc;
	uint8_t algtype;
	int i, j;

	switch (proto) {
	case IKEV2_SPI_AH:
	case IKEV2_SPI_ESP:
		algtype = proto;
		break;
	default:
		PRTDBG(D_PFKEY, ("Unsupported SA Type %s in extended ACQUIRE.",
		    ikev2_spi_str(proto)));
		return (NULL);
	}

	sap = (ikev2_pay_sa_t *)ikev2_pay_alloc(IKEV2_PAYLOAD_SA, B_FALSE);
	if (sap == NULL) {
		PRTDBG(D_PFKEY, ("No memory for SA payload."));
		return (NULL);
	}

	sofar = (uint64_t *)(eprop + 1);
	ecomb = (sadb_x_ecomb_t *)sofar;

	for (i = 0; i < eprop->sadb_x_prop_numecombs; i++) {
		ikev2_prop_t *i2prop;

		i2prop = ikev2_prop_alloc();
		if (i2prop == NULL) {
			PRTDBG(D_PFKEY, ("No memory for SA proposal."));
			ikev2_pay_free((ikev2_pay_t *)sap);
			return (NULL);
		}

		i2prop->id = proto;

		sofar = (uint64_t *)(ecomb + 1);
		algdesc = (sadb_x_algdesc_t *)sofar;

		for (j = 0; i < ecomb->sadb_x_ecomb_numalgs; j++) {
			if (algdesc->sadb_x_algdesc_algtype != algtype &&
			    algdesc->sadb_x_algdesc_algtype !=
			    SADB_SATYPE_UNSPEC) {
				sofar = (uint64_t *)(algdesc++);
				continue;
			}

			if (!convert_algdesc(i2prop, algdesc)) {
				ikev2_prop_free(i2prop);
				ikev2_pay_free((ikev2_pay_t *)sap);
				return (NULL);
			}

			sofar = (uint64_t *)(++algdesc);
		}

		ikev2_add_proposal(sap, i2prop);
		ecomb = (sadb_x_ecomb_t *)sofar;
	}

	return (sap);
}

static ikev2_xf_auth_t
ikev2_pf_to_auth(int alg)
{
	/*
	 * Most of the SADB_* values correspond to the IKEV2 values
	 * however, these two do not.  New auth algs should use
	 * the corresponding IKEV2 values.
	 */
	switch (alg) {
	case SADB_AALG_MD5HMAC:
		return (IKEV2_XF_AUTH_HMAC_MD5_96);
	case SADB_AALG_SHA1HMAC:
		return (IKEV2_XF_AUTH_HMAC_SHA1_96);
	default:
		return (alg);
	}
}

static int
pfreq_compare(const void *l_arg, const void *r_arg, void *msg_arg)
{
	const pfreq_t *l = l_arg;
	const pfreq_t *r = r_arg;
	sadb_msg_t *msg = msg_arg;
	uint32_t msgid;
	
	ASSERT((r != NULL && msg == NULL) || (r == NULL && msg != NULL));

	if (r != NULL)
		msgid = r->pr_msgid;
	else
		msgid = msg->sadb_msg_seq;

	if (l->pr_msgid < msgid)
		return (-1);
	if (l->pr_msgid > msgid)
		return (1);
	if (r == NULL)
		return (0);

	if (l->pr_data < r->pr_data)
		return (-1);
	if (l->pr_data > r->pr_data)
		return (1);
	return (0);
}

static int
pfreq_ctor(void *buf, void *ignore, int flags)
{
	_NOTE(ARGUNUSED(ignore, flags))
	(void) memset(buf, 0, sizeof (pfreq_t));
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

void
pfkey_init(void)
{
	uint64_t buffer[128] = { 0 };
	sadb_msg_t *samsg = (sadb_msg_t *)buffer;
	sadb_x_ereg_t *ereg = (sadb_x_ereg_t *)(samsg + 1);
	boolean_t ah_ack = B_FALSE;
	boolean_t esp_ack = B_FALSE;
	uint32_t flag = 0;
	ssize_t n;
	int rc;

	CTASSERT(sizeof (buffer) >= sizeof (*samsg) + sizeof (*ereg));

#ifdef DEBUG
	flg |= UU_LIST_POOL_DEBUG;
#endif

	pfreq_pool = uu_list_pool_create("pfreq list", sizeof (pfreq_t),
	    offsetof(pfreq_t, pr_node), pfreq_compare, flag);
	if (pfreq_pool == NULL)
		err(EXIT_FAILURE, "Unable to create pfreq list pool");

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

	/*
	 * Extended REGISTER for AH/ESP combination(s).
	 */
	samsg->sadb_msg_version = PF_KEY_V2;
	samsg->sadb_msg_type = SADB_REGISTER;
	samsg->sadb_msg_errno = 0;
	samsg->sadb_msg_satype = SADB_SATYPE_UNSPEC;
	samsg->sadb_msg_reserved = 0;
	samsg->sadb_msg_seq = 1;
	samsg->sadb_msg_pid = getpid();
	samsg->sadb_msg_len = SADB_8TO64(sizeof (*samsg) + sizeof (*ereg));

	ereg->sadb_x_ereg_len = SADB_8TO64(sizeof (*ereg));
	ereg->sadb_x_ereg_exttype = SADB_X_EXT_EREG;
	ereg->sadb_x_ereg_satypes[0] = SADB_SATYPE_ESP;
	ereg->sadb_x_ereg_satypes[1] = SADB_SATYPE_AH;
	ereg->sadb_x_ereg_satypes[2] = SADB_SATYPE_UNSPEC;

	n = write(pfkey, buffer, sizeof (*samsg) + sizeof (*ereg));
	if (n < 0)
		err(EXIT_FAILURE, "Extended register write error");
	if (n < sizeof (*samsg) + sizeof (*ereg))
		errx(EXIT_FAILURE, "Unable to write extended register message");

	pid_t pid = getpid();
	do {
		do {
			(void) memset(buffer, 0, sizeof (buffer));
			n = read(pfkey, buffer, sizeof (buffer));
			if (n < 0)
				err(EXIT_FAILURE, "Extended register read "
				    "error");
		} while (samsg->sadb_msg_seq !=1 ||
		    samsg->sadb_msg_pid != pid ||
		    samsg->sadb_msg_type != SADB_REGISTER);

		if (samsg->sadb_msg_errno != 0) {
			if (samsg->sadb_msg_errno != EPROTONOSUPPORT)
				errx(EXIT_FAILURE, "Extended REGISTER "
				    "returned %s (%d).",
				    strerror(samsg->sadb_msg_errno),
				    samsg->sadb_msg_errno);
			bunyan_info(pflog, "Protocol not supported",
			    BUNYAN_T_UINT32, "msg_satype",
			    (uint32_t)samsg->sadb_msg_satype,
			    BUNYAN_T_END);
		}

		switch (samsg->sadb_msg_satype) {
		case SADB_SATYPE_ESP:
			esp_ack = B_TRUE;
			bunyan_debug(pflog, "ESP initial REGISTER with SADB",
			    BUNYAN_T_END);
			break;
		case SADB_SATYPE_AH:
			ah_ack = B_TRUE;
			bunyan_debug(pflog, "AH initial REGISTER with SADB",
			    BUNYAN_T_END);
			break;
		default:
			err(EXIT_FAILURE, "Bad satype %d in extended register "
			    "ACK.", samsg->sadb_msg_satype);
		}

		handle_register(samsg);
	} while (!esp_ack || !ah_ack);

	schedule_socket(pfkey, pfkey_inbound);
}
