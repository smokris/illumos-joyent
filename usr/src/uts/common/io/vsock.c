/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2021 Joyent, Inc.
 */

#include <sys/strsubr.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/modctl.h>
#include <sys/cmn_err.h>
#include <sys/strsun.h>
#include <sys/sunddi.h>

typedef struct vsock_sock {
	int foo;
} vsock_sock_t;

static sock_lower_handle_t vsock_create(int, int, int, sock_downcalls_t **,
    uint_t *, int *, int, cred_t *);
static vsock_sock_t * vsock_do_open(int flags);
static void vsock_activate(sock_lower_handle_t proto_handle,
    sock_upper_handle_t sock_handle, sock_upcalls_t *sock_upcalls, int flags,
    cred_t *cr);
static int vsock_accept(sock_lower_handle_t proto_handle,
    sock_lower_handle_t lproto_handle, sock_upper_handle_t sock_handle,
    cred_t *cr);
static int vsock_bind(sock_lower_handle_t proto_handle, struct sockaddr *sa,
   socklen_t len, cred_t *cr);
static int
vsock_listen(sock_lower_handle_t proto_handle, int backlog, cred_t *cr);
static int
vsock_connect(sock_lower_handle_t proto_handle, const struct sockaddr *sa,
   socklet_t len, sock_connid_t *id, cred_t *cr);
static int
vsock_getpeername(sock_lower_handle_t proto_handle, struct sockaddr *addr,
   socklen_t *addrlenp, cred_t *cr);
static int
vsock_getsockname(sock_lower_handle_t proto_handle, struct sockaddr *addr,
    socklen_t *addrlenp, cred_t *cr);
static int
vsock_getsockopt(sock_lower_handle_t proto_handle, int level, int option_name,
    void *optvalp, socklen_t *optlen, cred_t *cr);
static int
vsock_setsockopt(sock_lower_handle_t proto_handle, int level, int option_name,
     const void *optvalp, socklen_t optlen, cred_t *cr);
static int
vsock_send(sock_lower_handle_t proto_handle, mblk_t *mp, struct nmsghdr *msg,
    cred_t *cr);
static int
vsock_send_uio(sock_lower_handle_t proto_handle, uio_t *uiop,
    struct nmsghdr *msg, cred_t *cr);
static int
vsock_recv_uio(sock_lower_handle_t proto_handle, uio_t *uiop,
    struct nmsghdr *msg, cred_t *cr);
static int 
vosck_poll(sock_lower_handle_t proto_handle, short events, int anyyet,
    cred_t *cr);
static int
vsock_shutdown(sock_lower_handle_t proto_handle, int how, cred_t *cr);
static int
vsock_setflowctrl(sock_lower_handle_t proto_handle);
static int
vsock_ioctl(sock_lower_handle_t proto_handle, int cmd, intptr_t arg,
   int mode, int32_t *rvalp, cred_t *cr);


static smod_reg_t sinfo = {
	SOCKMOD_VERSION,
	"vsock",
	SOCK_UC_VERSION,
	SOCK_DC_VERSION,
	sock_create,
	NULL,
};

static struct modlsockmod sockmod = {
	&mod_sockmodops, "AF_VSOCK socket module", &sinfo
};

static struct modlinkage ml = {
	MODREV_1,
	&sockmod,
	NULL
};

static sock_downcalls_t sock_vsock_downcalls = {
	vsock_activate,
	vsock_accept,
	vsock_bind,
	vsock_listen,
	vsock_connect,
	vsock_getpeername,
	vsock_getsockname,
	vsock_getsockopt,
	vsock_setsockopt,
	vsock_send,
	vsock_send_uio,
	vsock_recv_uio,
	vosck_poll,
	vsock_shutdown,
	vsock_setflowctrl,
	vsock_ioctl,
	vsock_close,
};

int
_init(void)
{
	int rc;

	rc = mod_install(&ml);
	return (rc);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&ml, modinfop));
}

int
_fini(void)
{
	int rc;

	rc = mod_remove(&ml);
	return (rc);
}

static sock_lower_handle_t
vsock_create(int family, int type, int proto, sock_downcalls_t **sock_downcalls,
    uint_t *smodep, int *errorp, int flags, cred_t *credp)
{
	vsock_sock_t *vsock;

	if (family != AF_VSOCK || type != SOCK_STREAM || proto != 0) {
		*errorp = EPROTONOSUPPORT;
		return (NULL);
	}

	*sock_downcalls = &sock_vsock_downcalls;
	*smodep = SM_CONNREQUIRED | SM_EXDATA | SM_ACCEPTSUPP;
	vsock = vsock_do_open(flags);
	*errorp = (vsock != NULL) ? 0 : ENOMEM;
	return ((sock_lower_handle_t)vsock);
}

static vsock_sock_t *
vsock_do_open(int flags)
{
	return (NULL);
}

static void
vsock_activate(sock_lower_handle_t proto_handle,
    sock_upper_handle_t sock_handle, sock_upcalls_t *sock_upcalls, int flags,
    cred_t *cr)
{
}

static int
vsock_accept(sock_lower_handle_t proto_handle,
    sock_lower_handle_t lproto_handle, sock_upper_handle_t sock_handle,
    cred_t *cr)
	return (ECONNABORTED);
}

static int
vsock_bind(sock_lower_handle_t proto_handle, struct sockaddr *sa,
   socklen_t len, cred_t *cr)
{
	return (EOPNOTSUPP);
}

static int
vsock_listen(sock_lower_handle_t proto_handle, int backlog, cred_t *cr)
{
	return (EOPNOTSUPP);
}

static int
vsock_connect(sock_lower_handle_t proto_handle, const struct sockaddr *sa,
   socklet_t len, sock_connid_t *id, cred_t *cr)
{
	return (EOPNOTSUPP);
}

static int
vsock_getpeername(sock_lower_handle_t proto_handle, struct sockaddr *addr,
   socklen_t *addrlenp, cred_t *cr)
{
	return (ENOTCONN);
}

static int
vsock_getsockname(sock_lower_handle_t proto_handle, struct sockaddr *addr,
    socklen_t *addrlenp, cred_t *cr)
{
	return (ENOTCONN);
}

static int
vsock_getsockopt(sock_lower_handle_t proto_handle, int level, int option_name,
    void *optvalp, socklen_t *optlen, cred_t *cr)
{
	return (EOPNOTSUPP);
}

static int
vsock_setsockopt(sock_lower_handle_t proto_handle, int level, int option_name,
     const void *optvalp, socklen_t optlen, cred_t *cr)
{
	return (EOPNOTSUPP);
}


static int
vsock_send(sock_lower_handle_t proto_handle, mblk_t *mp, struct nmsghdr *msg,
    cred_t *cr)
{
	return (EOPNOTSUPP);
}


static int
vsock_send_uio(sock_lower_handle_t proto_handle, uio_t *uiop,
    struct nmsghdr *msg, cred_t *cr)
{
	return (EOPNOTSUPP);
}

static int
vsock_recv_uio(sock_lower_handle_t proto_handle, uio_t *uiop,
    struct nmsghdr *msg, cred_t *cr)
{
	return (EOPNOTSUPP);
}

static int 
vosck_poll(sock_lower_handle_t proto_handle, short events, int anyyet,
    cred_t *cr)
{
	return (EOPNOTSUPP);
}


static int
vsock_shutdown(sock_lower_handle_t proto_handle, int how, cred_t *cr)
{
	return (EOPNOTSUPP);
}

static int
vsock_setflowctrl(sock_lower_handle_t proto_handle)
{
	return (EOPNOTSUPP);
}

static int
vsock_ioctl(sock_lower_handle_t proto_handle, int cmd, intptr_t arg,
   int mode, int32_t *rvalp, cred_t *cr)
{
	return (EOPNOTSUPP);
}
