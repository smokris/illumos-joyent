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

#ifndef _VSOCK_H
#define	_VSOCK_H

#ifdef __cplusplus
extern "C" {
#endif

#ifndef _SA_FAMILY_T
#define	_SA_FAMILY_T
typedef	unsigned short sa_family_t;
#endif

#define	VMADDR_CID_ANY		(-1U)
#define	VMADDR_CID_HYPERVISOR	0
#define	VMADDR_CID_LOCAL	2

#define	VSIOCTL				('v' << 16 | 's' << 8)
#define	IOCTL_VM_SOCKETS_GET_LOCAL_CID	(VSIOCTL | 0x1)

struct sockaddr_vm {
	sa_family_t	svm_family;
	unsigned short	svm_reserved1;
	uint32_t	svm_port;
	uint64_t	svm_cid;
};

#ifdef __cplusplus
}
#endif

#endif /* _VSOCK_H */
