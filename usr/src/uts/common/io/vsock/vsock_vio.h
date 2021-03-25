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

#ifndef _VSOCK_VIO_H
#define	_VSOCK_VIO_H

/*
 * xxx
 */

#ifdef __cplusplus
extern "C" {
#endif

/*
 * VIRTIO VSOCK CONFIGURATION REGISTERS
 *
 * These are offsets into the device-specific configuration space available
 * through the virtio_dev_*() family of functions.
 */
#define	VIRTO_VSOCK_CONFIG_CID	0x00	/* 16 R */

/*
 * VIRTIO VSOCK VIRTQUEUES
 */
#define	VIRTIO_VSOCK_VIRTQ_RX	0
#define	VIRTIO_VSOCK_VIRTQ_TX	1
#define	VIRTIO_VOCK_VIRTQ_EVENT	2

struct virtio_vsock_hdr {
	uint64_t	vvh_src_cid;
	uint64_t	vvh_dst_cid;
	uint32_t	vvh_src_port;
	uint32_t	vvh_dst_port;
	uint32_t	vvh_len;
	uint16_t	vvh_type;
	uint16_t	vvh_op;
	uint32_t	vvh_flags;
	uint32_t	vvh_buf_alloc;
	uint32_t	vvh_fwd_cnt;
} __packed;

#define	VIRTIO_VSOCK_OP_INVALID		0

#define	VIRTIO_VSOCK_OP_REQUEST		1
#define	VIRTIO_VSOCK_OP_RESPONSE	2
#define	VIRTIO_VSOCK_OP_RST		3
#define	VIRTIO_VSOCK_OP_SHUTDOWN	4

#define	VIRTIO_VSOCK_OP_RW		5

#define	VIRTIO_VSOCK_OP_CREDIT_UPDATE	6
#define	VIRTIO_VSOCK_OP_CREDIT_REQUEST	7

struct vsock_dev {
	dev_info_t	*vsd_dip;
	virtio_t	*vsd_virtio;

	kmutex_t	vsd_mutex;

	virtio_queue_t	*vsd_rx_vq;
	virtio_queue_t	*vsd_tx_vq;
	virtio_queue_t	*vsd_event_vq;

	uint64_t	vsd_cid;
};

#ifdef __cplusplus
}
#endif

#endif /* _VSOCK_H */
