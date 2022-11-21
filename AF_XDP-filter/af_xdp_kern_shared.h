/* SPDX-License-Identifier: GPL-2.0+ */

/* Used by both kernel side BPF-progs and userspace programs,
 * for sharing common DEFINEs.
 */
#ifndef __AF_XDP_KERN_SHARED_H
#define __AF_XDP_KERN_SHARED_H

/* This is the data record stored in the map */
struct datarec {
	__u64 rx_packets;
	/* Assignment#1: Add byte counters */
	__u64 rx_bytes;
};

enum {
	k_rx_queue_count_max = 64  /* Assume netdev has no more than 64 queues */
} ;

#endif
