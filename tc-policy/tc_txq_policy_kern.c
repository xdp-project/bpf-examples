/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Copyright 2022 Jesper Dangaard Brouer */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/compiler.h>
#include <linux/pkt_sched.h>
#include <linux/pkt_cls.h>
//#include <stdbool.h>
//#include "../include/xdp/parsing_helpers.h"

/* Manuel setup:
 export DEV=eth1

 tc qdisc  add dev "$DEV" clsact
 tc filter add dev "$DEV" egress bpf da obj tc_txq_policy_kern.o
 tc filter list dev "$DEV" egress

 * Quick test reloading with tc:
 tc filter replace dev "$DEV" egress prio 0xC000 handle 1 bpf da obj tc_txq_policy_kern.o

 * Delete by teardown of clsact
 tc qdisc delete dev "$DEV" clsact

*/
SEC("classifier")
int queue_map_4 (struct __sk_buff *skb)
{
	__u16 txq_root_handle;

	/* The skb->queue_mapping is 1-indexed (zero means not set).  The
	 * underlying MQ leaf's are also 1-indexed, which makes it easier to
	 * reason about.
	 */
	txq_root_handle = 4;
	skb->queue_mapping = txq_root_handle;

	/* Details: Kernel double protect against setting a too high
	 * queue_mapping.  In skb_tx_hash() it will reduce number to be
	 * less-than (or equal) dev->real_num_tx_queues.  And netdev_pick_tx()
	 * cap via netdev_cap_txqueue().
	 */

	// FIXME: Do we need to set TC_H_MAJOR(skb->priority) for this to work?
	
	return TC_ACT_OK;
}
