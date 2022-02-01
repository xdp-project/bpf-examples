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

 * Beware: Trying to replace an existing TC-BPF prog often result in appending a
 * new prog (as a new tc filter instance).  Be careful to set both handle and
 * prio to the existing TC-BPF "filter" instance.

 * Delete by teardown of clsact
 tc qdisc delete dev "$DEV" clsact

*/
SEC("classifier")
int queue_map_4 (struct __sk_buff *skb)
{
	__u16 txq_root_handle;

	/* The skb->queue_mapping is 1-indexed (zero means not set).  The
	 * underlying MQ leaf's are also 1-indexed, which makes it easier to
	 * reason about. If debugging this realize that setting
	 * skb->queue_mapping here is like it was set on RX-path the
	 * skb_rx_queue_recorded number, and when reaching TX-layer
	 * (skb_get_rx_queue) will have decremented it by-1.
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

/*
 * Section name "tc" is preferred over "classifier" as its being deprecated
 *  https://github.com/libbpf/libbpf/wiki/Libbpf-1.0-migration-guide#bpf-program-sec-annotation-deprecations
 */

SEC("tc")
int not_txq_zero (struct __sk_buff *skb)
{
	/* Existing skb->queue_mapping can come from skb_record_rx_queue() which
	 * is usually called by drivers in early RX handling when creating SKB.
	 */

	/* At this stage queue_mapping is 1-indexed.
	 * Thus, code is changing TXQ zero to be remapped to TXQ 3. */
	if (skb->queue_mapping == 1)
		skb->queue_mapping = 4;

	/* If queue_mapping was not set by skb_record_rx_queue(),
	 * e.g. locally generated traffic
	 */
	if (skb->queue_mapping == 0)
		skb->queue_mapping = 3;

	return TC_ACT_OK;
}
