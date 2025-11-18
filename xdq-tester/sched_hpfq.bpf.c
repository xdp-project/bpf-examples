// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2022 Freysteinn Alfredsson <freysteinn@freysteinn.com> */

#include <vmlinux_local.h>
#include <linux/bpf.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <xdp/parsing_helpers.h>

#include "bpf_local_helpers.h"

/* This code determines root WFQ scheduling using UDP ports. It would be nicer
   in the future to use VLANs instead.
   All UDP ports up to 4000 go to the left PIFO, and the other ports go to the
   right PIFO. */

enum leaf_pifo {
	NO_PIFO = 0,
	LEFT_PIFO,
	RIGHT_PIFO
};

struct {
	__uint(type, BPF_MAP_TYPE_PIFO_GENERIC);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u32));
	__uint(max_entries, 4096);
	__uint(map_extra, 8388608); /* range - 1024×4098×2 */
} root_pifo_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PIFO_XDP);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u32));
	__uint(max_entries, 4096);
	__uint(map_extra, 8388608); /* range - 1024×4098×2 */
} left_pifo_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PIFO_XDP);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u32));
	__uint(max_entries, 4096);
	__uint(map_extra, 8388608); /* range - 1024×4098×2 */
} right_pifo_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct network_tuple);
	__type(value, struct flow_state);
	__uint(max_entries, 16384);
} flow_states SEC(".maps");

__u64 root_time_bytes = 0;
__u64 left_time_bytes = 0;
__u64 right_time_bytes = 0;

__u16 default_root_weight = 256;
__u16 default_weight = 256;

static __always_inline int set_root_flow_priority(struct parsing_context *pctx,
						  struct flow_state *flow)
{
	__u64 root_start_time_bytes = bpf_max(root_time_bytes, flow->root_finish_bytes);
	flow->root_finish_bytes = root_start_time_bytes + (pctx->pkt_len * flow->root_weight >> 8);
	return root_start_time_bytes & ((1UL << 60) - 1); // Priority only defined in the lower 60 bits
}

static __always_inline int set_leaf_flow_priority(struct parsing_context *pctx,
						  struct flow_state *flow,
						  __u64 leaf_time_bytes)
{
	__u64 leaf_start_time_bytes = bpf_max(leaf_time_bytes, flow->finish_bytes);
	flow->finish_bytes = leaf_start_time_bytes + (pctx->pkt_len * flow->weight >> 8);
	return leaf_start_time_bytes;
}

static __always_inline int schedule_packet(struct parsing_context *pctx)
{
	struct packet_info p_info = {};

	struct network_tuple nt = {0};
	__u32 leaf_id;

	struct flow_state new_flow = {0};
	struct flow_state *flow;

	__u64 root_prio;
	__u32 left_prio;
	__u32 right_prio;

	new_flow.root_weight = default_root_weight;
	new_flow.weight = default_weight;

	/* Get flow */
	if (parse_packet(pctx, &p_info) < 0)
		goto err;

	nt = p_info.nt;

	leaf_id = (bpf_ntohs(p_info.udph->dest) <= 4000) ? LEFT_PIFO : RIGHT_PIFO;

	flow = bpf_map_lookup_or_try_init(&flow_states, &nt, &new_flow);
	if (!flow)
		goto err;
	flow->pkts++;

	/* Calculate scheduling priority */
	// Root WFQ
	root_prio = set_root_flow_priority(pctx, flow);
	if (bpf_map_push_elem(&root_pifo_map, &leaf_id, root_prio))
		goto err;
	flow->root_priority = root_prio;

	// Leaf WFQ
	if (leaf_id == LEFT_PIFO) {
		left_prio = set_leaf_flow_priority(pctx, flow, left_time_bytes);

		if (bpf_map_update_elem(&flow_states, &nt, flow, BPF_ANY))
			goto err;

		bpf_printk("XDP HPFQ scheduled with priority, root:%d left:%d", root_prio, left_prio);
		return bpf_redirect_map(&left_pifo_map, left_prio, 0);
	} else if (leaf_id == RIGHT_PIFO) {
		right_prio = set_leaf_flow_priority(pctx, flow, right_time_bytes);

		if (bpf_map_update_elem(&flow_states, &nt, flow, BPF_ANY))
			goto err;

		bpf_printk("XDP HPFQ scheduled with priority, root:%d right:%d", root_prio, right_prio);
		return bpf_redirect_map(&right_pifo_map, right_prio, 0);
	}
err:
	bpf_printk("XDP DROP");
	return XDP_DROP;
}

/* Hierarchical Packet Fair Queueing (HPFQ) */
SEC("xdp")
int enqueue_prog(struct xdp_md *xdp)
{
	struct parsing_context pctx = {
		.data = (void *)(long)xdp->data,
		.data_end = (void *)(long)xdp->data_end,
		.pkt_len = (xdp->data_end - xdp->data) & 0xffff,
		.nh = { .pos = (void *)(long)xdp->data },
	};
	return schedule_packet(&pctx);
}


SEC("dequeue")
void *dequeue_prog(struct dequeue_ctx *ctx)
{
	struct parsing_context pctx;
	struct packet_info p_info = {0};

	struct network_tuple nt;
	__u32 leaf_id;

	struct flow_state *flow;

	__u64 root_prio = 0;
	__u64 leaf_prio = 0;

	struct xdp_md *pkt = NULL;


	if (bpf_map_pop_elem(&root_pifo_map, &leaf_id))
		goto err;

	if (leaf_id == LEFT_PIFO)
		pkt = (void *) bpf_packet_dequeue(ctx, &left_pifo_map, 0, &leaf_prio);
	else if (leaf_id == RIGHT_PIFO)
		pkt = (void *) bpf_packet_dequeue(ctx, &right_pifo_map, 0, &leaf_prio);

	if (!pkt)
		goto err;

	pctx.data = (void *)(long) pkt->data;
	pctx.data_end = (void *)(long) pkt->data_end;
	pctx.nh.pos = (void *)(long) pkt->data;

	/* Get flows */
	if (parse_packet(&pctx, &p_info) < 0)
		goto err;

	nt = p_info.nt;

	// Handle flow
	flow = bpf_map_lookup_elem(&flow_states, &nt);
	if (!flow)
		goto err;
	root_prio = flow->root_priority;

	flow->pkts--;
	if (flow->pkts <= 0) {
		if (!flow->persistent) {
			bpf_map_delete_elem(&flow_states, &nt);
		} else {
			flow->root_finish_bytes = 0;
			flow->finish_bytes = 0;
		}
	}

	// Handle virtual time in bytes
	root_time_bytes = root_prio;
	if (leaf_id == LEFT_PIFO)
		left_time_bytes = leaf_prio;
	else
		right_time_bytes = leaf_prio;

	bpf_printk("Frey: left_time_bytes:%d right_time_bytes:%d", left_time_bytes, right_time_bytes);
	bpf_printk("flow: %hd - root_weight:%d leaf_weight:%d", nt.daddr.port, flow->root_weight, flow->weight);
	if (leaf_id == LEFT_PIFO)
		bpf_printk("DEQUEUE HPFQ with priority, root:%d left:%d", root_prio, leaf_prio);
	else
		bpf_printk("DEQUEUE HPFQ with priority, root:%d right:%d", root_prio, leaf_prio);

	return pkt;
err:
	if (pkt)
		bpf_packet_drop(ctx, pkt);
	bpf_printk("DEQUEUE packet failed");
	return NULL;
}

char _license[] SEC("license") = "GPL";
