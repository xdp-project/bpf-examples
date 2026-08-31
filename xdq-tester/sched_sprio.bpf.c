// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2022 Freysteinn Alfredsson <freysteinn@freysteinn.com> */

#include <vmlinux_local.h>
#include <linux/bpf.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <xdp/parsing_helpers.h>

#include "bpf_local_helpers.h"

struct {
	__uint(type, BPF_MAP_TYPE_PIFO_XDP);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u32));
	__uint(max_entries, 1024);
	__uint(map_extra, 4096); /* range */
} pifo_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct network_tuple);
	__type(value, struct flow_state);
	__uint(max_entries, 16384);
} flow_states SEC(".maps");

__u32 default_weight = 256;

static __always_inline int schedule_packet(struct parsing_context *pctx)
{
	struct packet_info p_info = {};
	struct network_tuple nt = {0};
	struct flow_state *flow;
	struct flow_state new_flow = {0};
	__u32 prio = 0;

	new_flow.pkts = 0;
	new_flow.finish_bytes = 0;
	new_flow.weight = default_weight;
	new_flow.persistent = 0;

	/* Get flow */
	if (parse_packet(pctx, &p_info) < 0)
		goto err;

	nt = p_info.nt;

	flow = bpf_map_lookup_or_try_init(&flow_states, &nt, &new_flow);
	if (!flow)
		goto err;

	flow->pkts++;

	/* Calculate scheduling priority */
	prio = flow->weight;

	if (bpf_map_update_elem(&flow_states, &nt, flow, BPF_ANY))
		goto err;

	bpf_printk("XDP SPRIO scheduled with priority %d", prio);
	return bpf_redirect_map(&pifo_map, prio, 0);
err:
	bpf_printk("XDP DROP");
	return XDP_DROP;
}

/* Simple strict priority */
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
	struct flow_state *flow;
	__u64 prio = 0;

	struct xdp_md *pkt = NULL;

	pkt = (void *)bpf_packet_dequeue(ctx, &pifo_map, 0, &prio);
	if (!pkt)
		goto err;

	pctx.data = (void *)(long) pkt->data;
	pctx.data_end = (void *)(long) pkt->data_end;
	pctx.nh.pos = (void *)(long) pkt->data;

	/* Get flow */
	if (parse_packet(&pctx, &p_info) < 0)
		goto err;

	nt = p_info.nt;

	flow = bpf_map_lookup_elem(&flow_states, &nt);
	if (!flow)
		goto err;

	flow->pkts--;
	if (flow->pkts <= 0) {
		if (!flow->persistent)
			bpf_map_delete_elem(&flow_states, &nt);
		else
			flow->finish_bytes = 0;
	}

	bpf_printk("DEQUEUE SPRIO with priority %d", prio);
	return pkt;
err:
	if (pkt)
		bpf_packet_drop(ctx, pkt);
	bpf_printk("DEQUEUE packet failed");
	return NULL;
}

char _license[] SEC("license") = "GPL";
