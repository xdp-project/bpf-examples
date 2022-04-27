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
	__uint(max_entries, 4096);
	__uint(map_extra, 4096); /* range */
} pifo_map SEC(".maps");


/* Simple FIFO  */
SEC("xdp")
int enqueue_prog(struct xdp_md *xdp)
{
	void *data = (void *)(long)xdp->data;
	void *data_end = (void *)(long)xdp->data_end;
	struct ethhdr *eth = data;

	if (eth + 1 > data_end)
		return XDP_DROP;

	return bpf_redirect_map(&pifo_map, 0, 0);
}

SEC("dequeue")
void *dequeue_prog(struct dequeue_ctx *ctx)
{
	__u64 prio = 0;
	void *pkt = (void *) bpf_packet_dequeue(ctx, &pifo_map, 0, &prio);
	if (!pkt)
		return 0;

	return pkt;
}

char _license[] SEC("license") = "GPL";
