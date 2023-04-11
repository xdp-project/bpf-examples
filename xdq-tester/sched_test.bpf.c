// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2022 Freysteinn Alfredsson <freysteinn@freysteinn.com> */

#include <vmlinux_local.h>
#include <linux/bpf.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <xdp/parsing_helpers.h>

#include "bpf_local_helpers.h"


struct {
	__uint(type, BPF_MAP_TYPE_PIFO_XDP);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u32));
	__uint(max_entries, 4096);
	__uint(map_extra, 4096); /* range */
} pifo_map SEC(".maps");


struct xdq_meta {
	__u64 time_ns;
} __attribute__((aligned(4))) __attribute__((packed));

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, __u64);
	__uint(max_entries, 1);
} xdq_time_ns SEC(".maps");

static __always_inline __u64 get_time_ns()
{
#ifdef XDQ_LIVE
	return bpf_ktime_get_boot_ns();
#else
	__u32 key = 0;
	__u64 *val = bpf_map_lookup_elem(&xdq_time_ns, &key);
	if (!val) {
		return 0;
	}
	return *val;
#endif
}


static __always_inline int xdq_meta_add(struct xdp_md *ctx)
{
	struct xdq_meta *meta;
	void *data;
	void *data_end;
	int err;

	/* Reserve space in-front of data pointer for our meta info.
	 * (Notice drivers not supporting data_meta will fail here!)
	 */
	err = bpf_xdp_adjust_meta(ctx, -(int)sizeof(*meta));
	if (err) {
		bpf_printk("Frey: Failed to add meta data section");
		return -1;
	}

	data = (void *)(unsigned long)ctx->data;
	data_end = (void *)(unsigned long)ctx->data_end;
	meta = (void *)(unsigned long)ctx->data_meta;
	if (meta + 1 > data) /* Verify meta area is accessible */
		return -2;

	meta->time_ns = get_time_ns();

	bpf_printk("Frey 1: data: %p data_end: %p data_size: %d meta: %p meta+1: %p meta_size: %d", data, data_end, data_end - data, meta, (meta + 1), sizeof(struct xdq_meta));
	return 0;
}


static __always_inline int schedule_packet(struct parsing_context *pctx)
{
	struct packet_info p_info = {};

	/* Get flow */
	if (parse_packet(pctx, &p_info) < 0)
		goto err;


	return bpf_redirect_map(&pifo_map, 0, 0);
err:
	bpf_printk("XDP DROP");
	return XDP_DROP;
}


SEC("xdp")
int enqueue_prog(struct xdp_md *xdp)
{
	if (xdq_meta_add(xdp) < 0) {
		return XDP_ABORTED;
	}

	struct parsing_context pctx = {
		.data = (void *)(long)xdp->data,
		.data_end = (void *)(long)xdp->data_end,
		.meta = (void *)(long)xdp->data_meta,
		.pkt_len = (xdp->data_end - xdp->data) & 0xffff,
		.nh = { .pos = (void *)(long)xdp->data },
	};
	return schedule_packet(&pctx);
}


SEC("dequeue")
void *dequeue_prog(struct dequeue_ctx *ctx)
{
	__u64 prio = 0;
	struct xdp_md *pkt = (void *) bpf_packet_dequeue(ctx, &pifo_map, 0, &prio);
	__u64 sojourn_time = 0;
	void *data;
	struct xdq_meta *meta;

	if (!pkt)
		return 0;

	data = (void *)(unsigned long)pkt->data;
	meta = (void *)(unsigned long)pkt->data_meta;

	if (meta + 1 > data) { /* Verify meta area is accessible */
		bpf_printk("Frey: Failed to lookup metadata");
		bpf_printk("Frey 2: data: %p data_end: %p data_size: %d meta: %p meta+1: %p meta_size: %d", pkt->data, pkt->data_end, pkt->data_end - pkt->data, meta, (meta + 1), sizeof(*meta));
		goto err;
	}
	sojourn_time = meta->time_ns;
	bpf_printk("Frey: Sojourn_time: %llu", sojourn_time);
	return pkt;

err:
	if (pkt)
		bpf_packet_drop(ctx, pkt);
	bpf_printk("DEQUEUE packet failed");
	return NULL;

}

char _license[] SEC("license") = "GPL";
