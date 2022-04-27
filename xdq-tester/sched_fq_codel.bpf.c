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
	__uint(map_extra, 8388608); /* range - 1024×4098×2 */
} pifo_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct network_tuple);
	__type(value, struct fq_codel_flow_state);
	__uint(max_entries, 16384);
} flow_states SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, __u64);
	__uint(max_entries, 1);
} xdq_time_ns SEC(".maps");

const __u32 quantom = 1522;
__u64 time_bytes = quantom;

struct xdq_meta {
        __u64 time_ns;
        __u32 btf_id;
} __attribute__((aligned(4))) __attribute__((packed));

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
        int err;

        /* Reserve space in-front of data pointer for our meta info.
         * (Notice drivers not supporting data_meta will fail here!)
         */
        err = bpf_xdp_adjust_meta(ctx, -(int)sizeof(*meta));
        if (err) {
		bpf_printk("Frey: Failed to add meta data section");
                return -1;
	}

        /* Notice: Kernel-side verifier requires that loading of
         * ctx->data MUST happen _after_ helper bpf_xdp_adjust_meta(),
         * as pkt-data pointers are invalidated.  Helpers that require
         * this are determined/marked by bpf_helper_changes_pkt_data()
         */
        data = (void *)(unsigned long)ctx->data;

        meta = (void *)(unsigned long)ctx->data_meta;
        if (meta + 1 > data) /* Verify meta area is accessible */
                return -2;

        meta->time_ns = get_time_ns();
        /* Userspace can identify struct used by BTF id */
        meta->btf_id = bpf_core_type_id_local(struct xdq_meta);
        return 0;
}

static __always_inline int schedule_packet(struct parsing_context *pctx)
{
	struct packet_info p_info = {};
	struct network_tuple nt = {0};
	struct fq_codel_flow_state *flow;
	struct fq_codel_flow_state new_flow = {0};
	__u32 flow_time_bytes = time_bytes; // Used to offset sparse flows
	__u32 packet_start_time_bytes;
	__u32 prio = 0;

	char flow_type = 'd';

	/* Get flow */
	if (parse_packet(pctx, &p_info) < 0)
		goto err;

	nt = p_info.nt;

	flow = bpf_map_lookup_or_try_init(&flow_states, &nt, &new_flow);
	if (!flow)
		goto err;

	/* Handle Sparse flows */
	if (flow->pkts == 0 && flow_time_bytes >= flow->grace_period) { // New flow
		flow_type = 'S';
		flow->pkts = 0;
		flow->total_bytes = (pctx->data_end - pctx->data);
		flow->finish_bytes = 0;
		flow->grace_period = flow_time_bytes + quantom;

		flow_time_bytes -= quantom; // Give sparse flows a negative quantom priority;
	} else if (flow->total_bytes < quantom) {
		flow_type = 's';
		flow->total_bytes += (pctx->data_end - pctx->data);
		flow_time_bytes -= quantom; // Give sparse flows a negative quantom priority;
	}
	flow->pkts++;

	/* Calculate scheduling priority */
	packet_start_time_bytes = bpf_max(flow_time_bytes, flow->finish_bytes);
	flow->finish_bytes = packet_start_time_bytes + pctx->pkt_len;
	prio = packet_start_time_bytes;

	if (bpf_map_update_elem(&flow_states, &nt, flow, BPF_ANY))
		goto err;

	bpf_printk("ENQUEUE: port: %d -> prio: %6d -> time_bytes: %6d -> pkt: %6d -> end: %6d type: %c ", (int) bpf_ntohs(nt.daddr.port), prio, time_bytes, flow->pkts, flow->finish_bytes, flow_type);
	return bpf_redirect_map(&pifo_map, prio, 0);
err:
	bpf_printk("XDP DROP");
	return XDP_DROP;
}

/* Weighted fair queueing (WFQ) */
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
	struct parsing_context pctx;
	struct packet_info p_info = {0};
	struct network_tuple nt;
	struct fq_codel_flow_state *flow;
        struct xdq_meta *meta;
	__u64 now;
	__u64 sojourn_time;
	__u64 prio = 0;

	struct xdp_md *pkt = NULL;

	pkt = (void *) bpf_packet_dequeue(ctx, &pifo_map, 0, &prio);
	if (!pkt) {
		bpf_printk("Frey: No packet in PIFO");
		goto err;
	}

	pctx.data = (void *)(long) pkt->data;
	pctx.data_end = (void *)(long) pkt->data_end;
	pctx.nh.pos = (void *)(long) pkt->data;
	pctx.meta = (void *)(long) pkt->data_meta;

	/* Get flow */
	if (parse_packet(&pctx, &p_info) < 0) {
		bpf_printk("Frey: Parse failed");
		goto err;
	}

	nt = p_info.nt;

	flow = bpf_map_lookup_elem(&flow_states, &nt);
	if (!flow) {
		bpf_printk("Frey: Failed to lookup flow");
		goto err;
	}

	flow->pkts--;

	if (prio > time_bytes)
		time_bytes = prio;

        meta = (struct xdq_meta *) pctx.meta;
        if (meta + 1 > pctx.data) { /* Verify meta area is accessible */
		bpf_printk("Frey: Failed to lookup metadata");
                goto err;
	}
	now = get_time_ns();
	sojourn_time = now - meta->time_ns;
	if (codel_drop(&flow->codel, sojourn_time, now)) {
		bpf_printk("Frey: Codel dropped packet!");
		goto err;
	}

	bpf_printk("DEQUEUE: port: %d <- prio: %6d <- time_bytes: %6d <- pkt: %6d <- tot: %6d", (int) bpf_ntohs(nt.daddr.port), prio, time_bytes, flow->pkts, flow->total_bytes);
	return pkt;
err:
	if (pkt)
		bpf_packet_drop(ctx, pkt);
	bpf_printk("DEQUEUE packet failed");
	return NULL;
}

char _license[] SEC("license") = "GPL";
