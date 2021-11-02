/* SPDX-License-Identifier: GPL-2.0 */

#include <linux/bpf.h>

#include <bpf/bpf_helpers.h>

#include <bpf/bpf_core_read.h> /* bpf_core_type_id_local */

struct {
	__uint(type, BPF_MAP_TYPE_XSKMAP);
	__uint(max_entries, 64); /* Assume netdev has no more than 64 queues */
	__uint(key_size, sizeof(int));
	__uint(value_size, sizeof(int));
} xsks_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, __u32);
	__type(value, __u32);
	__uint(max_entries, 64);
} xdp_stats_map SEC(".maps");

/*
 * This struct is stored in the XDP 'data_meta' area, which is located
 * just in-front-of the raw packet payload data.
 *
 * The struct must be 4 byte aligned, which here is enforced by the
 * struct __attribute__((aligned(4))).
 */
struct xdp_hints_mark {
	__u32 mark;
	__u32 btf_id;
} __attribute__((aligned(4))) __attribute__((packed));
/*
 * NOTICE: Do NOT define __attribute__((preserve_access_index)) here,
 * as libbpf will try to find a matching kernel data-structure,
 * e.g. it will cause BPF-prog loading step to fail (with invalid func
 * unknown#195896080 which is 0xbad2310 in hex for "bad relo").
 */

struct xdp_hints_rx_time {
	__u64 rx_ktime;
	__u32 btf_id;
} __attribute__((aligned(4))) __attribute__((packed));

int meta_add_rx_time(struct xdp_md *ctx)
{
	struct xdp_hints_rx_time *meta;
	void *data;
	int err;

	/* Reserve space in-front of data pointer for our meta info.
	 * (Notice drivers not supporting data_meta will fail here!)
	 */
	err = bpf_xdp_adjust_meta(ctx, -(int)sizeof(*meta));
	if (err)
		return -1;

	/* Notice: Kernel-side verifier requires that loading of
	 * ctx->data MUST happen _after_ helper bpf_xdp_adjust_meta(),
	 * as pkt-data pointers are invalidated.  Helpers that require
	 * this are determined/marked by bpf_helper_changes_pkt_data()
	 */
	data = (void *)(unsigned long)ctx->data;

	meta = (void *)(unsigned long)ctx->data_meta;
	if (meta + 1 > data) /* Verify meta area is accessible */
		return -2;

	meta->rx_ktime = bpf_ktime_get_ns();
	meta->btf_id = bpf_core_type_id_local(struct xdp_hints_rx_time);

	return 0;
}

int meta_add_mark(struct xdp_md *ctx, __u32 mark)
{
	struct xdp_hints_mark *meta;
	void *data;
	int err;

	/* Reserve space in-front of data pointer for our meta info */
	err = bpf_xdp_adjust_meta(ctx, -(int)sizeof(*meta));
	if (err)
		return -1;

	data = (void *)(unsigned long)ctx->data;
	meta = (void *)(unsigned long)ctx->data_meta;
	if (meta + 1 > data) /* Verify meta area is accessible */
		return -2;

	meta->mark = mark;
	meta->btf_id = bpf_core_type_id_local(struct xdp_hints_mark);

	return 0;
}

SEC("xdp_sock")
int xdp_sock_prog(struct xdp_md *ctx)
{
	int index = ctx->rx_queue_index;
	__u32 *pkt_count;
	void *data;
	int err;

	pkt_count = bpf_map_lookup_elem(&xdp_stats_map, &index);
	if (!pkt_count)
		return XDP_ABORTED;
	__u64 cnt = (*pkt_count)++;

	if ((cnt % 2) == 0) {
		err = meta_add_rx_time(ctx);
		if (err < 0)
			return XDP_ABORTED;
	} else {
		err = meta_add_mark(ctx, 42);
		if (err < 0)
			return XDP_DROP;
	}

	/* A set entry here means that the correspnding queue_id
	 * has an active AF_XDP socket bound to it. */
	if (bpf_map_lookup_elem(&xsks_map, &index))
		return bpf_redirect_map(&xsks_map, index, 0);

	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
