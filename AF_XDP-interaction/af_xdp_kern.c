/* SPDX-License-Identifier: GPL-2.0 */

#include <linux/bpf.h>

#include <bpf/bpf_helpers.h>

#include <bpf/bpf_core_read.h> /* */

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
struct meta_info {
	__u32 mark;
	__u32 btf_id;
} __attribute__((aligned(4)));
/*
 * NOTICE: Do NOT define __attribute__((preserve_access_index)) here,
 * as libbpf will try to find a matching kernel data-structure,
 * e.g. it will cause BPF-prog loading step to fail (with invalid func
 * unknown#195896080 which is 0xbad2310 in hex for "bad relo").
 */

SEC("xdp_sock")
int xdp_sock_prog(struct xdp_md *ctx)
{
	int index = ctx->rx_queue_index;
	struct meta_info *meta;
	__u32 *pkt_count;
	void *data;
	int err;

	/* Reserve space in-front of data pointer for our meta info.
	 * (Notice drivers not supporting data_meta will fail here!)
	 */
	err = bpf_xdp_adjust_meta(ctx, -(int)sizeof(*meta));
	if (err)
		return XDP_ABORTED;

	/* Notice: Kernel-side verifier requires that loading of
	 * ctx->data MUST happen _after_ helper bpf_xdp_adjust_meta(),
	 * as pkt-data pointers are invalidated.  Helpers that require
	 * this are determined/marked by bpf_helper_changes_pkt_data()
	 */
	data = (void *)(unsigned long)ctx->data;

	/* Check data_meta have room for meta_info struct */
	meta = (void *)(unsigned long)ctx->data_meta;
	if (meta + 1 > data)
		return XDP_ABORTED;

	meta->mark = 42;
	meta->btf_id = bpf_core_type_id_local(struct xdp_hints_mark);

	pkt_count = bpf_map_lookup_elem(&xdp_stats_map, &index);
	if (pkt_count) {
		/* We pass every other packet */
		if ((*pkt_count)++ & 1)
			return XDP_PASS;
	}

	/* A set entry here means that the correspnding queue_id
	 * has an active AF_XDP socket bound to it. */
	if (bpf_map_lookup_elem(&xsks_map, &index))
		return bpf_redirect_map(&xsks_map, index, 0);

	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
