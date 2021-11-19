/* SPDX-License-Identifier: GPL-2.0 */

#include <linux/bpf.h>

#include <bpf/bpf_helpers.h>

#include <bpf/bpf_core_read.h> /* bpf_core_type_id_local */

#include "xdp/parsing_helpers.h"
#include "af_xdp_kern_shared.h"

struct {
	__uint(type, BPF_MAP_TYPE_XSKMAP);
	__uint(max_entries, MAX_AF_SOCKS);
	__uint(key_size, sizeof(int));
	__uint(value_size, sizeof(int));
} xsks_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, __u32);
	__type(value, __u32);
	__uint(max_entries, MAX_AF_SOCKS);
} xdp_stats_map SEC(".maps");

/*
 * The xdp_hints_xxx struct's are stored in the XDP 'data_meta' area,
 * which is located just in-front-of the raw packet payload data.
 *
 * Explaining the struct attribute's:
 * ----------------------------------
 * The struct must be 4 byte aligned (kernel requirement), which here
 * is enforced by the struct __attribute__((aligned(4))).
 *
 * To avoid any C-struct padding attribute "packed" is used.
 *
 * NOTICE: Do NOT define __attribute__((preserve_access_index)) here,
 * as libbpf will try to find a matching kernel data-structure,
 * e.g. it will cause BPF-prog loading step to fail (with invalid func
 * unknown#195896080 which is 0xbad2310 in hex for "bad relo").
 */
struct xdp_hints_mark {
	__u32 mark;
	__u32 btf_id;
} __attribute__((aligned(4))) __attribute__((packed));

struct xdp_hints_rx_time {
	__u64 rx_ktime;
	__u32 xdp_rx_cpu;
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
	meta->xdp_rx_cpu = bpf_get_smp_processor_id();
	/* Userspace can identify struct used by BTF id */
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

/* Neighbor Discovery in IPv6 - Values taken from RFC4861 */
#define NDP_R_SOL	133 /* Router Solicitation */
#define NDP_R_ADV	134 /* Router Advertisement */
#define NDP_SOL 	135 /* Neighbor Solicitation */
#define NDP_ADV 	136 /* Neighbor Advertisement */
#define NDP_REDIR 	137 /* Redirect Message */

int parse_pkt__is_ARP_or_NDP(struct xdp_md *ctx)
{
	void *data     = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct hdr_cursor nh  = { .pos = data };
	struct ethhdr *eth;
	int eth_type;

	eth_type = parse_ethhdr(&nh, data_end, &eth);
	if (eth_type < 0)
		return -1;

	if (eth_type == bpf_htons(ETH_P_ARP))
		return 1;

	if (eth_type == bpf_htons(ETH_P_IPV6)) {
		struct ipv6hdr *ip6h;
		int ip_type = parse_ip6hdr(&nh, data_end, &ip6h);
		if (ip_type < 0)
			return -1;

		if (ip_type == IPPROTO_ICMPV6) {
			struct icmp6hdr *icmp6hdr;
			int icmp6_type = parse_icmp6hdr(&nh, data_end, &icmp6hdr);

			if (icmp6_type < 0)
				return -1;
			if (icmp6_type >= NDP_R_SOL &&
			    icmp6_type <= NDP_REDIR)
				return 1;
		}
	}

	return 0;
}

SEC("xdp_sock")
int xdp_sock_prog(struct xdp_md *ctx)
{
	int index = ctx->rx_queue_index;
	__u32 *pkt_count;
	int err, ret;

	pkt_count = bpf_map_lookup_elem(&xdp_stats_map, &index);
	if (!pkt_count)
		return XDP_ABORTED;
	__u64 cnt = (*pkt_count)++;
//	if (cnt == 0) {
//		if (bpf_ktime_get_ns() == 42)
//			return XDP_ABORTED;
//		cnt++;
//	}

	/* Notice how two different xdp_hints meta-data are used */
	if ((cnt % 2) == 0) {
		err = meta_add_rx_time(ctx);
		if (err < 0)
			return XDP_ABORTED;
	} else {
		err = meta_add_mark(ctx, 42);
		if (err < 0)
			return XDP_DROP;
	}

	/* Let network stack handle ARP and IPv6 Neigh Solicitation */
	ret = parse_pkt__is_ARP_or_NDP(ctx);
	if (ret < 0)
		return XDP_ABORTED;
	if (ret == 1)
		return XDP_PASS;

	/* A set entry here means that the correspnding queue_id
	 * has an active AF_XDP socket bound to it. */
	if (bpf_map_lookup_elem(&xsks_map, &index))
		return bpf_redirect_map(&xsks_map, index, 0);

	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
