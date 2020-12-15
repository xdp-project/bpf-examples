/* SPDX-License-Identifier: GPL-2.0+ */
#include <linux/types.h>
#include <linux/bpf.h> /* struct bpf_cpumap_val */
#include <bpf/bpf_helpers.h>
#include <bpf/compiler.h>


#include <bpf/bpf_helpers.h>

#define VLAN_MAX_DEPTH 2
#include <xdp/parsing_helpers.h>

#define MAX_CPUS 24

/* Special map type that can XDP_REDIRECT frames to another CPU */
struct {
	__uint(type, BPF_MAP_TYPE_CPUMAP);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(struct bpf_cpumap_val));
	__uint(max_entries, MAX_CPUS);
} cpumap SEC(".maps");

SEC("xdp")
int  xdp_cpumap_qinq(struct xdp_md *ctx)
{
	void *data     = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct collect_vlans vlans = { 0 };
	struct ethhdr *eth;
	__u32 cpu_dest = 0;
	__u64 action;

	/* These keep track of the next header type and iterator pointer */
	struct hdr_cursor nh;
	int eth_type;
	nh.pos = data;

	eth_type = parse_ethhdr_vlan(&nh, data_end, &eth, &vlans);
	if (eth_type < 0) {
		action = XDP_ABORTED;
		goto out;
	}

	/* Keep ARP resolution working */
	if (eth_type == bpf_htons(ETH_P_ARP)) {
		action = XDP_PASS;
		goto out;
	}

	if (!proto_is_vlan(eth->h_proto)) {
		/* Skip non-VLAN frames */
		action = XDP_PASS;
		goto out;
	}

	// WARNING: Userspace MUST insert entries into cpumap
	action = bpf_redirect_map(&cpumap, cpu_dest, XDP_PASS);
out:
	return action;
}
