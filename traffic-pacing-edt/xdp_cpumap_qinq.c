/* SPDX-License-Identifier: GPL-2.0+ */
#include <linux/types.h>
#include <linux/bpf.h> /* struct bpf_cpumap_val */
#include <bpf/bpf_helpers.h>
#include <bpf/compiler.h>

#define INITVAL 15485863
#include "hash_func01.h" /* SuperFastHash */

#include <bpf/bpf_helpers.h>

#define VLAN_MAX_DEPTH 2
#include <xdp/parsing_helpers.h>

#define MAX_CPUS 24

/* This global variable is used for limiting CPU that can be selected */
__u32 global_max_cpus = 12; /* TODO: Allow userspace to adjust this */

/* Special map type that can XDP_REDIRECT frames to another CPU */
struct {
	__uint(type, BPF_MAP_TYPE_CPUMAP);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(struct bpf_cpumap_val));
	__uint(max_entries, MAX_CPUS);
} cpumap SEC(".maps");

static __always_inline
__u32 extract_vlan_key(struct collect_vlans *vlans)
{
	/* Combine inner and outer VLAN as a key */
	__u32  vlan_key = (vlans->id[1] << 16) |  vlans->id[0];
	return vlan_key;
}

SEC("xdp")
int  xdp_cpumap_qinq(struct xdp_md *ctx)
{
	void *data     = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct collect_vlans vlans = { 0 };
	__u32 hash_key, vlan_key;
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

	/* Use inner+outer VLAN as key and hash based on max_cpus */
	vlan_key = extract_vlan_key(&vlans);
	hash_key = SuperFastHash((char *)&vlan_key, 4, INITVAL);
	cpu_dest = hash_key % global_max_cpus;

	/* Notice: Userspace MUST insert entries into cpumap */
	action = bpf_redirect_map(&cpumap, cpu_dest, XDP_PASS);
out:
	return action;
}
