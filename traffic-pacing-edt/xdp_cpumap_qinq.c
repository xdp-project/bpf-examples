/* SPDX-License-Identifier: GPL-2.0+ */
#include <linux/types.h>
#include <linux/bpf.h> /* struct bpf_cpumap_val */
#include <bpf/bpf_helpers.h>
#include <bpf/compiler.h>

#define INITVAL 15485863
//#define INITVAL 2654435761

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

/* Mapping table with CPUs enabled, for hashing between */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, __u32);
	__uint(max_entries, MAX_CPUS);
} cpus_enabled SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, __u32);
	__uint(max_entries, 1);
} cpus_count SEC(".maps");

static __always_inline
__u32 extract_vlan_key(struct collect_vlans *vlans)
{
	/* Combine inner and outer VLAN as a key */
	__u32  vlan_key = (vlans->id[1] << 16) | vlans->id[0];
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
	__u32 cpu_idx, cpu_dest = 0;
	__u32 *cpu_lookup;
	__u64 action;
	__u32 *cpu_max;


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

	int key0 = 0;
	cpu_max = bpf_map_lookup_elem(&cpus_count, &key0);
	if (!cpu_max)
		return XDP_ABORTED;

	/* Use inner+outer VLAN as key and hash based on max_cpus */
	vlan_key = extract_vlan_key(&vlans);
	hash_key = SuperFastHash((char *)&vlan_key, 4, INITVAL);
	cpu_idx = hash_key % *cpu_max;

	/* To allow excluding some CPUs, a mapping table cpus_enabled
	 * translates cpu_idx to real CPU-id
	 */
	cpu_lookup = bpf_map_lookup_elem(&cpus_enabled, &cpu_idx);
	if (!cpu_lookup)
		return XDP_ABORTED;
	cpu_dest = *cpu_lookup;

	/* Notice: Userspace MUST insert entries into cpumap */
	action = bpf_redirect_map(&cpumap, cpu_dest, XDP_PASS);
out:
	return action;
}
