/* SPDX-License-Identifier: GPL-2.0+ */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <xdp/parsing_helpers.h>
#include "iproute2_compat.h"

char _license[] SEC("license") = "GPL";

#define NS_PER_SEC 1000000000

struct edt_val {
	__u64	rate;
	__u64	t_last;
	__u64	t_horizon_drop;
	__u64	t_horizon_ecn;
};

/* The tc tool (iproute2) use another ELF map layout than libbpf (struct
 * bpf_map_def), see struct bpf_elf_map from iproute2.
 */
struct bpf_elf_map SEC("maps") time_delay_map = {
	.type		= BPF_MAP_TYPE_ARRAY,
	.size_key	= sizeof(__u32),
	.size_value	= sizeof(struct edt_val),
	.max_elem	= 1,
	//.pinning	= PIN_GLOBAL_NS,
};

static __always_inline int sched_departure(struct __sk_buff *skb)
{
	struct edt_val *edt;
	__u64 t_xmit_ns;
	int key = 0;
	__u64 now;

	edt = bpf_map_lookup_elem(&time_delay_map, &key);
	if (!edt)
		return BPF_DROP;

	// FIXME: Warning NON-functional state

	t_xmit_ns = ((__u64)skb->len) * NS_PER_SEC / edt->rate;

	now = bpf_ktime_get_ns();
	// XXX: Test helpers and write access to SKB is avail
	skb->tstamp = now;
	return BPF_OK;
}

SEC("classifier") int tc_edt_simple(struct __sk_buff *skb)
{
	volatile void *data, *data_end;
	int ret = BPF_OK;
	struct ethhdr *eth;

	data     = (void *)(long)skb->data;
	data_end = (void *)(long)skb->data_end;
	eth = (struct ethhdr *)data;

	if (data + sizeof(*eth) > data_end)
		return BPF_DROP;

	/* Keep ARP resolution working */
	if (eth->h_proto == bpf_htons(ETH_P_ARP)) {
		ret = BPF_OK;
		goto out;
	}

	// TODO: match on vlan16 and only apply EDT on that
	return sched_departure(skb);

 out:
	return ret;
}
