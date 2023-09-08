// SPDX-License-Identifier: GPL-2.0

#include "vmlinux_local.h"
#include "linux/bpf.h"
#include <bpf/bpf_helpers.h>


#define NF_DROP 0
#define NF_ACCEPT 1

int bpf_dynptr_from_skb(struct sk_buff *skb,
		__u64 flags, struct bpf_dynptr *ptr__uninit) __ksym;
void *bpf_dynptr_slice(const struct bpf_dynptr *ptr,
		uint32_t offset, void *buffer, uint32_t buffer__sz) __ksym;


struct ipv4_lpm_key {
	__u32 prefixlen;
	__u32 data;
};

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__type(key, struct ipv4_lpm_key);
	__type(value, __u32);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__uint(max_entries, 200);
} ipv4_lpm_map SEC(".maps");


SEC("netfilter")
int netfilter_ip4block(struct bpf_nf_ctx *ctx)
{
	struct sk_buff *skb = ctx->skb;
	struct bpf_dynptr ptr;
	struct iphdr *p, iph = {};
	struct ipv4_lpm_key key;
	__u32 *pvalue;

	if (skb->len <= 20 || bpf_dynptr_from_skb(skb, 0, &ptr))
		return NF_ACCEPT;
	p = bpf_dynptr_slice(&ptr, 0, &iph, sizeof(iph));
	if (!p)
		return NF_ACCEPT;

	/* ip4 only */
	if (p->version != 4)
		return NF_ACCEPT;

	/* search p->daddr in trie */
	key.prefixlen = 32;
	key.data = p->daddr;
	pvalue = bpf_map_lookup_elem(&ipv4_lpm_map, &key);
	if (pvalue) {
		/* cat /sys/kernel/debug/tracing/trace_pipe */
		bpf_printk("rule matched with %d...\n", *pvalue);
		return NF_DROP;
	}
	return NF_ACCEPT;
}

char _license[] SEC("license") = "GPL";

