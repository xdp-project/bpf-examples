/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <xdp/parsing_helpers.h>
#include <linux/pkt_cls.h>

/* We use an LRU map to avoid having to do cleanup: We will remove the matching
 * entry in the map if a packet does not have a DSCP value, but we won't
 * otherwise clean up stale entries. Instead, we just rely on the LRU mechanism
 * to evict old entries as the map fills up.
 */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, __u32);
	__type(value, __u8);
	__uint(max_entries, 16384);
} flow_dscps SEC(".maps");

const volatile static int ip_only = 0;

static __u8 get_dscp(struct __sk_buff *skb)
{
	void *data_end = (void *)(unsigned long long)skb->data_end;
	void *data = (void *)(unsigned long long)skb->data;
	struct hdr_cursor nh = { .pos = data };

	struct ipv6hdr *ipv6hdr;
	struct iphdr *iphdr;
	struct ethhdr *eth;
	int eth_type;

	if (!ip_only) {

		eth_type = parse_ethhdr(&nh, data_end, &eth);
		if (eth_type != bpf_htons(ETH_P_IP) &&
		    eth_type != bpf_htons(ETH_P_IPV6))
			return 0;
	}
	if (parse_iphdr(&nh, data_end, &iphdr) > 0)
		return iphdr->tos >> 2;

	else if (parse_ip6hdr(&nh, data_end, &ipv6hdr) > 0)
		return bpf_ntohs(*(__u16 *)ipv6hdr) >> 4;

	return 0;
}

static inline void ipv4_change_dsfield(struct iphdr *iph, __u8 mask, __u8 value)
{
        __u32 check = bpf_ntohs(iph->check);
	__u8 dsfield;

	dsfield = (iph->tos & mask) | value;
	check += iph->tos;
	if ((check+1) >> 16) check = (check+1) & 0xffff;
	check -= dsfield;
	check += check >> 16; /* adjust carry */
	iph->check = bpf_htons(check);
	iph->tos = dsfield;
}

static inline void ipv6_change_dsfield(struct ipv6hdr *ipv6h,__u8 mask,
    __u8 value)
{
	__u16 *p = (__u16 *)ipv6h;

	*p = (*p & bpf_htons((((__u16)mask << 4) | 0xf00f))) | bpf_htons((__u16)value << 4);
}

#define INET_ECN_MASK 3

static void set_dscp(struct __sk_buff *skb, __u8 dscp)
{
	void *data_end = (void *)(unsigned long long)skb->data_end;
	void *data = (void *)(unsigned long long)skb->data;
	struct hdr_cursor nh = { .pos = data };

	struct ipv6hdr *ipv6hdr;
	struct iphdr *iphdr;
	struct ethhdr *eth;
	int eth_type;

	eth_type = parse_ethhdr(&nh, data_end, &eth);

	if (eth_type == bpf_htons(ETH_P_IP) &&
	    parse_iphdr(&nh, data_end, &iphdr) > 0)
		ipv4_change_dsfield(iphdr, INET_ECN_MASK, dscp << 2);

	else if (eth_type == bpf_htons(ETH_P_IPV6) &&
		 parse_ip6hdr(&nh, data_end, &ipv6hdr) > 0)
		ipv6_change_dsfield(ipv6hdr, INET_ECN_MASK, dscp << 2);
}

SEC("tc")
int read_dscp(struct __sk_buff *skb)
{
	__u32 key = bpf_get_hash_recalc(skb);
	__u8 dscp;

	dscp = get_dscp(skb);
	if (dscp)
		bpf_map_update_elem(&flow_dscps, &key, &dscp, BPF_ANY);
	else
		bpf_map_delete_elem(&flow_dscps, &key);

	return TC_ACT_OK;
}

SEC("tc")
int write_dscp(struct __sk_buff *skb)
{
	__u32 key = skb->hash;
	__u8 *dscp;

	dscp = bpf_map_lookup_elem(&flow_dscps, &key);
	if (dscp)
		set_dscp(skb, *dscp);

	return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
