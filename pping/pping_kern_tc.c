/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <iproute2/bpf_elf.h>
#include <xdp/parsing_helpers.h>

#include <linux/in.h>
#include <linux/in6.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>

#include <string.h>

#include "pping.h"
#include "pping_helpers.h"

char _license[] SEC("license") = "GPL";

#ifdef HAVE_TC_LIBBPF /* detected by configure script in config.mk */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(key_size, sizeof(struct packet_id));
	__uint(value_size, sizeof(struct packet_timestamp));
	__uint(max_entries, 16384);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} ts_start SEC(".maps");

#else
struct bpf_elf_map SEC("maps") ts_start = {
	.type = BPF_MAP_TYPE_HASH,
	.size_key = sizeof(struct packet_id),
	.size_value = sizeof(struct packet_timestamp),
	.max_elem = 16384,
	.pinning = PIN_GLOBAL_NS,
};
#endif

// TC-BFP for parsing TSVAL from egress traffic and add to map
SEC(TCBPF_PROG_SEC)
int tc_bpf_prog_egress(struct __sk_buff *skb)
{
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;

	int proto = -1;
	__u32 tsval, tsecr;

	struct hdr_cursor nh = { .pos = data };
	struct ethhdr *eth;
	struct iphdr *iph;
	struct ipv6hdr *ip6h;
	struct tcphdr *tcph;

	struct packet_id p_id = { 0 };
	struct packet_timestamp p_ts = { 0 };

	proto = parse_ethhdr(&nh, data_end, &eth);

	// Parse IPv4/6 header
	if (proto == bpf_htons(ETH_P_IP)) {
		p_id.flow.ipv = AF_INET;
		proto = parse_iphdr(&nh, data_end, &iph);
	} else if (proto == bpf_htons(ETH_P_IPV6)) {
		p_id.flow.ipv = AF_INET6;
		proto = parse_ip6hdr(&nh, data_end, &ip6h);
	} else
		goto end;

	// Parse TCP timestamp
	if (proto != IPPROTO_TCP)
		goto end;
	if (parse_tcphdr(&nh, data_end, &tcph) < 0)
		goto end;
	if (parse_tcp_ts(tcph, data_end, &tsval, &tsecr) < 0)
		goto end;

	// We have a TCP timestamp, try adding it to the map
	p_id.identifier = tsval;
	if (p_id.flow.ipv == AF_INET) {
		map_ipv4_to_ipv6(iph->saddr, &p_id.flow.saddr);
		map_ipv4_to_ipv6(iph->daddr, &p_id.flow.daddr);
	} else { // IPv6
		p_id.flow.saddr = ip6h->saddr;
		p_id.flow.daddr = ip6h->daddr;
	}
	p_id.flow.sport = tcph->source;
	p_id.flow.dport = tcph->dest;

	p_ts.timestamp = bpf_ktime_get_ns(); // or bpf_ktime_get_boot_ns
	bpf_map_update_elem(&ts_start, &p_id, &p_ts, BPF_NOEXIST);

end:
	return BPF_OK;
}
