/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
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

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(key_size, sizeof(struct packet_id));
	__uint(value_size, sizeof(struct packet_timestamp));
	__uint(max_entries, 16384);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} ts_start SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u32));
} rtt_events SEC(".maps");

// XDP program for parsing TSECR-val from ingress traffic and check for match in map
SEC(XDP_PROG_SEC)
int xdp_prog_ingress(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;

	int proto = -1;
	__u32 tsval, tsecr;

	struct hdr_cursor nh = { .pos = data };
	struct ethhdr *eth;
	struct iphdr *iph;
	struct ipv6hdr *ip6h;
	struct tcphdr *tcph;

	struct packet_id p_id = { 0 };
	struct packet_timestamp *p_ts;
	struct rtt_event event = { 0 };

	proto = bpf_ntohs(parse_ethhdr(&nh, data_end, &eth));

	// Parse IPv4/6 header
	if (proto == ETH_P_IP) {
		p_id.flow.ipv = AF_INET;
		proto = parse_iphdr(&nh, data_end, &iph);
	} else if (proto == ETH_P_IPV6) {
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

	// We have a TCP-timestamp - now we can check if it's in the map
	p_id.identifier = tsecr;
	p_id.flow.proto == proto;
	// Fill in reverse order of egress (dest <--> source)
	if (p_id.flow.ipv == AF_INET) {
		map_ipv4_to_ipv6(iph->daddr, &p_id.flow.saddr);
		map_ipv4_to_ipv6(iph->saddr, &p_id.flow.daddr);
	} else { // IPv6
		p_id.flow.saddr = ip6h->daddr;
		p_id.flow.daddr = ip6h->saddr;
	}
	p_id.flow.sport = tcph->dest;
	p_id.flow.dport = tcph->source;

	p_ts = bpf_map_lookup_elem(&ts_start, &p_id);

	// Only calculate RTT for first packet with matching TSecr
	if (p_ts && p_ts->used == 0) {
		/*
		 * As used is not set atomically with the lookup, could 
		 * potentially have multiple "first" packets (on different 
		 * CPUs), but all those should then also have very similar RTT,
		 * so don't consider it a significant issue
		 */
		p_ts->used = 1;
		// TODO - Optional delete of entry (if identifier is garantued unique)

		memcpy(&event.flow, &p_id.flow, sizeof(struct network_tuple));
		event.rtt = bpf_ktime_get_ns() - p_ts->timestamp;
		bpf_perf_event_output(ctx, &rtt_events, BPF_F_CURRENT_CPU,
				      &event, sizeof(event));
	}

end:
	return XDP_PASS;
}
