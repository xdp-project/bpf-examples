/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <xdp/parsing_helpers.h>

#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>

#include <string.h>

#include "pping.h"
#include "pping_helpers.h"

char _license[] SEC("license") = "GPL";

struct bpf_map_def SEC("maps") ts_start = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(struct ts_key),
	.value_size = sizeof(struct ts_timestamp),
	.max_entries = 16384,
};

struct bpf_map_def SEC("maps") rtt_events = {
	.type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
	.key_size = sizeof(__u32), // CPU ID
	.value_size = sizeof(__u32), // perf file descriptor?
};

// XDP program for parsing TSECR-val from ingress traffic and check for match in map
SEC("pping_ingress")
int xdp_prog_ingress(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	int proto = -1;
	struct hdr_cursor nh = { .pos = data };
	struct ethhdr *eth;
	struct iphdr *iph;
	struct tcphdr *tcph;

	//bpf_printk("Received packet of length %d\n", (int)(data_end - data));
	proto = parse_ethhdr(&nh, data_end, &eth);
	if (bpf_ntohs(proto) != ETH_P_IP)
		goto end; 
	proto = parse_iphdr(&nh, data_end, &iph);
	if (proto != IPPROTO_TCP)
		goto end; 
	proto = parse_tcphdr(&nh, data_end, &tcph);
	if (proto < 0)
		goto end; 

	//bpf_printk("TCP-packet with %d byte header and %lu bytes of data\n", proto, data_end - nh.pos);

	__u32 tsval, tsecr;
	if (parse_tcp_ts(tcph, data_end, &tsval, &tsecr) < 0) 
		goto end;

	// We have a TCP-timestamp - now we can check if it's in the map
	//bpf_printk("TCP-packet with timestap. TSval: %u, TSecr: %u\n", bpf_ntohl(tsval), bpf_ntohl(tsecr));
	struct ts_key key;
	// Fill in reverse order of egress (dest <--> source)
	fill_ipv4_flow(&(key.flow), iph->daddr, iph->saddr,
		       tcph->dest, tcph->source);
	key.tsval = tsecr;
	struct ts_timestamp *ts = bpf_map_lookup_elem(&ts_start, &key);
	// Only calculate RTT for first packet with matching TSecr
	if (ts && ts->used == 0) {
		/*
		 * As used is not set atomically with the lookup, could 
		 * potentially have multiple "first" packets (on different 
		 * CPUs), but all those should then also have very similar RTT,
		 * so don't consider it a significant issue
		 */
		ts->used = 1;

		struct rtt_event event = { 0 };
		memcpy(&(event.flow), &(key.flow), sizeof(struct ipv4_flow));
		event.rtt = bpf_ktime_get_ns() - ts->timestamp;
		bpf_perf_event_output(ctx, &rtt_events, BPF_F_CURRENT_CPU,
				      &event, sizeof(event));
		//bpf_printk("Pushed rtt event with RTT: %llu\n", event.rtt);
	}
end:
	return XDP_PASS;
}
