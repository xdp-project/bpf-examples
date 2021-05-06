/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <stdbool.h>

// overwrite xdp/parsing_helpers.h value to avoid hitting verifier limit
#ifdef IPV6_EXT_MAX_CHAIN
#undef IPV6_EXT_MAX_CHAIN
#endif
#define IPV6_EXT_MAX_CHAIN 3

#include <xdp/parsing_helpers.h>
#include "pping.h"

#define AF_INET 2
#define AF_INET6 10
#define MAX_TCP_OPTIONS 10

/*
 * This struct keeps track of the data and data_end pointers from the xdp_md or
 * __skb_buff contexts, as well as a currently parsed to position kept in nh.
 * Additionally, it also keeps the length of the entire packet, which together
 * with the other members can be used to determine ex. how much data each
 * header encloses.
 */
struct parsing_context {
	void *data; //Start of eth hdr
	void *data_end; //End of safe acessible area
	struct hdr_cursor nh; //Position to parse next
	__u32 pkt_len; //Full packet length (headers+data)
	bool is_egress; //Is packet on egress or ingress?
};

char _license[] SEC("license") = "GPL";
// Global config struct - set from userspace
static volatile const struct bpf_config config = {};

// Map definitions
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct packet_id);
	__type(value, __u64);
	__uint(max_entries, 16384);
} packet_ts SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct network_tuple);
	__type(value, struct flow_state);
	__uint(max_entries, 16384);
} flow_state SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u32));
} rtt_events SEC(".maps");

// Help functions

/*
 * Maps an IPv4 address into an IPv6 address according to RFC 4291 sec 2.5.5.2
 */
static void map_ipv4_to_ipv6(__be32 ipv4, struct in6_addr *ipv6)
{
	__builtin_memset(&ipv6->in6_u.u6_addr8[0], 0x00, 10);
	__builtin_memset(&ipv6->in6_u.u6_addr8[10], 0xff, 2);
	ipv6->in6_u.u6_addr32[3] = ipv4;
}

/*
 * Parses the TSval and TSecr values from the TCP options field. If sucessful
 * the TSval and TSecr values will be stored at tsval and tsecr (in network
 * byte order).
 * Returns 0 if sucessful and -1 on failure
 */
static int parse_tcp_ts(struct tcphdr *tcph, void *data_end, __u32 *tsval,
			__u32 *tsecr)
{
	int len = tcph->doff << 2;
	void *opt_end = (void *)tcph + len;
	__u8 *pos = (__u8 *)(tcph + 1); //Current pos in TCP options
	__u8 i, opt;
	volatile __u8
		opt_size; // Seems to ensure it's always read of from stack as u8

	if (tcph + 1 > data_end || len <= sizeof(struct tcphdr))
		return -1;
#pragma unroll //temporary solution until we can identify why the non-unrolled loop gets stuck in an infinite loop
	for (i = 0; i < MAX_TCP_OPTIONS; i++) {
		if (pos + 1 > opt_end || pos + 1 > data_end)
			return -1;

		opt = *pos;
		if (opt == 0) // Reached end of TCP options
			return -1;

		if (opt == 1) { // TCP NOP option - advance one byte
			pos++;
			continue;
		}

		// Option > 1, should have option size
		if (pos + 2 > opt_end || pos + 2 > data_end)
			return -1;
		opt_size = *(pos + 1);
		if (opt_size < 2) // Stop parsing options if opt_size has an invalid value
			return -1;

		// Option-kind is TCP timestap (yey!)
		if (opt == 8 && opt_size == 10) {
			if (pos + 10 > opt_end || pos + 10 > data_end)
				return -1;
			*tsval = *(__u32 *)(pos + 2);
			*tsecr = *(__u32 *)(pos + 6);
			return 0;
		}

		// Some other TCP option - advance option-length bytes
		pos += opt_size;
	}
	return -1;
}

/*
 * Attempts to fetch an identifier for TCP packets, based on the TCP timestamp
 * option. If sucessful, identifier will be set to TSval if is_ingress, TSecr
 * otherwise, the port-members of saddr and daddr will be set the the TCP source
 * and dest, respectively, and 0 will be returned. On failure, -1 will be
 * returned. Additionally, if the connection is closing (FIN or RST flag), sets
 * flow_closing to true.
 */
static int parse_tcp_identifier(struct parsing_context *ctx, __be16 *sport,
				__be16 *dport, bool *flow_closing,
				__u32 *identifier)
{
	__u32 tsval, tsecr;
	struct tcphdr *tcph;

	if (parse_tcphdr(&ctx->nh, ctx->data_end, &tcph) < 0)
		return -1;

	// Check if connection is closing
	*flow_closing = tcph->rst || (!ctx->is_egress && tcph->fin);

	// Do not timestamp pure ACKs
	if (ctx->is_egress && ctx->nh.pos - ctx->data >= ctx->pkt_len &&
	    !tcph->syn)
		return -1;

	if (parse_tcp_ts(tcph, ctx->data_end, &tsval, &tsecr) < 0)
		return -1; //Possible TODO, fall back on seq/ack instead

	*sport = tcph->source;
	*dport = tcph->dest;
	*identifier = ctx->is_egress ? tsval : tsecr;
	return 0;
}

/*
 * Attempts to parse the packet limited by the data and data_end pointers,
 * to retrieve a protocol dependent packet identifier. If sucessful, the
 * pointed to p_id will be filled with parsed information from the packet
 * packet, and 0 will be returned. On failure, -1 will be returned.
 * If is_egress saddr and daddr will match source and destination of packet,
 * respectively, and identifier will be set to the identifer for an outgoing
 * packet. Otherwise, saddr and daddr will be swapped (will match
 * destination and source of packet, respectively), and identifier will be
 * set to the identifier of a response.
 */
static int parse_packet_identifier(struct parsing_context *ctx,
				   struct packet_id *p_id, bool *flow_closing)
{
	int proto, err;
	struct ethhdr *eth;
	struct iphdr *iph;
	struct ipv6hdr *ip6h;
	struct flow_address *saddr, *daddr;

	// Switch saddr <--> daddr on ingress to match egress
	if (ctx->is_egress) {
		saddr = &p_id->flow.saddr;
		daddr = &p_id->flow.daddr;
	} else {
		saddr = &p_id->flow.daddr;
		daddr = &p_id->flow.saddr;
	}

	proto = parse_ethhdr(&ctx->nh, ctx->data_end, &eth);

	// Parse IPv4/6 header
	if (proto == bpf_htons(ETH_P_IP)) {
		p_id->flow.ipv = AF_INET;
		p_id->flow.proto = parse_iphdr(&ctx->nh, ctx->data_end, &iph);
	} else if (proto == bpf_htons(ETH_P_IPV6)) {
		p_id->flow.ipv = AF_INET6;
		p_id->flow.proto = parse_ip6hdr(&ctx->nh, ctx->data_end, &ip6h);
	} else {
		return -1;
	}

	// Add new protocols here
	if (p_id->flow.proto == IPPROTO_TCP) {
		err = parse_tcp_identifier(ctx, &saddr->port, &daddr->port,
					   flow_closing, &p_id->identifier);
		if (err)
			return -1;
	} else {
		return -1;
	}

	// Sucessfully parsed packet identifier - fill in IP-addresses and return
	if (p_id->flow.ipv == AF_INET) {
		map_ipv4_to_ipv6(iph->saddr, &saddr->ip);
		map_ipv4_to_ipv6(iph->daddr, &daddr->ip);
	} else { // IPv6
		saddr->ip = ip6h->saddr;
		daddr->ip = ip6h->daddr;
	}
	return 0;
}

// Programs

// TC-BFP for parsing packet identifier from egress traffic and add to map
SEC(EGRESS_PROG_SEC)
int pping_egress(struct __sk_buff *skb)
{
	struct packet_id p_id = { 0 };
	__u64 p_ts;
	struct parsing_context pctx = {
		.data = (void *)(long)skb->data,
		.data_end = (void *)(long)skb->data_end,
		.pkt_len = skb->len,
		.nh = { .pos = pctx.data },
		.is_egress = true,
	};
	bool flow_closing = false;
	struct flow_state *f_state;
	struct flow_state new_state = { 0 };

	if (parse_packet_identifier(&pctx, &p_id, &flow_closing) < 0)
		goto out;

	// Delete flow and create no timestamp entry if flow is closing
	if (flow_closing) {
		bpf_map_delete_elem(&flow_state, &p_id.flow);
		goto out;
	}

	// Check flow state
	f_state = bpf_map_lookup_elem(&flow_state, &p_id.flow);
	if (!f_state) { // No previous state - attempt to create it
		bpf_map_update_elem(&flow_state, &p_id.flow, &new_state,
				    BPF_NOEXIST);
		f_state = bpf_map_lookup_elem(&flow_state, &p_id.flow);
		if (!f_state)
			goto out;
	}

	// Check if identfier is new
	if (f_state->last_id == p_id.identifier)
		goto out;
	f_state->last_id = p_id.identifier;

	// Check rate-limit
	p_ts = bpf_ktime_get_ns(); // or bpf_ktime_get_boot_ns
	if (p_ts < f_state->last_timestamp ||
	    p_ts - f_state->last_timestamp < config.rate_limit)
		goto out;

	/*
	 * Updates attempt at creating timestamp, even if creation of timestamp
	 * fails (due to map being full). This should make the competition for
	 * the next available map slot somewhat fairer between heavy and sparse
	 * flows.
	 */
	f_state->last_timestamp = p_ts;
	bpf_map_update_elem(&packet_ts, &p_id, &p_ts, BPF_NOEXIST);

out:
	return BPF_OK;
}

// XDP program for parsing identifier in ingress traffic and check for match in map
SEC(INGRESS_PROG_SEC)
int pping_ingress(struct xdp_md *ctx)
{
	struct packet_id p_id = { 0 };
	__u64 *p_ts;
	struct rtt_event event = { 0 };
	struct flow_state *f_state;
	struct parsing_context pctx = {
		.data = (void *)(long)ctx->data,
		.data_end = (void *)(long)ctx->data_end,
		.pkt_len = pctx.data_end - pctx.data,
		.nh = { .pos = pctx.data },
		.is_egress = false,
	};
	bool flow_closing = false;
	__u64 now;

	if (parse_packet_identifier(&pctx, &p_id, &flow_closing) < 0)
		goto out;

	now = bpf_ktime_get_ns();
	p_ts = bpf_map_lookup_elem(&packet_ts, &p_id);
	if (!p_ts || now < *p_ts)
		goto validflow_out;

	event.rtt = now - *p_ts;
	event.timestamp = now;

	// Delete timestamp entry as soon as RTT is calculated
	bpf_map_delete_elem(&packet_ts, &p_id);

	// Update flow's min-RTT
	f_state = bpf_map_lookup_elem(&flow_state, &p_id.flow);
	if (!f_state)
		goto validflow_out;

	if (f_state->min_rtt == 0 || event.rtt < f_state->min_rtt)
		f_state->min_rtt = event.rtt;

	event.min_rtt = f_state->min_rtt;

	// Push event to perf-buffer
	__builtin_memcpy(&event.flow, &p_id.flow, sizeof(struct network_tuple));
	bpf_perf_event_output(ctx, &rtt_events, BPF_F_CURRENT_CPU, &event,
			      sizeof(event));

validflow_out:
	// Wait with deleting flow until having pushed final RTT message
	if (flow_closing)
		bpf_map_delete_elem(&flow_state, &p_id.flow);

out:
	return XDP_PASS;
}
