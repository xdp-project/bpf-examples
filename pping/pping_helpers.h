/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef PPING_HELPERS_H
#define PPING_HELPERS_H

#include <linux/bpf.h>
#include <xdp/parsing_helpers.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>

#include <stdbool.h>
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
	void *data;           //Start of eth hdr
	void *data_end;       //End of safe acessible area
	struct hdr_cursor nh; //Position to parse next
	__u32 pkt_len;        //Full packet length (headers+data)
	bool is_egress;       //Is packet on egress or ingress?
};

// Timestamp map
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct packet_id);
	__type(value, __u64);
	__uint(max_entries, 16384);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} ts_start SEC(".maps");

// Flow state map
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct network_tuple);
	__type(value, struct flow_state);
	__uint(max_entries, 16384);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} flow_state SEC(".maps");

/*
 * Maps an IPv4 address into an IPv6 address according to RFC 4291 sec 2.5.5.2
 */
static void map_ipv4_to_ipv6(__be32 ipv4, struct in6_addr *ipv6)
{
	__u16 ipv4_prefix[] = { 0x0, 0x0, 0x0, 0x0, 0x0, 0xffff };
	__builtin_memcpy(ipv6, ipv4_prefix, sizeof(ipv4_prefix));
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
	__u8 i, opt, opt_size;

	if (tcph + 1 > data_end || len <= sizeof(struct tcphdr))
		return -1;

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

		// Option-kind is TCP timestap (yey!)
		if (opt == 8 && opt_size == 10) {
			if (pos + opt_size > opt_end ||
			    pos + opt_size > data_end)
				return -1;
			*tsval = *(__u32 *)(pos + 2);
			*tsecr = *(__u32 *)(pos + 6);
			return 0;
		}

		// Some other TCP option - advance option-length bytes
		if (opt_size < 0 || opt_size > 34) // Try to convince verifier that opt-size can't be something crazy - leads to program being too large instead...
			return -1;
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
	if (tcph->fin || tcph->rst) {
		*flow_closing = true;
		/* bpf_printk("Detected connection closing on %d\n", */
		/* 	   ctx->is_egress); //Upsets verifier? */
	}

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
		proto = parse_iphdr(&ctx->nh, ctx->data_end, &iph);
	} else if (proto == bpf_htons(ETH_P_IPV6)) {
		p_id->flow.ipv = AF_INET6;
		proto = parse_ip6hdr(&ctx->nh, ctx->data_end, &ip6h);
	} else {
		return -1;
	}

	// Add new protocols here
	if (proto == IPPROTO_TCP) {
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

#endif
