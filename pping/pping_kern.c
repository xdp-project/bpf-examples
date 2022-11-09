/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/pkt_cls.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>
#include <stdbool.h>

// overwrite xdp/parsing_helpers.h value to avoid hitting verifier limit
#ifdef IPV6_EXT_MAX_CHAIN
#undef IPV6_EXT_MAX_CHAIN
#endif
#define IPV6_EXT_MAX_CHAIN 3

#include <xdp/parsing_helpers.h>
#include "pping.h"
#include "pping_debug_cleanup.h"

#ifndef AF_INET
#define AF_INET 2
#endif
#ifndef AF_INET6
#define AF_INET6 10
#endif
#define MAX_TCP_OPTIONS 10

// Mask for IPv6 flowlabel + traffic class -  used in fib lookup
#define IPV6_FLOWINFO_MASK __cpu_to_be32(0x0FFFFFFF)

// Emit a warning max once per second when failing to add entry to map
#define WARN_MAP_FULL_INTERVAL 1000000000UL

// Time before map entry is considered old and can safetly be removed
#define TIMESTAMP_LIFETIME (10 * NS_PER_SECOND) // Clear any timestamp older than this
#define TIMESTAMP_RTT_LIFETIME 8 // Clear timestamp once it is this many times older than RTT
#define FLOW_LIFETIME (300 * NS_PER_SECOND) // Clear any flow that's been inactive this long
#define ICMP_FLOW_LIFETIME (30 * NS_PER_SECOND) // Clear any ICMP flows if they're inactive this long
#define UNOPENED_FLOW_LIFETIME (30 * NS_PER_SECOND) // Clear out flows that have not seen a response after this long

#define MAX_MEMCMP_SIZE 128

/*
 * Structs for map iteration programs
 * Copied from /tools/testing/selftest/bpf/progs/bpf_iter.h
 */
struct bpf_iter_meta {
	struct seq_file *seq;
	__u64 session_id;
	__u64 seq_num;
} __attribute__((preserve_access_index));

struct bpf_iter__bpf_map_elem {
	struct bpf_iter_meta *meta;
	struct bpf_map *map;
	void *key;
	void *value;
};

/*
 * This struct keeps track of the data and data_end pointers from the xdp_md or
 * __skb_buff contexts, as well as a currently parsed to position kept in nh.
 * Additionally, it also keeps the length of the entire packet, which together
 * with the other members can be used to determine ex. how much data each
 * header encloses.
 */
struct parsing_context {
	void *data;            // Start of eth hdr
	void *data_end;        // End of safe acessible area
	struct hdr_cursor nh;  // Position to parse next
	__u32 pkt_len;         // Full packet length (headers+data)
};

/*
 * Struct filled in by parse_packet_id.
 *
 * Note: As long as parse_packet_id is successful, the flow-parts of pid
 * and reply_pid should be valid, regardless of value for pid_valid and
 * reply_pid valid. The *pid_valid members are there to indicate that the
 * identifier part of *pid are valid and can be used for timestamping/lookup.
 * The reason for not keeping the flow parts as an entirely separate members
 * is to save some performance by avoid doing a copy for lookup/insertion
 * in the packet_ts map.
 */
struct packet_info {
	__u64 time;                  // Arrival time of packet
	__u32 payload;               // Size of packet data (excluding headers)
	struct packet_id pid;        // flow + identifier to timestamp (ex. TSval)
	struct packet_id reply_pid;  // rev. flow + identifier to match against (ex. TSecr)
	__u32 ingress_ifindex;       // Interface packet arrived on (if is_ingress, otherwise not valid)
	union {                      // The IP-level "type of service" (DSCP for IPv4, traffic class + flow label for IPv6)
		__u8 ipv4_tos;
		__be32 ipv6_tos;
	} ip_tos;
	__u16 ip_len;                // The IPv4 total length or IPv6 payload length
	bool is_ingress;             // Packet on egress or ingress?
	bool pid_flow_is_dfkey;      // Used to determine which member of dualflow state to use for forward direction
	bool pid_valid;              // identifier can be used to timestamp packet
	bool reply_pid_valid;        // reply_identifier can be used to match packet
	enum flow_event_type event_type; // flow event triggered by packet
	enum flow_event_reason event_reason; // reason for triggering flow event
	bool wait_first_edge;        // Do we need to wait for the first identifier change before timestamping?
};

/*
 * Struct filled in by protocol id parsers (ex. parse_tcp_identifier)
 */
struct protocol_info {
	__u32 pid;
	__u32 reply_pid;
	bool pid_valid;
	bool reply_pid_valid;
	enum flow_event_type event_type;
	enum flow_event_reason event_reason;
	bool wait_first_edge;
};

char _license[] SEC("license") = "GPL";
// Global config struct - set from userspace
static volatile const struct bpf_config config = {};
static volatile __u64 last_warn_time[2] = { 0 };


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
	__type(value, struct dual_flow_state);
	__uint(max_entries, 16384);
} flow_state SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u32));
} events SEC(".maps");


// Help functions

/*
 * Maps an IPv4 address into an IPv6 address according to RFC 4291 sec 2.5.5.2
 */
static void map_ipv4_to_ipv6(struct in6_addr *ipv6, __be32 ipv4)
{
	__builtin_memset(&ipv6->in6_u.u6_addr8[0], 0x00, 10);
	__builtin_memset(&ipv6->in6_u.u6_addr8[10], 0xff, 2);
	ipv6->in6_u.u6_addr32[3] = ipv4;
}

static __be32 ipv4_from_ipv6(struct in6_addr *ipv6)
{
	return ipv6->in6_u.u6_addr32[3];
}

/*
 * Returns the number of unparsed bytes left in the packet (bytes after nh.pos)
 */
static __u32 remaining_pkt_payload(struct parsing_context *ctx)
{
	// pkt_len - (pos - data) fails because compiler transforms it to pkt_len - pos + data (pkt_len - pos not ok because value - pointer)
	// data + pkt_len - pos fails on (data+pkt_len) - pos due to math between pkt_pointer and unbounded register
	__u32 parsed_bytes = ctx->nh.pos - ctx->data;
	return parsed_bytes < ctx->pkt_len ? ctx->pkt_len - parsed_bytes : 0;
}

/*
 * Convenience function for getting the corresponding reverse flow.
 * PPing needs to keep track of flow in both directions, and sometimes
 * also needs to reverse the flow to report the "correct" (consistent
 * with Kathie's PPing) src and dest address.
 */
static void reverse_flow(struct network_tuple *dest, struct network_tuple *src)
{
	dest->ipv = src->ipv;
	dest->proto = src->proto;
	dest->saddr = src->daddr;
	dest->daddr = src->saddr;
	dest->reserved = 0;
}

/*
 * Can't seem to get __builtin_memcmp to work, so hacking my own
 *
 * Based on https://githubhot.com/repo/iovisor/bcc/issues/3559,
 * __builtin_memcmp should work constant size but I still get the "failed to
 * find BTF for extern" error.
 */
static int my_memcmp(const void *s1_, const void *s2_, __u32 size)
{
	const __u8 *s1 = s1_, *s2 = s2_;
	int i;

	for (i = 0; i < MAX_MEMCMP_SIZE && i < size; i++) {
		if (s1[i] != s2[i])
			return s1[i] > s2[i] ? 1 : -1;
	}

	return 0;
}

static bool is_dualflow_key(struct network_tuple *flow)
{
	return my_memcmp(&flow->saddr, &flow->daddr, sizeof(flow->saddr)) <= 0;
}

static void make_dualflow_key(struct network_tuple *key,
			      struct network_tuple *flow)
{
	if (is_dualflow_key(flow))
		*key = *flow;
	else
		reverse_flow(key, flow);
}

static struct flow_state *fstate_from_dfkey(struct dual_flow_state *df_state,
					    bool is_dfkey)
{
	return is_dfkey ? &df_state->dir1 : &df_state->dir2;
}

/*
 * Get the flow state for flow-direction from df_state
 *
 * Note: Does not validate that any of the entries in df_state actually matches
 * flow, just selects the direction in df_state that best fits the flow.
 */
static struct flow_state *
get_flowstate_from_dualflow(struct dual_flow_state *df_state,
			    struct network_tuple *flow)
{
	return fstate_from_dfkey(df_state, is_dualflow_key(flow));
}

static struct flow_state *
get_flowstate_from_packet(struct dual_flow_state *df_state,
			  struct packet_info *p_info)
{
	return fstate_from_dfkey(df_state, p_info->pid_flow_is_dfkey);
}

static struct flow_state *
get_reverse_flowstate_from_packet(struct dual_flow_state *df_state,
				  struct packet_info *p_info)
{
	return fstate_from_dfkey(df_state, !p_info->pid_flow_is_dfkey);
}

static struct network_tuple *
get_dualflow_key_from_packet(struct packet_info *p_info)
{
	return p_info->pid_flow_is_dfkey ? &p_info->pid.flow :
						 &p_info->reply_pid.flow;
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
			*tsval = bpf_ntohl(*(__u32 *)(pos + 2));
			*tsecr = bpf_ntohl(*(__u32 *)(pos + 6));
			return 0;
		}

		// Some other TCP option - advance option-length bytes
		pos += opt_size;
	}
	return -1;
}

/*
 * Attempts to fetch an identifier for TCP packets, based on the TCP timestamp
 * option.
 *
 * Will use the TSval as pid and TSecr as reply_pid, and the TCP source and dest
 * as port numbers.
 *
 * If successful, tcph, sport, dport and proto_info will be set
 * appropriately and 0 will be returned.
 * On failure -1 will be returned (and arguments will not be set).
 */
static int parse_tcp_identifier(struct parsing_context *pctx,
				struct tcphdr **tcph, __u16 *sport,
				__u16 *dport, struct protocol_info *proto_info)
{
	struct tcphdr *hdr;
	if (parse_tcphdr(&pctx->nh, pctx->data_end, &hdr) < 0)
		return -1;

	if (config.skip_syn && hdr->syn)
		return -1;

	if (parse_tcp_ts(hdr, pctx->data_end, &proto_info->pid,
			 &proto_info->reply_pid) < 0)
		return -1; //Possible TODO, fall back on seq/ack instead

	// Do not timestamp pure ACKs (no payload)
	proto_info->pid_valid =
		pctx->nh.pos - pctx->data < pctx->pkt_len || hdr->syn;

	// Do not match on non-ACKs (TSecr not valid)
	proto_info->reply_pid_valid = hdr->ack;

	// Check if connection is opening/closing
	if (hdr->rst) {
		proto_info->event_type = FLOW_EVENT_CLOSING_BOTH;
		proto_info->event_reason = EVENT_REASON_RST;
	} else if (hdr->fin) {
		proto_info->event_type = FLOW_EVENT_CLOSING;
		proto_info->event_reason = EVENT_REASON_FIN;
	} else if (hdr->syn) {
		proto_info->event_type = FLOW_EVENT_OPENING;
		proto_info->event_reason =
			hdr->ack ? EVENT_REASON_SYN_ACK : EVENT_REASON_SYN;
		proto_info->wait_first_edge = false;
	} else {
		proto_info->event_type = FLOW_EVENT_NONE;
		proto_info->event_reason = EVENT_REASON_NONE;
		proto_info->wait_first_edge = true;
	}

	*sport = hdr->source;
	*dport = hdr->dest;
	*tcph = hdr;

	return 0;
}

/*
 * Attempts to fetch an identifier for an ICMPv6 header, based on the echo
 * request/reply sequence number.
 *
 * Will use the echo sequence number as pid/reply_pid and the echo identifier
 * as both src and dst port numbers. Echo requests will only generate a valid
 * pid and echo replies will only generate a valid reply_pid.
 *
 * If successful, icmp6h, sport, dport and proto_info will be set appropriately
 * and 0 will be returned.
 * On failure, -1 will be returned (and arguments will not be set).
 *
 * Note: Will store the 16-bit sequence number in network byte order
 * in the 32-bit proto_info->(reply_)pid.
 */
static int parse_icmp6_identifier(struct parsing_context *pctx,
				  struct icmp6hdr **icmp6h, __u16 *sport,
				  __u16 *dport,
				  struct protocol_info *proto_info)
{
	struct icmp6hdr *hdr;
	if (parse_icmp6hdr(&pctx->nh, pctx->data_end, &hdr) < 0)
		return -1;

	if (hdr->icmp6_code != 0)
		return -1;

	if (hdr->icmp6_type == ICMPV6_ECHO_REQUEST) {
		proto_info->pid = hdr->icmp6_sequence;
		proto_info->pid_valid = true;
		proto_info->reply_pid = 0;
		proto_info->reply_pid_valid = false;
	} else if (hdr->icmp6_type == ICMPV6_ECHO_REPLY) {
		proto_info->reply_pid = hdr->icmp6_sequence;
		proto_info->reply_pid_valid = true;
		proto_info->pid = 0;
		proto_info->pid_valid = false;
	} else {
		return -1;
	}

	proto_info->event_type = FLOW_EVENT_NONE;
	proto_info->event_reason = EVENT_REASON_NONE;
	proto_info->wait_first_edge = false;
	*sport = hdr->icmp6_identifier;
	*dport = hdr->icmp6_identifier;
	*icmp6h = hdr;

	return 0;
}

/*
 * Same as parse_icmp6_identifier, but for an ICMP(v4) header instead.
 */
static int parse_icmp_identifier(struct parsing_context *pctx,
				 struct icmphdr **icmph, __u16 *sport,
				 __u16 *dport, struct protocol_info *proto_info)
{
	struct icmphdr *hdr;
	if (parse_icmphdr(&pctx->nh, pctx->data_end, &hdr) < 0)
		return -1;

	if (hdr->code != 0)
		return -1;

	if (hdr->type == ICMP_ECHO) {
		proto_info->pid = hdr->un.echo.sequence;
		proto_info->pid_valid = true;
		proto_info->reply_pid = 0;
		proto_info->reply_pid_valid = false;
	} else if (hdr->type == ICMP_ECHOREPLY) {
		proto_info->reply_pid = hdr->un.echo.sequence;
		proto_info->reply_pid_valid = true;
		proto_info->pid = 0;
		proto_info->pid_valid = false;
	} else {
		return -1;
	}

	proto_info->event_type = FLOW_EVENT_NONE;
	proto_info->event_reason = EVENT_REASON_NONE;
	proto_info->wait_first_edge = false;
	*sport = hdr->un.echo.id;
	*dport = hdr->un.echo.id;
	*icmph = hdr;

	return 0;
}

/*
 * Attempts to parse the packet defined by pctx for a valid packet identifier
 * and reply identifier, filling in p_info.
 *
 * If succesful, all members of p_info will be set appropriately and 0 will
 * be returned.
 * On failure -1 will be returned (no garantuees on p_info members).
 */
static int parse_packet_identifier(struct parsing_context *pctx,
				   struct packet_info *p_info)
{
	int proto, err;
	struct ethhdr *eth;
	struct protocol_info proto_info;
	union {
		struct iphdr *iph;
		struct ipv6hdr *ip6h;
	} iph_ptr;
	union {
		struct tcphdr *tcph;
		struct icmphdr *icmph;
		struct icmp6hdr *icmp6h;
	} transporth_ptr;

	p_info->time = bpf_ktime_get_ns();
	proto = parse_ethhdr(&pctx->nh, pctx->data_end, &eth);

	// Parse IPv4/6 header
	if (proto == bpf_htons(ETH_P_IP)) {
		p_info->pid.flow.ipv = AF_INET;
		p_info->pid.flow.proto =
			parse_iphdr(&pctx->nh, pctx->data_end, &iph_ptr.iph);
	} else if (proto == bpf_htons(ETH_P_IPV6)) {
		p_info->pid.flow.ipv = AF_INET6;
		p_info->pid.flow.proto =
			parse_ip6hdr(&pctx->nh, pctx->data_end, &iph_ptr.ip6h);
	} else {
		return -1;
	}

	// Parse identifer from suitable protocol
	if (config.track_tcp && p_info->pid.flow.proto == IPPROTO_TCP)
		err = parse_tcp_identifier(pctx, &transporth_ptr.tcph,
					   &p_info->pid.flow.saddr.port,
					   &p_info->pid.flow.daddr.port,
					   &proto_info);
	else if (config.track_icmp &&
		 p_info->pid.flow.proto == IPPROTO_ICMPV6 &&
		 p_info->pid.flow.ipv == AF_INET6)
		err = parse_icmp6_identifier(pctx, &transporth_ptr.icmp6h,
					     &p_info->pid.flow.saddr.port,
					     &p_info->pid.flow.daddr.port,
					     &proto_info);
	else if (config.track_icmp && p_info->pid.flow.proto == IPPROTO_ICMP &&
		 p_info->pid.flow.ipv == AF_INET)
		err = parse_icmp_identifier(pctx, &transporth_ptr.icmph,
					    &p_info->pid.flow.saddr.port,
					    &p_info->pid.flow.daddr.port,
					    &proto_info);
	else
		return -1; // No matching protocol
	if (err)
		return -1; // Failed parsing protocol

	// Sucessfully parsed packet identifier - fill in remaining members and return
	p_info->pid.identifier = proto_info.pid;
	p_info->pid_valid = proto_info.pid_valid;
	p_info->reply_pid.identifier = proto_info.reply_pid;
	p_info->reply_pid_valid = proto_info.reply_pid_valid;
	p_info->event_type = proto_info.event_type;
	p_info->event_reason = proto_info.event_reason;
	p_info->wait_first_edge = proto_info.wait_first_edge;

	if (p_info->pid.flow.ipv == AF_INET) {
		map_ipv4_to_ipv6(&p_info->pid.flow.saddr.ip,
				 iph_ptr.iph->saddr);
		map_ipv4_to_ipv6(&p_info->pid.flow.daddr.ip,
				 iph_ptr.iph->daddr);
		p_info->ip_len = bpf_ntohs(iph_ptr.iph->tot_len);
		p_info->ip_tos.ipv4_tos = iph_ptr.iph->tos;
	} else { // IPv6
		p_info->pid.flow.saddr.ip = iph_ptr.ip6h->saddr;
		p_info->pid.flow.daddr.ip = iph_ptr.ip6h->daddr;
		p_info->ip_len = bpf_ntohs(iph_ptr.ip6h->payload_len);
		p_info->ip_tos.ipv6_tos =
			*(__be32 *)iph_ptr.ip6h & IPV6_FLOWINFO_MASK;
	}

	p_info->pid_flow_is_dfkey = is_dualflow_key(&p_info->pid.flow);

	reverse_flow(&p_info->reply_pid.flow, &p_info->pid.flow);
	p_info->payload = remaining_pkt_payload(pctx);

	return 0;
}

/*
 * Global versions of parse_packet_identifer that should allow for
 * function-by-function verification, and reduce the overall complexity.
 * Need separate versions for tc and XDP so that verifier understands that the
 * first argument is PTR_TO_CTX, and therefore their data and data_end pointers
 * are valid packet pointers.
 */
__noinline int parse_packet_identifer_tc(struct __sk_buff *ctx,
					 struct packet_info *p_info)
{
	if (!p_info)
		return -1;

	struct parsing_context pctx = {
		.data = (void *)(long)ctx->data,
		.data_end = (void *)(long)ctx->data_end,
		.nh = { .pos = pctx.data },
		.pkt_len = ctx->len,
	};

	return parse_packet_identifier(&pctx, p_info);
}

__noinline int parse_packet_identifer_xdp(struct xdp_md *ctx,
					  struct packet_info *p_info)
{
	if (!p_info)
		return -1;

	struct parsing_context pctx = {
		.data = (void *)(long)ctx->data,
		.data_end = (void *)(long)ctx->data_end,
		.nh = { .pos = pctx.data },
		.pkt_len = pctx.data_end - pctx.data,
	};

	return parse_packet_identifier(&pctx, p_info);
}

/*
 * Calculate a smoothed rtt similar to how TCP stack does it in
 * net/ipv4/tcp_input.c/tcp_rtt_estimator().
 *
 * NOTE: Will cause roundoff errors, but if RTTs > 1000ns errors should be small
 */
static __u64 calculate_srtt(__u64 prev_srtt, __u64 rtt)
{
	if (!prev_srtt)
		return rtt;
	// srtt = 7/8*prev_srtt + 1/8*rtt
	return prev_srtt - (prev_srtt >> 3) + (rtt >> 3);
}

static bool is_rate_limited(__u64 now, __u64 last_ts, __u64 rtt)
{
	if (now < last_ts)
		return true;

	// RTT-based rate limit
	if (config.rtt_rate && rtt)
		return now - last_ts < FIXPOINT_TO_UINT(config.rtt_rate * rtt);

	// Static rate limit
	return now - last_ts < config.rate_limit;
}

/*
 * Send a flow opening event through the perf-buffer.
 * As these events are only sent upon receiving a reply, need to access state
 * of the reverse flow to get reason flow was opened and when the original
 * packet opening the flow was sent.
 */
static void send_flow_open_event(void *ctx, struct packet_info *p_info,
				 struct flow_state *rev_flow)
{
	struct flow_event fe = {
		.event_type = EVENT_TYPE_FLOW,
		.flow_event_type = FLOW_EVENT_OPENING,
		.source = EVENT_SOURCE_PKT_DEST,
		.flow = p_info->pid.flow,
		.reason = rev_flow->opening_reason,
		.timestamp = rev_flow->last_timestamp,
		.reserved = 0,
	};

	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &fe, sizeof(fe));
}

/*
 * Sends a flow-event message based on p_info.
 *
 * The rev_flow argument is used to inform if the message is for the flow
 * in the current direction or the reverse flow, and will adapt the flow and
 * source members accordingly.
 */
static void send_flow_event(void *ctx, struct packet_info *p_info,
			    bool rev_flow)
{
	struct flow_event fe = {
		.event_type = EVENT_TYPE_FLOW,
		.flow_event_type = p_info->event_type,
		.reason = p_info->event_reason,
		.timestamp = p_info->time,
		.reserved = 0, // Make sure it's initilized
	};

	if (rev_flow) {
		fe.flow = p_info->pid.flow;
		fe.source = EVENT_SOURCE_PKT_SRC;
	} else {
		fe.flow = p_info->reply_pid.flow;
		fe.source = EVENT_SOURCE_PKT_DEST;
	}

	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &fe, sizeof(fe));
}

/*
 * Send a map-full event for the map.
 * Will only trigger once every WARN_MAP_FULL_INTERVAL
 */
static void send_map_full_event(void *ctx, struct packet_info *p_info,
				enum pping_map map)
{
	struct map_full_event me;

	if (p_info->time < last_warn_time[map] ||
	    p_info->time - last_warn_time[map] < WARN_MAP_FULL_INTERVAL)
		return;

	last_warn_time[map] = p_info->time;

	__builtin_memset(&me, 0, sizeof(me));
	me.event_type = EVENT_TYPE_MAP_FULL;
	me.timestamp = p_info->time;
	me.flow = p_info->pid.flow;
	me.map = map;

	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &me, sizeof(me));
}

/*
 * Initilizes an "empty" flow state based on the forward direction of the
 * current packet
 */
static void init_flowstate(struct flow_state *f_state,
			   struct packet_info *p_info)
{
	f_state->conn_state = CONNECTION_STATE_WAITOPEN;
	f_state->last_timestamp = p_info->time;
	/* We should only ever create new flows for packet with valid pid,
	   so assume pid is valid*/
	f_state->last_id = p_info->pid.identifier;
	f_state->opening_reason = p_info->event_type == FLOW_EVENT_OPENING ?
					  p_info->event_reason :
						EVENT_REASON_FIRST_OBS_PCKT;
	f_state->has_been_timestamped = false;
}

static void init_empty_flowstate(struct flow_state *f_state)
{
	f_state->conn_state = CONNECTION_STATE_EMPTY;
	f_state->has_been_timestamped = false;
}

/*
 * Initilize a new (assumed 0-initlized) dual flow state based on the current
 * packet.
 */
static void init_dualflow_state(struct dual_flow_state *df_state,
				struct packet_info *p_info)
{
	struct flow_state *fw_state =
		get_flowstate_from_packet(df_state, p_info);
	struct flow_state *rev_state =
		get_reverse_flowstate_from_packet(df_state, p_info);

	init_flowstate(fw_state, p_info);
	init_empty_flowstate(rev_state);
}

static struct dual_flow_state *
create_dualflow_state(void *ctx, struct packet_info *p_info)
{
	struct network_tuple *key = get_dualflow_key_from_packet(p_info);
	struct dual_flow_state new_state = { 0 };

	init_dualflow_state(&new_state, p_info);

	if (bpf_map_update_elem(&flow_state, key, &new_state, BPF_NOEXIST) !=
	    0) {
		send_map_full_event(ctx, p_info, PPING_MAP_FLOWSTATE);
		return NULL;
	}

	return bpf_map_lookup_elem(&flow_state, key);
}

static struct dual_flow_state *
lookup_or_create_dualflow_state(void *ctx, struct packet_info *p_info)
{
	struct dual_flow_state *df_state;

	df_state = bpf_map_lookup_elem(&flow_state,
				       get_dualflow_key_from_packet(p_info));

	if (df_state)
		return df_state;

	// Only try to create new state if we have a valid pid
	if (!p_info->pid_valid || p_info->event_type == FLOW_EVENT_CLOSING ||
	    p_info->event_type == FLOW_EVENT_CLOSING_BOTH)
		return NULL;

	return create_dualflow_state(ctx, p_info);
}

static bool is_flowstate_active(struct flow_state *f_state)
{
	return f_state->conn_state != CONNECTION_STATE_EMPTY &&
	       f_state->conn_state != CONNECTION_STATE_CLOSED;
}

static void update_forward_flowstate(struct packet_info *p_info,
				     struct flow_state *f_state)
{
	// "Create" flowstate if it's empty
	if (f_state->conn_state == CONNECTION_STATE_EMPTY && p_info->pid_valid)
		init_flowstate(f_state, p_info);

	if (is_flowstate_active(f_state)) {
		f_state->sent_pkts++;
		f_state->sent_bytes += p_info->payload;
	}
}

static void update_reverse_flowstate(void *ctx, struct packet_info *p_info,
				     struct flow_state *f_state)
{
	if (!is_flowstate_active(f_state))
		return;

	// First time we see reply for flow?
	if (f_state->conn_state == CONNECTION_STATE_WAITOPEN &&
	    p_info->event_type != FLOW_EVENT_CLOSING_BOTH) {
		f_state->conn_state = CONNECTION_STATE_OPEN;
		send_flow_open_event(ctx, p_info, f_state);
	}

	f_state->rec_pkts++;
	f_state->rec_bytes += p_info->payload;
}

static bool should_notify_closing(struct flow_state *f_state)
{
	return f_state->conn_state == CONNECTION_STATE_OPEN;
}

static void close_and_delete_flows(void *ctx, struct packet_info *p_info,
				   struct flow_state *fw_flow,
				   struct flow_state *rev_flow)
{
	// Forward flow closing
	if (p_info->event_type == FLOW_EVENT_CLOSING ||
	    p_info->event_type == FLOW_EVENT_CLOSING_BOTH) {
		if (should_notify_closing(fw_flow))
			send_flow_event(ctx, p_info, false);
		fw_flow->conn_state = CONNECTION_STATE_CLOSED;
	}

	// Reverse flow closing
	if (p_info->event_type == FLOW_EVENT_CLOSING_BOTH) {
		if (should_notify_closing(rev_flow))
			send_flow_event(ctx, p_info, true);
		rev_flow->conn_state = CONNECTION_STATE_CLOSED;
	}

	// Delete flowstate entry if neither flow is open anymore
	if (!is_flowstate_active(fw_flow) && !is_flowstate_active(rev_flow)) {
		if (bpf_map_delete_elem(&flow_state,
					get_dualflow_key_from_packet(p_info)) ==
		    0)
			debug_increment_autodel(PPING_MAP_FLOWSTATE);
	}
}

/*
 * Return true if p_info->pid.flow.daddr is a "local" address.
 *
 * Works by performing a fib lookup for p_info->pid.flow.
 * Lookup struct filled based on examples from
 * samples/bpf/xdp_fwd_kern.c/xdp_fwd_flags() and
 * tools/testing/selftests/bpf/progs/test_tc_neigh_fib.c
 */
static bool is_local_address(struct packet_info *p_info, void *ctx)
{
	int ret;
	struct bpf_fib_lookup lookup;
	__builtin_memset(&lookup, 0, sizeof(lookup));

	lookup.ifindex = p_info->ingress_ifindex;
	lookup.family = p_info->pid.flow.ipv;
	lookup.tot_len = p_info->ip_len;

	if (lookup.family == AF_INET) {
		lookup.tos = p_info->ip_tos.ipv4_tos;
		lookup.ipv4_src = ipv4_from_ipv6(&p_info->pid.flow.saddr.ip);
		lookup.ipv4_dst = ipv4_from_ipv6(&p_info->pid.flow.daddr.ip);
	} else if (lookup.family == AF_INET6) {
		struct in6_addr *src = (struct in6_addr *)lookup.ipv6_src;
		struct in6_addr *dst = (struct in6_addr *)lookup.ipv6_dst;

		lookup.flowinfo = p_info->ip_tos.ipv6_tos;
		*src = p_info->pid.flow.saddr.ip;
		*dst = p_info->pid.flow.daddr.ip;
	}

	lookup.l4_protocol = p_info->pid.flow.proto;
	lookup.sport = 0;
	lookup.dport = 0;

	ret = bpf_fib_lookup(ctx, &lookup, sizeof(lookup), 0);

	return ret == BPF_FIB_LKUP_RET_NOT_FWDED ||
	       ret == BPF_FIB_LKUP_RET_FWD_DISABLED;
}

static bool is_new_identifier(struct packet_id *pid, struct flow_state *f_state)
{
	if (pid->flow.proto == IPPROTO_TCP)
		/* TCP timestamps should be monotonically non-decreasing
		 * Check that pid > last_ts (considering wrap around) by
		 * checking 0 < pid - last_ts < 2^31 as specified by
		 * RFC7323 Section 5.2*/
		return pid->identifier - f_state->last_id > 0 &&
		       pid->identifier - f_state->last_id < 1UL << 31;

	return pid->identifier != f_state->last_id;
}

/*
 * Attempt to create a timestamp-entry for packet p_info for flow in f_state
 */
static void pping_timestamp_packet(struct flow_state *f_state, void *ctx,
				   struct packet_info *p_info)
{
	if (!is_flowstate_active(f_state) || !p_info->pid_valid)
		return;

	if (config.localfilt && p_info->is_ingress &&
	    is_local_address(p_info, ctx))
		return;

	// Check if identfier is new
	if ((f_state->has_been_timestamped || p_info->wait_first_edge) &&
	    !is_new_identifier(&p_info->pid, f_state))
		return;
	f_state->last_id = p_info->pid.identifier;

	// Check rate-limit
	if (f_state->has_been_timestamped &&
	    is_rate_limited(p_info->time, f_state->last_timestamp,
			    config.use_srtt ? f_state->srtt : f_state->min_rtt))
		return;

	/*
	 * Updates attempt at creating timestamp, even if creation of timestamp
	 * fails (due to map being full). This should make the competition for
	 * the next available map slot somewhat fairer between heavy and sparse
	 * flows.
	 */
	f_state->has_been_timestamped = true;
	f_state->last_timestamp = p_info->time;

	if (bpf_map_update_elem(&packet_ts, &p_info->pid, &p_info->time,
				BPF_NOEXIST) == 0)
		__sync_fetch_and_add(&f_state->outstanding_timestamps, 1);
	else
		send_map_full_event(ctx, p_info, PPING_MAP_PACKETTS);
}

/*
 * Attempt to match packet in p_info with a timestamp from flow in f_state
 */
static void pping_match_packet(struct flow_state *f_state, void *ctx,
			       struct packet_info *p_info)
{
	struct rtt_event re = { 0 };
	__u64 *p_ts;

	if (!is_flowstate_active(f_state) || !p_info->reply_pid_valid)
		return;

	if (f_state->outstanding_timestamps == 0)
		return;

	p_ts = bpf_map_lookup_elem(&packet_ts, &p_info->reply_pid);
	if (!p_ts || p_info->time < *p_ts)
		return;

	re.rtt = p_info->time - *p_ts;

	// Delete timestamp entry as soon as RTT is calculated
	if (bpf_map_delete_elem(&packet_ts, &p_info->reply_pid) == 0) {
		__sync_fetch_and_add(&f_state->outstanding_timestamps, -1);
		debug_increment_autodel(PPING_MAP_PACKETTS);
	}

	if (f_state->min_rtt == 0 || re.rtt < f_state->min_rtt)
		f_state->min_rtt = re.rtt;
	f_state->srtt = calculate_srtt(f_state->srtt, re.rtt);

	// Fill event and push to perf-buffer
	re.event_type = EVENT_TYPE_RTT;
	re.timestamp = p_info->time;
	re.min_rtt = f_state->min_rtt;
	re.sent_pkts = f_state->sent_pkts;
	re.sent_bytes = f_state->sent_bytes;
	re.rec_pkts = f_state->rec_pkts;
	re.rec_bytes = f_state->rec_bytes;
	re.flow = p_info->pid.flow;
	re.match_on_egress = !p_info->is_ingress;
	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &re, sizeof(re));
}

/*
 * Contains the actual pping logic that is applied after a packet has been
 * parsed and deemed to contain some valid identifier.

 * Looks up and updates flowstate (in both directions), tries to save a
 * timestamp of the packet, tries to match packet against previous timestamps,
 * calculates RTTs and pushes messages to userspace as appropriate.
 */
static void pping_parsed_packet(void *ctx, struct packet_info *p_info)
{
	struct dual_flow_state *df_state;
	struct flow_state *fw_flow, *rev_flow;

	df_state = lookup_or_create_dualflow_state(ctx, p_info);
	if (!df_state)
		return;

	fw_flow = get_flowstate_from_packet(df_state, p_info);
	update_forward_flowstate(p_info, fw_flow);
	pping_timestamp_packet(fw_flow, ctx, p_info);

	rev_flow = get_reverse_flowstate_from_packet(df_state, p_info);
	update_reverse_flowstate(ctx, p_info, rev_flow);
	pping_match_packet(rev_flow, ctx, p_info);

	close_and_delete_flows(ctx, p_info, fw_flow, rev_flow);
}

/*
 * Main function which contains all the pping logic (parse packet, attempt to
 * create timestamp for it, try match against previous timestamps, update
 * flowstate etc.).
 *
 * Has a separate tc and xdp version so that verifier sees the global
 * functions for parsing packets in the right context, but most of the
 * work is done in common functions (parse_packet_identifier and
 * pping_parsed_packet)
 */
static void pping_tc(struct __sk_buff *ctx, bool is_ingress)
{
	struct packet_info p_info = { 0 };

	if (parse_packet_identifer_tc(ctx, &p_info) < 0)
		return;

	p_info.is_ingress = is_ingress;
	p_info.ingress_ifindex = is_ingress ? ctx->ingress_ifindex : 0;

	pping_parsed_packet(ctx, &p_info);
}

static void pping_xdp(struct xdp_md *ctx)
{
	struct packet_info p_info = { 0 };

	if (parse_packet_identifer_xdp(ctx, &p_info) < 0)
		return;

	p_info.is_ingress = true;
	p_info.ingress_ifindex = ctx->ingress_ifindex;

	pping_parsed_packet(ctx, &p_info);
}

static bool is_flow_old(struct network_tuple *flow, struct flow_state *f_state,
			__u64 time)
{
	__u64 age;
	__u64 ts;

	if (!f_state || !is_flowstate_active(f_state))
		return false;

	ts = f_state->last_timestamp; // To avoid concurrency issue between check and age calculation
	if (ts > time)
		return false;
	age = time - ts;

	return (f_state->conn_state == CONNECTION_STATE_WAITOPEN &&
		age > UNOPENED_FLOW_LIFETIME) ||
	       ((flow->proto == IPPROTO_ICMP ||
		 flow->proto == IPPROTO_ICMPV6) &&
		age > ICMP_FLOW_LIFETIME) ||
	       age > FLOW_LIFETIME;
}

static void send_flow_timeout_message(void *ctx, struct network_tuple *flow,
				      __u64 time)
{
	struct flow_event fe = {
		.event_type = EVENT_TYPE_FLOW,
		.flow_event_type = FLOW_EVENT_CLOSING,
		.reason = EVENT_REASON_FLOW_TIMEOUT,
		.source = EVENT_SOURCE_GC,
		.timestamp = time,
		.reserved = 0,
	};

	// To be consistent with Kathie's pping we report flow "backwards"
	reverse_flow(&fe.flow, flow);

	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &fe, sizeof(fe));
}

// Programs

// Egress path using TC-BPF
SEC("tc")
int pping_tc_egress(struct __sk_buff *skb)
{
	pping_tc(skb, false);

	return TC_ACT_UNSPEC;
}

// Ingress path using TC-BPF
SEC("tc")
int pping_tc_ingress(struct __sk_buff *skb)
{
	pping_tc(skb, true);

	return TC_ACT_UNSPEC;
}

// Ingress path using XDP
SEC("xdp")
int pping_xdp_ingress(struct xdp_md *ctx)
{
	pping_xdp(ctx);

	return XDP_PASS;
}

SEC("iter/bpf_map_elem")
int tsmap_cleanup(struct bpf_iter__bpf_map_elem *ctx)
{
	struct packet_id local_pid;
	struct flow_state *f_state = NULL;
	struct dual_flow_state *df_state;
	struct network_tuple df_key;
	struct packet_id *pid = ctx->key;
	__u64 *timestamp = ctx->value;
	__u64 now = bpf_ktime_get_ns();
	__u64 rtt;

	debug_update_mapclean_stats(ctx, &events, !ctx->key || !ctx->value,
				    ctx->meta->seq_num, now,
				    PPING_MAP_PACKETTS);

	if (!pid || !timestamp)
		return 0;
	if (now <= *timestamp)
		return 0;

	make_dualflow_key(&df_key, &pid->flow);
	df_state = bpf_map_lookup_elem(&flow_state, &df_key);
	if (df_state)
		f_state = get_flowstate_from_dualflow(df_state, &pid->flow);
	rtt = f_state ? f_state->srtt : 0;

	if ((rtt && now - *timestamp > rtt * TIMESTAMP_RTT_LIFETIME) ||
	    now - *timestamp > TIMESTAMP_LIFETIME) {
		/* Seems like the key for map lookup operations must be
		   on the stack, so copy pid to local_pid. */
		__builtin_memcpy(&local_pid, pid, sizeof(local_pid));
		if (bpf_map_delete_elem(&packet_ts, &local_pid) == 0) {
			debug_increment_timeoutdel(PPING_MAP_PACKETTS);

			if (f_state)
				__sync_fetch_and_add(
					&f_state->outstanding_timestamps, -1);
		}
	}

	return 0;
}

SEC("iter/bpf_map_elem")
int flowmap_cleanup(struct bpf_iter__bpf_map_elem *ctx)
{
	struct network_tuple flow1, flow2;
	struct flow_state *f_state1, *f_state2;
	struct dual_flow_state *df_state;
	__u64 now = bpf_ktime_get_ns();
	bool notify1, notify2, timeout1, timeout2;

	debug_update_mapclean_stats(ctx, &events, !ctx->key || !ctx->value,
				    ctx->meta->seq_num, now,
				    PPING_MAP_FLOWSTATE);

	if (!ctx->key || !ctx->value)
		return 0;

	flow1 = *(struct network_tuple *)ctx->key;
	reverse_flow(&flow2, &flow1);

	df_state = ctx->value;
	f_state1 = get_flowstate_from_dualflow(df_state, &flow1);
	f_state2 = get_flowstate_from_dualflow(df_state, &flow2);

	timeout1 = is_flow_old(&flow1, f_state1, now);
	timeout2 = is_flow_old(&flow2, f_state2, now);

	if ((!is_flowstate_active(f_state1) || timeout1) &&
	    (!is_flowstate_active(f_state2) || timeout2)) {
		// Entry should be deleted
		notify1 = should_notify_closing(f_state1) && timeout1;
		notify2 = should_notify_closing(f_state2) && timeout2;
		if (bpf_map_delete_elem(&flow_state, &flow1) == 0) {
			debug_increment_timeoutdel(PPING_MAP_FLOWSTATE);
			if (notify1)
				send_flow_timeout_message(ctx, &flow1, now);
			if (notify2)
				send_flow_timeout_message(ctx, &flow2, now);
		}
	}

	return 0;
}
