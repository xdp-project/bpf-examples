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

#define AF_INET 2
#define AF_INET6 10
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
	__u32 ingress_ifindex; // Interface packet arrived on
	bool is_egress;        // Is packet on egress or ingress?
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
	union {
		struct iphdr *iph;
		struct ipv6hdr *ip6h;
	};
	union {
		struct icmphdr *icmph;
		struct icmp6hdr *icmp6h;
		struct tcphdr *tcph;
	};
	__u64 time;                  // Arrival time of packet
	__u32 payload;               // Size of packet data (excluding headers)
	struct packet_id pid;        // flow + identifier to timestamp (ex. TSval)
	struct packet_id reply_pid;  // rev. flow + identifier to match against (ex. TSecr)
	bool pid_valid;              // identifier can be used to timestamp packet
	bool reply_pid_valid;        // reply_identifier can be used to match packet
	enum flow_event_type event_type; // flow event triggered by packet
	enum flow_event_reason event_reason; // reason for triggering flow event
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
	__type(value, struct flow_state);
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
	} else {
		proto_info->event_type = FLOW_EVENT_NONE;
		proto_info->event_reason = EVENT_REASON_NONE;
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

	p_info->time = bpf_ktime_get_ns();
	proto = parse_ethhdr(&pctx->nh, pctx->data_end, &eth);

	// Parse IPv4/6 header
	if (proto == bpf_htons(ETH_P_IP)) {
		p_info->pid.flow.ipv = AF_INET;
		p_info->pid.flow.proto =
			parse_iphdr(&pctx->nh, pctx->data_end, &p_info->iph);
	} else if (proto == bpf_htons(ETH_P_IPV6)) {
		p_info->pid.flow.ipv = AF_INET6;
		p_info->pid.flow.proto =
			parse_ip6hdr(&pctx->nh, pctx->data_end, &p_info->ip6h);
	} else {
		return -1;
	}

	// Parse identifer from suitable protocol
	if (config.track_tcp && p_info->pid.flow.proto == IPPROTO_TCP)
		err = parse_tcp_identifier(pctx, &p_info->tcph,
					   &p_info->pid.flow.saddr.port,
					   &p_info->pid.flow.daddr.port,
					   &proto_info);
	else if (config.track_icmp &&
		 p_info->pid.flow.proto == IPPROTO_ICMPV6 &&
		 p_info->pid.flow.ipv == AF_INET6)
		err = parse_icmp6_identifier(pctx, &p_info->icmp6h,
					     &p_info->pid.flow.saddr.port,
					     &p_info->pid.flow.daddr.port,
					     &proto_info);
	else if (config.track_icmp && p_info->pid.flow.proto == IPPROTO_ICMP &&
		 p_info->pid.flow.ipv == AF_INET)
		err = parse_icmp_identifier(pctx, &p_info->icmph,
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

	if (p_info->pid.flow.ipv == AF_INET) {
		map_ipv4_to_ipv6(&p_info->pid.flow.saddr.ip,
				 p_info->iph->saddr);
		map_ipv4_to_ipv6(&p_info->pid.flow.daddr.ip,
				 p_info->iph->daddr);
	} else { // IPv6
		p_info->pid.flow.saddr.ip = p_info->ip6h->saddr;
		p_info->pid.flow.daddr.ip = p_info->ip6h->daddr;
	}

	reverse_flow(&p_info->reply_pid.flow, &p_info->pid.flow);
	p_info->payload = remaining_pkt_payload(pctx);

	return 0;
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
 * Attempt to create a new flow-state.
 * Returns a pointer to the flow_state if successful, NULL otherwise
 */
static struct flow_state *create_flow(void *ctx, struct packet_info *p_info)
{
	struct flow_state new_state = { 0 };

	new_state.last_timestamp = p_info->time;
	new_state.opening_reason = p_info->event_type == FLOW_EVENT_OPENING ?
					   p_info->event_reason :
						 EVENT_REASON_FIRST_OBS_PCKT;

	if (bpf_map_update_elem(&flow_state, &p_info->pid.flow, &new_state,
				BPF_NOEXIST) != 0) {
		send_map_full_event(ctx, p_info, PPING_MAP_FLOWSTATE);
		return NULL;
	}

	return bpf_map_lookup_elem(&flow_state, &p_info->pid.flow);
}

static struct flow_state *update_flow(void *ctx, struct packet_info *p_info,
				      bool *new_flow)
{
	struct flow_state *f_state;
	*new_flow = false;

	f_state = bpf_map_lookup_elem(&flow_state, &p_info->pid.flow);

	// Attempt to create flow if it does not exist
	if (!f_state && p_info->pid_valid &&
	    !(p_info->event_type == FLOW_EVENT_CLOSING ||
	      p_info->event_type == FLOW_EVENT_CLOSING_BOTH)) {
		*new_flow = true;
		f_state = create_flow(ctx, p_info);
	}

	if (!f_state)
		return NULL;

	// Update flow state
	f_state->sent_pkts++;
	f_state->sent_bytes += p_info->payload;

	return f_state;
}

static struct flow_state *update_rev_flow(void *ctx, struct packet_info *p_info)
{
	struct flow_state *f_state;

	f_state = bpf_map_lookup_elem(&flow_state, &p_info->reply_pid.flow);
	if (!f_state)
		return NULL;

	// Is a new flow, push opening flow message
	if (!f_state->has_opened &&
	    p_info->event_type != FLOW_EVENT_CLOSING_BOTH) {
		f_state->has_opened = true;
		send_flow_open_event(ctx, p_info, f_state);
	}

	// Update flow state
	f_state->rec_pkts++;
	f_state->rec_bytes += p_info->payload;

	return f_state;
}

static void delete_closed_flows(void *ctx, struct packet_info *p_info,
				struct flow_state *flow,
				struct flow_state *rev_flow)
{
	bool has_opened;

	// Flow closing - try to delete flow state and push closing-event
	if (flow && (p_info->event_type == FLOW_EVENT_CLOSING ||
		     p_info->event_type == FLOW_EVENT_CLOSING_BOTH)) {
		has_opened = flow->has_opened;
		if (bpf_map_delete_elem(&flow_state, &p_info->pid.flow) == 0) {
			debug_increment_autodel(PPING_MAP_FLOWSTATE);
			if (has_opened)
				send_flow_event(ctx, p_info, false);
		}
	}

	// Also close reverse flow
	if (rev_flow && p_info->event_type == FLOW_EVENT_CLOSING_BOTH) {
		has_opened = rev_flow->has_opened;
		if (bpf_map_delete_elem(&flow_state, &p_info->reply_pid.flow) ==
		    0) {
			debug_increment_autodel(PPING_MAP_FLOWSTATE);
			if (has_opened)
				send_flow_event(ctx, p_info, true);
		}
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
static bool is_local_address(struct packet_info *p_info, void *ctx,
			     struct parsing_context *pctx)
{
	int ret;
	struct bpf_fib_lookup lookup;
	__builtin_memset(&lookup, 0, sizeof(lookup));

	lookup.ifindex = pctx->ingress_ifindex;
	lookup.family = p_info->pid.flow.ipv;

	if (lookup.family == AF_INET) {
		lookup.tos = p_info->iph->tos;
		lookup.tot_len = bpf_ntohs(p_info->iph->tot_len);
		lookup.ipv4_src = p_info->iph->saddr;
		lookup.ipv4_dst = p_info->iph->daddr;
	} else if (lookup.family == AF_INET6) {
		struct in6_addr *src = (struct in6_addr *)lookup.ipv6_src;
		struct in6_addr *dst = (struct in6_addr *)lookup.ipv6_dst;

		lookup.flowinfo = *(__be32 *)p_info->ip6h & IPV6_FLOWINFO_MASK;
		lookup.tot_len = bpf_ntohs(p_info->ip6h->payload_len);
		*src = p_info->pid.flow.saddr.ip; //verifier did not like ip6h->saddr
		*dst = p_info->pid.flow.daddr.ip;
	}

	lookup.l4_protocol = p_info->pid.flow.proto;
	lookup.sport = 0;
	lookup.dport = 0;

	ret = bpf_fib_lookup(ctx, &lookup, sizeof(lookup), 0);

	return ret == BPF_FIB_LKUP_RET_NOT_FWDED ||
	       ret == BPF_FIB_LKUP_RET_FWD_DISABLED;
}

/*
 * Attempt to create a timestamp-entry for packet p_info for flow in f_state
 */
static void pping_timestamp_packet(struct flow_state *f_state, void *ctx,
				   struct parsing_context *pctx,
				   struct packet_info *p_info, bool new_flow)
{
	if (!f_state || !p_info->pid_valid)
		return;

	if (config.localfilt && !pctx->is_egress &&
	    is_local_address(p_info, ctx, pctx))
		return;

	// Check if identfier is new
	if (!new_flow && f_state->last_id == p_info->pid.identifier)
		return;
	f_state->last_id = p_info->pid.identifier;

	// Check rate-limit
	if (!new_flow &&
	    is_rate_limited(p_info->time, f_state->last_timestamp,
			    config.use_srtt ? f_state->srtt : f_state->min_rtt))
		return;

	/*
	 * Updates attempt at creating timestamp, even if creation of timestamp
	 * fails (due to map being full). This should make the competition for
	 * the next available map slot somewhat fairer between heavy and sparse
	 * flows.
	 */
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
			       struct parsing_context *pctx,
			       struct packet_info *p_info)
{
	struct rtt_event re = { 0 };
	__u64 *p_ts;

	if (!f_state || !p_info->reply_pid_valid)
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
	re.match_on_egress = pctx->is_egress;
	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &re, sizeof(re));
}

/*
 * Will parse the ingress/egress packet in pctx and attempt to create a
 * timestamp for it and match it against the reverse flow.
 */
static void pping(void *ctx, struct parsing_context *pctx)
{
	struct packet_info p_info = { 0 };
	struct flow_state *flow, *rev_flow;
	bool new_flow;

	if (parse_packet_identifier(pctx, &p_info) < 0)
		return;

	flow = update_flow(ctx, &p_info, &new_flow);
	pping_timestamp_packet(flow, ctx, pctx, &p_info, new_flow);

	rev_flow = update_rev_flow(ctx, &p_info);
	pping_match_packet(rev_flow, ctx, pctx, &p_info);

	delete_closed_flows(ctx, &p_info, flow, rev_flow);
}

// Programs

// Egress path using TC-BPF
SEC("tc")
int pping_tc_egress(struct __sk_buff *skb)
{
	struct parsing_context pctx = {
		.data = (void *)(long)skb->data,
		.data_end = (void *)(long)skb->data_end,
		.pkt_len = skb->len,
		.nh = { .pos = pctx.data },
		.is_egress = true,
	};

	pping(skb, &pctx);

	return TC_ACT_UNSPEC;
}

// Ingress path using TC-BPF
SEC("tc")
int pping_tc_ingress(struct __sk_buff *skb)
{
	struct parsing_context pctx = {
		.data = (void *)(long)skb->data,
		.data_end = (void *)(long)skb->data_end,
		.pkt_len = skb->len,
		.nh = { .pos = pctx.data },
		.ingress_ifindex = skb->ingress_ifindex,
		.is_egress = false,
	};

	pping(skb, &pctx);

	return TC_ACT_UNSPEC;
}

// Ingress path using XDP
SEC("xdp")
int pping_xdp_ingress(struct xdp_md *ctx)
{
	struct parsing_context pctx = {
		.data = (void *)(long)ctx->data,
		.data_end = (void *)(long)ctx->data_end,
		.pkt_len = pctx.data_end - pctx.data,
		.nh = { .pos = pctx.data },
		.ingress_ifindex = ctx->ingress_ifindex,
		.is_egress = false,
	};

	pping(ctx, &pctx);

	return XDP_PASS;
}

SEC("iter/bpf_map_elem")
int tsmap_cleanup(struct bpf_iter__bpf_map_elem *ctx)
{
	struct packet_id local_pid;
	struct flow_state *f_state;
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

	/* Seems like the key for map lookup operations must be
	   on the stack, so copy pid to local_pid. */
	__builtin_memcpy(&local_pid, pid, sizeof(local_pid));
	f_state = bpf_map_lookup_elem(&flow_state, &local_pid.flow);
	rtt = f_state ? f_state->srtt : 0;

	if ((rtt && now - *timestamp > rtt * TIMESTAMP_RTT_LIFETIME) ||
	    now - *timestamp > TIMESTAMP_LIFETIME) {
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
	struct network_tuple local_flow;
	struct network_tuple *flow = ctx->key;
	struct flow_state *f_state = ctx->value;
	struct flow_event fe;
	__u64 now = bpf_ktime_get_ns();
	bool has_opened;
	__u64 age;

	debug_update_mapclean_stats(ctx, &events, !ctx->key || !ctx->value,
				    ctx->meta->seq_num, now,
				    PPING_MAP_FLOWSTATE);

	if (!flow || !f_state)
		return 0;
	if (now < f_state->last_timestamp)
		return 0;

	// Check if flow is too old for unopned/ICMP/other flow type
	age = now - f_state->last_timestamp;
	has_opened = f_state->has_opened;

	if ((!has_opened && age > UNOPENED_FLOW_LIFETIME) ||
	    ((flow->proto == IPPROTO_ICMP || flow->proto == IPPROTO_ICMPV6) &&
	     age > ICMP_FLOW_LIFETIME) ||
	    age > FLOW_LIFETIME) {
		__builtin_memcpy(&local_flow, flow, sizeof(local_flow));
		has_opened = f_state->has_opened;

		if (bpf_map_delete_elem(&flow_state, &local_flow) == 0) {
			debug_increment_timeoutdel(PPING_MAP_FLOWSTATE);

			if (has_opened) {
				reverse_flow(&fe.flow, &local_flow);
				fe.event_type = EVENT_TYPE_FLOW;
				fe.timestamp = now;
				fe.flow_event_type = FLOW_EVENT_CLOSING;
				fe.reason = EVENT_REASON_FLOW_TIMEOUT;
				fe.source = EVENT_SOURCE_GC;
				fe.reserved = 0;
				bpf_perf_event_output(ctx, &events,
						      BPF_F_CURRENT_CPU, &fe,
						      sizeof(fe));
			}
		}
	}

	return 0;
}
