/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef PPING_H
#define PPING_H

#include <linux/types.h>
#include <linux/in6.h>

#define INGRESS_PROG_SEC "xdp"
#define EGRESS_PROG_SEC "classifier"

struct bpf_config {
	__u64 rate_limit;
};

/*
 * Struct that can hold the source or destination address for a flow (l3+l4).
 * Works for both IPv4 and IPv6, as IPv4 addresses can be mapped to IPv6 ones
 * based on RFC 4291 Section 2.5.5.2.
 */
struct flow_address {
	struct in6_addr ip;
	__u16 port;
	__u16 reserved;
};

/*
 * Struct to hold a full network tuple
 * The ipv member is technically not necessary, but makes it easier to 
 * determine if saddr/daddr are IPv4 or IPv6 address (don't need to look at the
 * first 12 bytes of address). The proto memeber is not currently used, but 
 * could be useful once pping is extended to work for other protocols than TCP.
 */
struct network_tuple {
	struct flow_address saddr;
	struct flow_address daddr;
	__u16 proto; //IPPROTO_TCP, IPPROTO_ICMP, QUIC etc
	__u8 ipv; //AF_INET or AF_INET6
	__u8 reserved;
};

struct flow_state {
	__u64 last_timestamp;
	__u32 last_id;
	__u32 reserved;
};

struct packet_id {
	struct network_tuple flow;
	__u32 identifier; //tsval for TCP packets
};

struct rtt_event {
	__u64 rtt;
	struct network_tuple flow;
	__u32 reserved;
};

#endif
