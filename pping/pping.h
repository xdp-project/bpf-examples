/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef PPING_H
#define PPING_H

#include <linux/types.h>
#include <linux/in6.h>

#define XDP_PROG_SEC "xdp"
#define TCBPF_PROG_SEC "pping_egress"

/*
 * Struct to hold a full network tuple
 * Works for both IPv4 and IPv6, as IPv4 addresses can be mapped to IPv6 ones
 * based on RFC 4291 Section 2.5.5.2. The ipv member is technically not 
 * necessary, but makes it easier to determine if it is an IPv4 or IPv6 address
 * (don't need to look at the first 12 bytes of address).
 * The proto memeber is not currently used, but could be useful once pping
 * is extended to work for other protocols than TCP
 */
struct network_tuple {
	struct in6_addr saddr;
	struct in6_addr daddr;
	__u16 sport;
	__u16 dport;
	__u16 proto; //IPPROTO_TCP, IPPROTO_ICMP, QUIC etc
	__u16 ipv; //AF_INET or AF_INET6
};

struct packet_id {
	struct network_tuple flow;
	__u32 identifier; //tsval for TCP packets
};

struct packet_timestamp {
	__u64 timestamp;
	__u8 used;
};

struct rtt_event {
	__u64 rtt;
	struct network_tuple flow;
};

#endif
