/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef PPING_H
#define PPING_H

#include <linux/types.h>

#define XDP_PROG_SEC "xdp"
#define TCBPF_PROG_SEC "pping_egress"

// TODO - change to support both IPv4 and IPv6 (IPv4 addresses can be mapped to IPv6 addresses)
struct ipv4_flow {
	__u32 saddr;
	__u32 daddr;
	__u16 sport;
	__u16 dport;
};

struct ts_key {
	struct ipv4_flow flow;
	__u32 tsval;
};

struct ts_timestamp {
	__u64 timestamp;
	__u8 used;
};

struct rtt_event {
	struct ipv4_flow flow;
	__u64 rtt;
};

#endif
