#ifndef BPF_SHARED_DATA_H_
#define BPF_SHARED_DATA_H_

#include "codel_impl.h"

struct flow_address {
	struct in6_addr ip;
	__u16 port;
	__u16 reserved;
};

struct network_tuple {
	struct flow_address saddr;
	struct flow_address daddr;
	__u16 proto;
	__u8 ipv;
	__u8 reserved;
};

struct flow_state {
	__u32 pkts;
	__u32 root_finish_bytes;
	__u32 finish_bytes;
	__u16 root_weight;
	__u16 weight;
	__u32 persistent;
	__u64 root_priority;
};

struct fq_codel_flow_state {
	__u32 pkts;
	__u32 finish_bytes;
	__u32 total_bytes;
	__u32 grace_period;
	struct codel_state codel;
};

struct packet_info {
	struct ethhdr *eth;
	union {
		struct iphdr *iph;
		struct ipv6hdr *ip6h;
	};
	union {
		struct udphdr *udph;
	};
	struct network_tuple nt;
	int eth_type;
	int ip_type;
};

#endif // BPF_SHARED_DATA_H_
