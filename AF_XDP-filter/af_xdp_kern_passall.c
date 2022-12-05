/* SPDX-License-Identifier: GPL-2.0 */

#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>

#include <linux/bpf.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <xdp/xdp_helpers.h>

#include "xsk_def_xdp_prog.h"

#include "af_xdp_kern_shared.h"
#ifndef NULL
#define NULL 0
#endif

#ifndef XDP_ACTION_MAX
#define XDP_ACTION_MAX (XDP_REDIRECT + 1)
#endif

enum { k_tracing = 0, k_tracing_detail = 0 };

enum { k_hashmap_size = 64 };

struct {
	__uint(type, BPF_MAP_TYPE_XSKMAP);
	__uint(key_size, sizeof(int));
	__uint(value_size, sizeof(int));
	__uint(max_entries, k_rx_queue_count_max);
} xsks_map SEC(".maps");

struct fivetuple {
	__u32 saddr; // Source address (network byte order)
	__u32 daddr; // Destination address (network byte order)
	__u16 sport; // Source port (network byte order) use 0 for ICMP
	__u16 dport; // Destination port (network byte order) use 0 for ICMP
	__u16 protocol; // Protocol
	__u16 padding;
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(key_size, sizeof(struct fivetuple));
	__uint(value_size, sizeof(int));
	__uint(max_entries, k_hashmap_size);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} accept_map SEC(".maps");

struct {
	__uint(priority, 10);
} XDP_RUN_CONFIG(xsk_my_prog);

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, XDP_ACTION_MAX);
	__type(key, int);
	__type(value, struct datarec);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} xdp_stats_map SEC(".maps");


SEC("xdp")
int xsk_my_prog(struct xdp_md *ctx)
{
	return XDP_PASS ;
}

char _license[] SEC("license") = "GPL";
__uint(xsk_prog_version, XSK_PROG_VERSION) SEC(XDP_METADATA_SECTION);
