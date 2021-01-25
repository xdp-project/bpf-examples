/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <iproute2/bpf_elf.h>
#include <xdp/parsing_helpers.h>

#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>

#include <string.h>

#include "pping.h"
#include "pping_helpers.h"

char _license[] SEC("license") = "GPL";

#ifdef HAVE_TC_LIBBPF /* detected by configure script in config.mk */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(key_size, sizeof(struct ts_key));
	__uint(value_size, sizeof(struct ts_timestamp));
	__uint(max_entries, 16384);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} ts_start SEC(".maps");

#else
struct bpf_elf_map SEC("maps") ts_start = {
	.type = BPF_MAP_TYPE_HASH,
	.size_key = sizeof(struct ts_key),
	.size_value = sizeof(struct ts_timestamp),
	.max_elem = 16384,
	.pinning = PIN_GLOBAL_NS,
};
#endif

// TC-BFP for parsing TSVAL from egress traffic and add to map
SEC("pping_egress")
int tc_bpf_prog_egress(struct __sk_buff *skb)
{
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;

	//bpf_printk("Sent packet of size %d bytes\n", data_end - data);

	int proto = -1;
	struct hdr_cursor nh = { .pos = data };
	struct ethhdr *eth;
	struct iphdr *iph;
	struct tcphdr *tcph;

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
	// We have a TCP timestamp, try adding it to the map
	//bpf_printk("TCP-packet with timestap. TSval: %u, TSecr: %u\n", bpf_ntohl(tsval), bpf_ntohl(tsecr));
	struct ts_key key;
	fill_ipv4_flow(&(key.flow), iph->saddr, iph->daddr,
		       tcph->source, tcph->dest);
	key.tsval = tsval;

	struct ts_timestamp ts = { 0 };
	ts.timestamp = bpf_ktime_get_ns(); // or bpf_ktime_get_boot_ns
	bpf_map_update_elem(&ts_start, &key, &ts, BPF_NOEXIST);

end:
	return BPF_OK;
}
