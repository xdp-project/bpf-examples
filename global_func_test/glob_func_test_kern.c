/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/icmp.h>
#include <stdbool.h>

#include <xdp/parsing_helpers.h>

//#define USE_GLOBAL_FUNC
#define USE_COMMON_CONTEXT

struct common_ctx {
	void *data;
	void *data_end;
	__u64 len;
};

struct packet_data {
	__u16 icmp_seq;
};

char _license[] SEC("license") = "GPL";


/*
 * Function that parses an ICMPv4 packet and saves its sequnce number in
 * pd->icmp_seq.
 * Returns 0 on success, otherwise -1.
 *
 * USE_GLOBAL_FUNC and USE_COMMON_CONTEXT can be used to change aspects
 * of this function.
 */
__attribute__((noinline))
#ifndef USE_GLOBAL_FUNC
static
#endif
#ifdef USE_COMMON_CONTEXT
int parse_packet(struct common_ctx *ctx, struct packet_data *pd)
#else
int parse_packet(struct xdp_md *ctx, struct packet_data *pd)
#endif
{
	int proto, err;

	// Check that context and it's data/data_end pointers are valid
	// Only necessary when using global + common_context (ctx is not PTR_TO_CTX)
	if (!ctx || !ctx->data || !ctx->data_end)
		return -1;
	if (!pd)
		return -1;

	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;

	struct ethhdr *eth;
	struct iphdr *iph;
	struct icmphdr *icmph;
	struct hdr_cursor nh = { .pos = data };

	// If using global func, this fails with common_context
	proto = parse_ethhdr(&nh, data_end, &eth);
	if (proto != bpf_htons(ETH_P_IP)) {
		return -1;
	}

	proto = parse_iphdr(&nh, data_end, &iph);
	if (proto != IPPROTO_ICMP)
		return -1;

	err = parse_icmphdr(&nh, data_end, &icmph);
	if (err)
		return -1;

	pd->icmp_seq = bpf_ntohs(icmph->un.echo.sequence);
	return 0;
}

// Ingress path using XDP
SEC("xdp")
int xdp_glob_func_test(struct xdp_md *ctx)
{
	int err;
	struct packet_data pd = { 0 };
#ifdef USE_COMMON_CONTEXT
	struct common_ctx cctx = {
		.data = (void *)(long)ctx->data,
		.data_end = (void *)(long)ctx->data_end,
		.len = ctx->data_end - ctx->data,
	};

	err = parse_packet(&cctx, &pd);
#else
	err = parse_packet(ctx, &pd);
#endif

	if (!err)
		bpf_printk("ICMP seq = %u", pd.icmp_seq);

	return XDP_PASS;
}
