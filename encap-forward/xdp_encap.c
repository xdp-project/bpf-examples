#include <linux/bpf.h>
#include <linux/in6.h>
#include <bpf/bpf_helpers.h>
#include <xdp/parsing_helpers.h>
#include "encap.h"


SEC("prog") int xdp_encap(struct xdp_md *ctx)
{
	volatile struct ethhdr *ehdr, old_ehdr = {};
	volatile void *data, *data_end;
	int ret = XDP_ABORTED;
	size_t offset = sizeof(struct iphdr);

	data = (void *)(long)ctx->data;
	data_end = (void *)(long)ctx->data_end;

	ehdr = data;
	if (ehdr + 1 > data_end)
		goto out;
	old_ehdr = *ehdr;

	if (bpf_xdp_adjust_head(ctx, -offset))
		goto out;

	data = (void *)(long)ctx->data;
	data_end = (void *)(long)ctx->data_end;

	ehdr = data;

	if (ehdr + 1 > data_end)
		goto out;
	*ehdr = old_ehdr;
	ehdr->h_proto = bpf_htons(ETH_P_IP);

//	encap_ipv6(data, data_end);
	encap_ipv4(data, data_end);
	ret = XDP_PASS;
out:
	return ret;
}

char _license[] SEC("license") = "GPL";
