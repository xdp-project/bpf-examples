#include <linux/bpf.h>
#include <linux/in6.h>
#include <bpf/bpf_helpers.h>
#include <xdp/parsing_helpers.h>
#include "encap.h"

#ifdef IPV6
#define OFFSET sizeof(struct ipv6hdr)
#else
#define OFFSET sizeof(struct iphdr)
#endif

SEC("prog") int xdp_encap(struct xdp_md *ctx)
{
	volatile struct ethhdr *ehdr, old_ehdr = {};
	volatile void *data, *data_end;
	size_t offset = OFFSET;
	int ret = XDP_ABORTED;

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

#ifdef IPV6
	encap_ipv6(data, data_end);
#else
	encap_ipv4(data, data_end);
#endif
	ret = XDP_PASS;
out:
	return ret;
}

char _license[] SEC("license") = "GPL";
