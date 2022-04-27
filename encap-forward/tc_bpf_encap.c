#include <linux/bpf.h>
#include <linux/in6.h>
#include <bpf/bpf_helpers.h>
#include <xdp/parsing_helpers.h>
#include "encap.h"

#ifdef IPV6
#define OFFSET sizeof(struct ipv6hdr)
#define ENCAP_TYPE BPF_F_ADJ_ROOM_ENCAP_L3_IPV6
#else
#define OFFSET sizeof(struct iphdr)
#define ENCAP_TYPE BPF_F_ADJ_ROOM_ENCAP_L3_IPV4
#endif

#ifndef AF_INET
#define AF_INET 2
#endif

SEC("classifier") int tc_encap(struct __sk_buff *skb)
{
	struct bpf_fib_lookup fib_params = {};
	volatile void *data, *data_end;
	size_t offset = OFFSET;
	int ret = BPF_DROP;
	struct ethhdr *eth;
	struct iphdr *iph;

	if (bpf_skb_adjust_room(skb, offset, BPF_ADJ_ROOM_MAC, ENCAP_TYPE))
		goto out;

	data = (void *)(long)skb->data;
	data_end = (void *)(long)skb->data_end;
	eth = (void *)data;

#ifdef IPV6
	encap_ipv6(data, data_end);
#else
	encap_ipv4(data, data_end);

	iph = (void *)(eth +1);
	if (iph +1 > data_end)
		goto out;

	fib_params.family = AF_INET;
	fib_params.tos = iph->tos;
	fib_params.l4_protocol = iph->protocol;
	fib_params.sport = 0;
	fib_params.dport = 0;
	fib_params.tot_len = bpf_ntohs(iph->tot_len);
	fib_params.ipv4_src = iph->saddr;
	fib_params.ipv4_dst = iph->daddr;
	fib_params.ifindex = skb->ingress_ifindex;

	ret = bpf_fib_lookup(skb, &fib_params, sizeof(fib_params), 0);
	if (ret == BPF_FIB_LKUP_RET_SUCCESS) {
		__builtin_memcpy(eth->h_dest, fib_params.dmac, ETH_ALEN);
		__builtin_memcpy(eth->h_source, fib_params.smac, ETH_ALEN);

		return bpf_redirect(fib_params.ifindex, 0);
	} else if (ret == BPF_FIB_LKUP_RET_NO_NEIGH) {
		struct bpf_redir_neigh nh_params = {};

		nh_params.nh_family = fib_params.family;
		__builtin_memcpy(&nh_params.ipv6_nh, &fib_params.ipv6_dst,
				 sizeof(nh_params.ipv6_nh));
		return bpf_redirect_neigh(fib_params.ifindex, &nh_params,
					  sizeof(nh_params), 0);
	}

#endif

	ret = BPF_OK;
out:
	return ret;
}

char _license[] SEC("license") = "GPL";
