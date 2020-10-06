#include <linux/bpf.h>
#include <linux/in6.h>
#include <bpf/bpf_helpers.h>
#include <xdp/parsing_helpers.h>
#include "encap.h"

SEC("classifier") int tc_encap(struct __sk_buff *skb)
{
	volatile void *data, *data_end;
	int ret = BPF_DROP;
	size_t offset = sizeof(struct iphdr);


	if (bpf_skb_adjust_room(skb, offset, BPF_ADJ_ROOM_MAC, BPF_F_ADJ_ROOM_ENCAP_L3_IPV4))
		goto out;

	data = (void *)(long)skb->data;
	data_end = (void *)(long)skb->data_end;

//	encap_ipv6(ctx);
	encap_ipv4(data, data_end);
	ret = BPF_OK;
out:
	return ret;
}

char _license[] SEC("license") = "GPL";
