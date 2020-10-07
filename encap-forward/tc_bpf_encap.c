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

SEC("classifier") int tc_encap(struct __sk_buff *skb)
{
	volatile void *data, *data_end;
	size_t offset = OFFSET;
	int ret = BPF_DROP;

	if (bpf_skb_adjust_room(skb, offset, BPF_ADJ_ROOM_MAC, ENCAP_TYPE))
		goto out;

	data = (void *)(long)skb->data;
	data_end = (void *)(long)skb->data_end;

#ifdef IPV6
	encap_ipv6(data, data_end);
#else
	encap_ipv4(data, data_end);

	/* proposed new helper for skipping source validation:
	bpf_skb_set_source_valid(skb, 1); */
#endif

	ret = BPF_OK;
out:
	return ret;
}

char _license[] SEC("license") = "GPL";
