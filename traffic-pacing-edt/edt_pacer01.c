#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <xdp/parsing_helpers.h>

char _license[] SEC("license") = "GPL";

SEC("classifier") int tc_dummy(struct __sk_buff *skb)
{
	volatile void *data, *data_end;
	int ret = BPF_OK;
	struct ethhdr *eth;

	data     = (void *)(long)skb->data;
	data_end = (void *)(long)skb->data_end;
	eth = (struct ethhdr *)data;

	if (data + sizeof(*eth) > data_end)
		return BPF_DROP;

	/* Keep ARP resolution working */
	if (eth->h_proto == bpf_htons(ETH_P_ARP)) {
		ret = BPF_OK;
		goto out;
	}

 out:
        return ret;
}
