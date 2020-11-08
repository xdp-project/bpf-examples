#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <xdp/parsing_helpers.h>
#include "iproute2_compat.h"

char _license[] SEC("license") = "GPL";

/* The tc tool (iproute2) use another ELF map layout than libbpf (struct
 * bpf_map_def), see struct bpf_elf_map from iproute2.
 */
struct bpf_elf_map  SEC("maps") cnt_map = {
	.type		= BPF_MAP_TYPE_ARRAY,
	.size_key	= sizeof(__u32),
	.size_value	= sizeof(__u64),
	.max_elem	= 1,
	//.pinning	= PIN_GLOBAL_NS,
};

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
