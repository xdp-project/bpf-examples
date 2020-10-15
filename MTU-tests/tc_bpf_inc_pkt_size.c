#include <linux/bpf.h>
#include <linux/in6.h>
#include <bpf/bpf_helpers.h>
#include <xdp/parsing_helpers.h>
#include "encap.h"

/* Cycle through different MTU packet sizes, encoded in BPF-code via switch
 * statement.  MTU is defined as L3 size (usually 1500 for Ethernet), but
 * remember TC (and XDP) operate at L2 (adjusted later)
 */
static __always_inline __u32 get_pkt_size_l3(__u64 cnt)
{
	switch (cnt) {
	case 0:
		return 1024;
	case 1:
		return 1500;
	case 2:
		return 1504;
	case 3:
		return 1508;
	case 4:
		return 1600;
	case 5:
		return 4096 + 128;
	case 6:
		return 3520;
	case 7:
		return 3528;
	case 8:
		return 4096 - 14;
	case 9:
		return 4096;
	case 10:
		return 8192;
	case 11:
		return 16000;
	default:
		return 1500;
	}
}
#define CNT_MAX 12

/* The tc tool (iproute2) use another ELF map layout than libbpf, see
 * struct bpf_elf_map from iproute2, but bpf_map_def from libbpf have
 * same binary layout until "flags" so use that.
 */
struct bpf_map_def  SEC("maps") cnt_map = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(__u64),
	.max_entries = 1,
	.map_flags = 0,
};

/* LLVM maps __sync_fetch_and_add() as a built-in function to the BPF atomic add
 * instruction (that is BPF_STX | BPF_XADD | BPF_W for word sizes)
 */
#ifndef lock_xadd
#define lock_xadd(ptr, val)     ((void) __sync_fetch_and_add(ptr, val))
#endif

#define ENCAP_TYPE BPF_F_ADJ_ROOM_ENCAP_L3_IPV4

SEC("classifier") int tc_inc_pkt_sz(struct __sk_buff *skb)
{
	volatile void *data, *data_end;
	int ret = BPF_DROP;
	struct ethhdr *eth;
	struct iphdr *iph;
	int extra_len;
	int len;

	int key = 0;
	__u64 *cnt;

	cnt = bpf_map_lookup_elem(&cnt_map, &key);
	if (!cnt)
		goto out;

	/* Desired packet size at L2 */
	int pkt_size_l2 = get_pkt_size_l3(*cnt) + sizeof(*eth) ;

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

	len = (data_end - data);
	extra_len = pkt_size_l2 - len;
	// extra_len= sizeof(*iph); /* Adj that does correct IPIP encap */

	/* Wrapping global counter */
        lock_xadd(cnt, 1);
	if (*cnt == CNT_MAX)
		*cnt = 0;

	if (bpf_skb_adjust_room(skb, extra_len, BPF_ADJ_ROOM_MAC, ENCAP_TYPE)) {
		/* If adjust fails, then skip this packet length adjustment */
		ret = BPF_OK;
		goto out;
	}

	/* Most re-load after bpf_skb_adjust_room() */
	data     = (void *)(long)skb->data;
	data_end = (void *)(long)skb->data_end;

	/* Add IP-header with IPIP */
	encap_ipv4_ipip(data, data_end);

	eth = (void *)data;
	iph = (void *)(eth +1);
	if (iph +1 > data_end)
		goto out;

	eth->h_proto = bpf_htons(ETH_P_IP);

	ret = BPF_OK;
out:
	return ret;
}

char _license[] SEC("license") = "GPL";
