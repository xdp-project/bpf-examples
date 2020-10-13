#include <linux/bpf.h>
#include <linux/in6.h>
#include <bpf/bpf_helpers.h>
#include <xdp/parsing_helpers.h>
#include "encap.h"

/* MTU is defined as L3 size (usually 1500 for Ethernet),
 * but remember TC (and XDP) operate at L2.
 */
//#define PKT_SIZE_L3 1500
#define PKT_SIZE_L3 1501
//#define PKT_SIZE_L3 1505
//#define PKT_SIZE_L3 1600
//#define PKT_SIZE_L3 20000
//#define PKT_SIZE_L3 65535

#define OFFSET sizeof(struct iphdr)
#define ENCAP_TYPE BPF_F_ADJ_ROOM_ENCAP_L3_IPV4

static unsigned int global_cnt = 0;
static int global_cnt = 0xFF;

SEC("classifier") int tc_inc_pkt_sz(struct __sk_buff *skb)
{
	volatile void *data, *data_end;
	int ret = BPF_DROP;
	struct ethhdr *eth;
	struct iphdr *iph;
	int extra_len;
	int len;

	/* Desired packet size at L2 */
	int pkt_size_l2 = PKT_SIZE_L3 + sizeof(*eth) ;

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

	if (bpf_skb_adjust_room(skb, extra_len, BPF_ADJ_ROOM_MAC, ENCAP_TYPE))
		goto out;

	// TODO: Handle if bpf_skb_adjust_room() cannot increase size,
	// as it's only my patched kernel that drop the MTU check

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
	iph->ttl = global_cnt;

	ret = BPF_OK;
out:
	return ret;
}

char _license[] SEC("license") = "GPL";
