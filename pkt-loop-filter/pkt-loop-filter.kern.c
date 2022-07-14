/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <stdbool.h>
#include <linux/bpf.h>
#include <asm/ptrace.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <xdp/parsing_helpers.h>
#include <linux/pkt_cls.h>

#include "pkt-loop-filter.h"
#include "bpf-defs.h"

#define NETDEV_GOING_DOWN 10

#define PKT_TYPE_UNICAST 1
#define PKT_TYPE_MULTICAST 2
#define PKT_TYPE_IGMP 3
#define PKT_TYPE_GRATUITOUS_ARP 4

/* We use an LRU map to avoid having to do cleanup: We just rely on the LRU
 * mechanism to evict old entries as the map fills up.
 */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, struct pkt_loop_key);
	__type(value, struct pkt_loop_data);
	__uint(max_entries, 1); /* set from userspace before load */
} iface_state SEC(".maps");

int bond_ifindex = 0;
int active_ifindex = 0;
/* This being const means that the verifier will do dead code elimination to
 * remove any code that depends on it being true entirely, incurring no runtime
 * overhead if debug mode is disabled.
 **/
volatile const int debug_output = 0;
volatile const int netns_cookie = INIT_NS;

/* copy of kernel's version - if the LSB of the first octet is 1 then it is
 * a multicast address
 */
static bool is_multicast_ether_addr(const __u8 *addr)
{
	return 0x01 & addr[0];
}

#define ARPHRD_ETHER 	1		/* Ethernet 10Mbps		*/

struct arphdr {
	__be16		ar_hrd;		/* format of hardware address	*/
	__be16		ar_pro;		/* format of protocol address	*/
	unsigned char	ar_hln;		/* length of hardware address	*/
	unsigned char	ar_pln;		/* length of protocol address	*/
	__be16		ar_op;		/* ARP opcode (command)		*/

	unsigned char		ar_sha[ETH_ALEN];	/* sender hardware address	*/
	__be32			ar_sip;		/* sender IP address		*/
	unsigned char		ar_tha[ETH_ALEN];	/* target hardware address	*/
	__be32			ar_tip;		/* sender IP address		*/
} __attribute__((packed));

static bool is_gratuitous_arp(struct hdr_cursor *nh, void *data_end)
{
	struct arphdr *ah = nh->pos;

	if (ah + 1 > data_end)
		return false;

	if (ah->ar_hrd != bpf_htons(ARPHRD_ETHER) || ah->ar_pro != bpf_htons(ETH_P_IP))
		return false;

	/* A gratuitous ARP has identical target and source IPs */
	return (ah->ar_sip == ah->ar_tip);
}

static int parse_pkt(struct __sk_buff *skb, struct pkt_loop_key *key)
{
	void *data_end = (void *)(unsigned long long)skb->data_end;
	void *data = (void *)(unsigned long long)skb->data;
	struct hdr_cursor nh = { .pos = data };
	int eth_type, ip_type;
	struct ethhdr *eth;

	/* Parse Ethernet and IP/IPv6 headers */
	eth_type = parse_ethhdr(&nh, data_end, &eth);
	if (eth_type < 0)
		return eth_type;

	__builtin_memcpy(key->src_mac, eth->h_source, ETH_ALEN);
	key->src_vlan = skb->vlan_tci;

	if (eth_type == bpf_htons(ETH_P_ARP) && is_gratuitous_arp(&nh, data_end))
		return PKT_TYPE_GRATUITOUS_ARP;

	if (is_multicast_ether_addr(eth->h_dest))
		return PKT_TYPE_MULTICAST;

	if (eth_type == bpf_htons(ETH_P_IP)) {
		struct iphdr *iph;

		ip_type = parse_iphdr(&nh, data_end, &iph);
		if (ip_type == IPPROTO_IGMP)
			return PKT_TYPE_IGMP;

	} else if (eth_type == bpf_htons(ETH_P_IPV6)) {
		struct icmp6hdr *icmp6;
		struct ipv6hdr *ip6h;
		int icmp6_type;

		ip_type = parse_ip6hdr(&nh, data_end, &ip6h);
		if (ip_type != IPPROTO_ICMPV6)
			goto out;

		icmp6_type = parse_icmp6hdr(&nh, data_end, &icmp6);
		if (icmp6_type == ICMPV6_MGM_QUERY || icmp6_type == ICMPV6_MGM_REPORT ||
		    icmp6_type == ICMPV6_MGM_REDUCTION || icmp6_type == ICMPV6_MLD2_REPORT ||
		    icmp6_type == ICMPV6_MRDISC_ADV)
			return PKT_TYPE_IGMP;
	}
out:
	return PKT_TYPE_UNICAST;
}

SEC("tc")
int record_egress_pkt(struct __sk_buff *skb)
{
	struct pkt_loop_data value = { .ifindex = skb->ifindex }, *v;
	__u64 now = bpf_ktime_get_boot_ns();
	struct pkt_loop_key key;
	int pkt_type;

	pkt_type = parse_pkt(skb, &key);
	if (pkt_type < 0)
		goto out;

	v = bpf_map_lookup_elem(&iface_state, &key);
	if (!v) {
		bpf_map_update_elem(&iface_state, &key, &value, BPF_NOEXIST);
		v = bpf_map_lookup_elem(&iface_state, &key);
		if (!v)
			goto out;
	}
	v->expiry_time = now + STATE_LIFETIME;
	if (pkt_type == PKT_TYPE_GRATUITOUS_ARP)
		v->lock_time = now + LOCK_LIFETIME;
	v->ifindex = skb->ifindex;
out:
	return TC_ACT_OK;
}

SEC("tc")
int filter_ingress_pkt(struct __sk_buff *skb)
{
	int pkt_type, ifindex = active_ifindex;
	__u64 now = bpf_ktime_get_boot_ns();
	struct pkt_loop_data *value;
	struct pkt_loop_key key;

	pkt_type = parse_pkt(skb, &key);
	if (pkt_type < 0)
		goto out;

	value = bpf_map_lookup_elem(&iface_state, &key);
	if (value && value->expiry_time > now &&
	    value->ifindex != skb->ifindex) {
		if (pkt_type == PKT_TYPE_GRATUITOUS_ARP &&
		    value->lock_time < now) {
			if (debug_output)
				bpf_printk("Received gratuitous ARP for SMAC/vlan %llx, expiring filter\n",
					   *(__u64 *)&key);
			value->expiry_time = 0;
			goto out;
		}

		value->drops++;
		if (debug_output)
			/* bpf_trace_printk doesn't know how to format MAC
			 * addresses, and we don't have enough arguments to do
			 * it ourselves; so just pass the whole key as a u64 and
			 * hex-print that
			 */
			bpf_printk("Dropping packet with SMAC/vlan %llx - ifindex %d != expected %d\n",
				   *(__u64 *)&key, skb->ifindex, value->ifindex);
		return TC_ACT_SHOT;
	}


	/* Only allow multicast and IGMP pkts on the currently active interface */
	if ((pkt_type == PKT_TYPE_MULTICAST || pkt_type == PKT_TYPE_IGMP) &&
	    skb->ifindex != ifindex) {
		if (debug_output)
			bpf_printk("Dropping packet type %d - ifindex %d != active %d\n",
				   pkt_type, skb->ifindex, ifindex);
		return TC_ACT_SHOT;
	}

out:
	return TC_ACT_OK;
}

SEC("kprobe/bond_change_active_slave")
int BPF_KPROBE(handle_change_slave, struct bonding *bond, struct slave *new_active)
{
        struct net_device *dev = BPF_PROBE_READ(bond, dev);
	struct net *net = BPF_CORE_READ(dev, nd_net.net);
	int ifindex = BPF_CORE_READ(dev, ifindex);
	__u64 cookie = read_net_cookie(net);


        if (cookie == netns_cookie && ifindex == bond_ifindex && new_active) {
                struct net_device *new_dev;
		int ifindex;

		new_dev = BPF_PROBE_READ(new_active, dev);
		ifindex = BPF_CORE_READ(new_dev, ifindex);
		if (ifindex) {
			active_ifindex = ifindex;
			if (debug_output)
				bpf_printk("Active ifindex changed, new value: %d\n", ifindex);
		}
        }

	return 0;
}

char _license[] SEC("license") = "GPL";
