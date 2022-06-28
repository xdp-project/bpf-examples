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

/* local partial kernel struct definitions with just the members we need */
struct net {
	__u64 net_cookie;
} __attribute__((preserve_access_index));

struct net_device {
	int ifindex;
	struct {
		struct net *net;
	} nd_net;
} __attribute__((preserve_access_index));

struct netdev_notifier_info {
	struct net_device *dev;
} __attribute__((preserve_access_index));

#define NETDEV_GOING_DOWN 10

/* cookie for init ns; hoping this is stable */
#define INIT_NS 1

#define PKT_TYPE_UNICAST 1
#define PKT_TYPE_MULTICAST 2

/* We use an LRU map to avoid having to do cleanup: We just rely on the LRU
 * mechanism to evict old entries as the map fills up.
 */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, struct pkt_loop_key);
	__type(value, struct pkt_loop_data);
	__uint(max_entries, 1); /* set from userspace before load */
} iface_state SEC(".maps");

int active_ifindexes[MAX_IFINDEXES] = {};
unsigned int current_ifindex = 0;

static int get_current_ifindex(void)
{
	/* bounds check to placate the verifier */
	if (current_ifindex > MAX_IFINDEXES)
		return 0;

	return active_ifindexes[current_ifindex];
}

/* copy of kernel's version - if the LSB of the first octet is 1 then it is
 * a multicast address
 */
static bool is_multicast_ether_addr(const __u8 *addr)
{
	return 0x01 & addr[0];
}

static int parse_pkt(struct __sk_buff *skb, struct pkt_loop_key *key)
{
	void *data_end = (void *)(unsigned long long)skb->data_end;
	void *data = (void *)(unsigned long long)skb->data;
	struct hdr_cursor nh = { .pos = data };
	struct ethhdr *eth;
	int eth_type;

	/* Parse Ethernet and IP/IPv6 headers */
	eth_type = parse_ethhdr(&nh, data_end, &eth);
	if (eth_type < 0)
		return eth_type;

	__builtin_memcpy(key->src_mac, eth->h_source, ETH_ALEN);
	key->src_vlan = skb->vlan_tci;

	return is_multicast_ether_addr(eth->h_dest) ? PKT_TYPE_MULTICAST : PKT_TYPE_UNICAST;
}

SEC("tc")
int record_egress_pkt(struct __sk_buff *skb)
{
	struct pkt_loop_data value = { .ifindex = skb->ifindex }, *v;
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
	v->expiry_time = bpf_ktime_get_coarse_ns() + STATE_LIFETIME;
	v->ifindex = skb->ifindex;
out:
	return TC_ACT_OK;
}

SEC("tc")
int filter_ingress_pkt(struct __sk_buff *skb)
{
	struct pkt_loop_data *value;
	struct pkt_loop_key key;
	int pkt_type;

	pkt_type = parse_pkt(skb, &key);
	if (pkt_type < 0)
		goto out;

	value = bpf_map_lookup_elem(&iface_state, &key);
	if (value && value->expiry_time > bpf_ktime_get_coarse_ns()) {
		value->drops++;
		return TC_ACT_SHOT;
	}

	/* Only allow multicast pkts on the currently active interface */
	if (pkt_type == PKT_TYPE_MULTICAST &&
	    skb->ifindex != get_current_ifindex())
		return TC_ACT_SHOT;

out:
	return TC_ACT_OK;
}

SEC("kprobe/call_netdevice_notifiers_info")
int BPF_KPROBE(handle_device_notify, unsigned long val, struct netdev_notifier_info *info)
{
	int ifindex = BPF_CORE_READ(info, dev, ifindex);
	__u64 cookie = BPF_CORE_READ(info, dev, nd_net.net, net_cookie);

	if (val == NETDEV_GOING_DOWN && cookie == INIT_NS &&
	    ifindex == get_current_ifindex()) {
		/* Active interface going down, switch to next one; we currently
		 * don't check for ifup and switch back
		 */
		current_ifindex++;
		if (current_ifindex > MAX_IFINDEXES || !active_ifindexes[current_ifindex])
			current_ifindex = 0;
	}

	return 0;
}

char _license[] SEC("license") = "GPL";
