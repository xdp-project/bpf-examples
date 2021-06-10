/* SPDX-License-Identifier: GPL-2.0-or-later */

#include <linux/bpf.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <xdp/parsing_helpers.h>
#include <xdp/context_helpers.h>
#include "dhcp-relay.h"

/*
 * This map is for storing the DHCP relay server
 * IP address configured by user. It is received
 * as an argument by user program.
*/
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, __u32);
	__uint(max_entries, 1);
} dhcp_server SEC(".maps");

/* Inserts DHCP option 82 into the received dhcp packet
 * at the specified offset.
*/
static __always_inline int write_dhcp_option(void *ctx, int offset,
					     struct collect_vlans *vlans)
{
	struct dhcp_option_82 option;

	option.t = DHO_DHCP_AGENT_OPTIONS;
	option.len = 8;
	option.circuit_id.option_id = RAI_CIRCUIT_ID;
	option.circuit_id.len = RAI_OPTION_LEN;
	option.circuit_id.val = bpf_htons(vlans->id[0]);
	option.remote_id.option_id = RAI_REMOTE_ID;
	option.remote_id.len = RAI_OPTION_LEN;
	option.remote_id.val = bpf_htons(vlans->id[1]);

	return xdp_store_bytes(ctx, offset, &option, sizeof(option), 0);
}

/* Calculates the IP checksum */
static __always_inline int calc_ip_csum(struct iphdr *oldip, struct iphdr *ip,
					__u32 oldcsum)
{
	__u32 size = sizeof(struct iphdr);
	__u32 csum = bpf_csum_diff((__be32 *)oldip, size, (__be32 *)ip, size,
				   ~oldcsum);
	__u32 sum = (csum >> 16) + (csum & 0xffff);
	sum += (sum >> 16);
	return sum;
}

/* Offset to DHCP Options part of the packet */
#define static_offset                                                          \
	sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) + \
		offsetof(struct dhcp_packet, options)

/* Delta value to be adjusted at xdp head*/
#define delta sizeof(struct dhcp_option_82)

/* buf needs to be a static global var because the verifier won't allow
 * unaligned stack accesses
*/
static __u8 buf[static_offset + VLAN_MAX_DEPTH * sizeof(struct vlan_hdr)];

/* XDP program for parsing the DHCP packet and inserting the option 82*/
SEC(XDP_PROG_SEC)
int xdp_dhcp_relay(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct collect_vlans vlans = { 0 };
	struct ethhdr *eth;
	struct iphdr *ip;
	struct iphdr oldip;
	struct udphdr *udp;
	__u32 *dhcp_srv;
	int rc = XDP_PASS;
	__u16 offset = static_offset;
	__u16 ip_offset = 0;
	int i = 0;

	/* These keep track of the next header type and iterator pointer */
	struct hdr_cursor nh;
	int ether_type;
	int h_proto = 0;
	int key = 0;
	int len = 0;

	if (data + 1 > data_end)
		return XDP_ABORTED;

	nh.pos = data;
	ether_type = parse_ethhdr_vlan(&nh, data_end, &eth, &vlans);
	/* check for valid ether type */
	if (ether_type < 0) {
		rc = XDP_ABORTED;
		goto out;
	}
	if (ether_type != bpf_htons(ETH_P_IP))
		goto out;

	/* Check at least two vlan tags are present */
	if (vlans.id[1] == 0)
		goto out;

	/* Read dhcp relay server IP from map */
	dhcp_srv = bpf_map_lookup_elem(&dhcp_server, &key);
	if (dhcp_srv == NULL)
		goto out;

	h_proto = parse_iphdr(&nh, data_end, &ip);

	/* only handle fixed-size IP header due to static copy */
	if (h_proto != IPPROTO_UDP || ip->ihl > 5) {
		goto out;
	}
	/*old ip hdr backup for re-calculating the checksum later*/
	oldip = *ip;
	ip_offset = ((void *)ip - data) & 0x3fff;
	len = parse_udphdr(&nh, data_end, &udp);
	if (len < 0)
		goto out;

	if (udp->dest != bpf_htons(DEST_PORT))
		goto out;

	if (xdp_load_bytes(ctx, 0, buf, static_offset))
		goto out;

	for (i = 0; i < VLAN_MAX_DEPTH; i++) {
		if (vlans.id[i]) {
			if (xdp_load_bytes(ctx, offset, buf + offset, 4))
				goto out;
			offset += 4;
		}
	}

	/* adjusting the packet head by delta size to insert option82 */
	if (bpf_xdp_adjust_head(ctx, 0 - delta) < 0)
		return XDP_ABORTED;

	data_end = (void *)(long)ctx->data_end;
	data = (void *)(long)ctx->data;

	if (data + offset > data_end)
		return XDP_ABORTED;

	if (xdp_store_bytes(ctx, 0, buf, static_offset, 0))
		return XDP_ABORTED;

	if (offset > static_offset) {
		offset = static_offset;
		for (i = 0; i < VLAN_MAX_DEPTH; i++) {
			if (vlans.id[i]) {
				if (xdp_store_bytes(ctx, offset, buf + offset,
						    4, 0))
					return XDP_ABORTED;
				offset += 4;
			}
		}
	}

	if (write_dhcp_option(ctx, offset, &vlans))
		return XDP_ABORTED;

	ip = data + ip_offset;
	if (ip + 1 > data_end)
		return XDP_ABORTED;

	/* overwrite the destination IP in IP header */
	ip->daddr = *dhcp_srv;

	//re-calc ip checksum
	__u32 sum = calc_ip_csum(&oldip, ip, oldip.check);
	ip->check = ~sum;
	rc = XDP_PASS;
	goto out;

out:
	return rc;
}
