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
struct bpf_map_def SEC("maps") dhcp_server = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(int),
	.value_size = sizeof(__u32),
	.max_entries = 1,
};

/* Inserts DHCP option 82 into the received dhcp packet
 * at the specified offset.
*/
static __always_inline int write_dhcp_option(void* ctx, int offset, struct collect_vlans* vlans) {
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
static __always_inline int calc_ip_csum(struct iphdr* oldip, struct iphdr *ip, __u32 oldcsum) {
	__u32 size = sizeof(struct iphdr);
	__u32 csum = bpf_csum_diff((__be32*)oldip,size,(__be32*)ip,size,~oldcsum);
	__u32 sum = (csum >> 16) + (csum&0xffff);
	sum+= (sum>>16);
	return sum;
}

/* Offset to DHCP Options part of the packet */
#define static_offset (sizeof(struct ethhdr) + DHCP_FIXED_LEN)

/* Delta value to be adjusted at xdp head*/
#define delta sizeof(struct dhcp_option_82)

/* buf needs to be a static global var because the verifier won't allow
 * unaligned stack accesses
*/
static __u8 buf[static_offset + VLAN_MAX_DEPTH * sizeof(struct vlan_hdr) + COOKIE_SIZE];


/* XDP program for parsing the DHCP packet and inserting the option 82*/
SEC(XDP_PROG_SEC)
int xdp_dhcp_relay(struct xdp_md* ctx) {
  	void* data_end = (void*)(long)ctx->data_end;
  	void* data = (void*)(long)ctx->data;
  	struct collect_vlans vlans = { 0 };
  	struct ethhdr *eth;
  	struct iphdr *ip;
  	struct iphdr oldip;
 	struct udphdr *udp;
  	__u32 *dhcp_srv;
  	int rc = XDP_PASS;
 	__u16 offset = static_offset;
        int i = 0;
  
  /* These keep track of the next header type and iterator pointer */
	struct hdr_cursor nh;
	int ether_type;
 	int h_proto;
 	int key = 0;
	int len = 0;

  	if(data+1 > data_end)
	 	return XDP_ABORTED;

  	nh.pos = data;
  	ether_type = parse_ethhdr_vlan(&nh, data_end, &eth, &vlans);
 	 if(ether_type < 0) {
   		rc = XDP_ABORTED;
    		goto out;
    	}
  	if(ether_type != bpf_htons(ETH_P_IP)) 
		goto out;
	
   	h_proto = parse_iphdr(&nh,data_end,&ip);

 /* only handle fixed-size IP header due to static copy */
        if(h_proto != IPPROTO_UDP || ip->ihl > 5) {
		goto out;
	}
/*old ip hdr backup for re-calculating the checksum later*/
	oldip = *ip;
	len = parse_udphdr(&nh,data_end,  &udp);
	if(len < 0) 
		return XDP_ABORTED;
	
      	if(bpf_ntohs(udp->dest) != DEST_PORT)
		goto out;

	if (xdp_load_bytes(ctx, 0, buf, static_offset))
                 goto out;

        for (i = 0; i < VLAN_MAX_DEPTH; i++) {
                if (vlans.id[i]) {
                        xdp_load_bytes(ctx, offset, buf+offset, 4);
                        offset += 4;
                }
        }
	
        if(xdp_load_bytes(ctx, offset, buf+offset, COOKIE_SIZE))
		goto out;
        offset += COOKIE_SIZE;//for DHCP magic cookie

/* adjusting the packet head by delta size to insert option82 */
        if(bpf_xdp_adjust_head(ctx,0-delta) < 0) 
		return XDP_ABORTED;

  	data_end = (void*)(long)ctx->data_end;
  	data = (void*)(long)ctx->data;

	if(data + offset > data_end)
		return XDP_ABORTED;

	if (xdp_store_bytes(ctx, 0, buf, static_offset, 0))
                return XDP_ABORTED;

        if (offset > static_offset) {
                offset = static_offset;
                for (i = 0; i < VLAN_MAX_DEPTH; i++) {
                        if (vlans.id[i]) {
                                xdp_store_bytes(ctx, offset, buf+offset, 4, 0);
                                offset += 4;
                        }
                }
        }
        if(xdp_store_bytes(ctx, offset, buf+offset, COOKIE_SIZE, 0))
		goto out;
        offset += COOKIE_SIZE;
        if (write_dhcp_option(ctx, offset, &vlans))
               return XDP_ABORTED;

	nh.pos = data;
  	ether_type = parse_ethhdr_vlan(&nh, data_end, &eth, &vlans);
  	if(ether_type != bpf_htons(ETH_P_IP)) 
		goto out;

   	h_proto = parse_iphdr(&nh,data_end,&ip);
	if(h_proto < 0)
		return XDP_ABORTED;

/* read the DHCP relay server IP from map and overwrite the 
 * destination IP addr in IP header
*/
        dhcp_srv = bpf_map_lookup_elem(&dhcp_server,&key);
	if(dhcp_srv != NULL)
        	ip->daddr = *dhcp_srv;

        //re-calc ip checksum
 	__u32 sum = calc_ip_csum(&oldip,ip,oldip.check);	
	ip->check = ~sum;
        rc = XDP_PASS;
	goto out;
      				    
    out:
      return rc;
      
}
