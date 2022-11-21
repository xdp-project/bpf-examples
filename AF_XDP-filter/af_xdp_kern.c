/* SPDX-License-Identifier: GPL-2.0 */

#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>

#include <linux/bpf.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <xdp/xdp_helpers.h>

#include "xsk_def_xdp_prog.h"

#include "af_xdp_kern_shared.h"

#ifndef XDP_ACTION_MAX
#define XDP_ACTION_MAX (XDP_REDIRECT + 1)
#endif

enum {
	k_tracing = 1,
	k_tracing_detail = 0
};

enum {
	k_hashmap_size = 64
};

struct {
	__uint(type, BPF_MAP_TYPE_XSKMAP);
	__uint(key_size, sizeof(int));
	__uint(value_size, sizeof(int));
	__uint(max_entries, k_rx_queue_count_max);
} xsks_map SEC(".maps");

struct fivetuple {
	__u32 saddr ; // Source address (network byte order)
	__u32 daddr ; // Destination address (network byte order)
	__u16 sport ; // Source port (network byte order) use 0 for ICMP
	__u16 dport ; // Destination port (network byte order) use 0 for ICMP
	__u16 protocol ; // Protocol
	__u16 padding ;
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH) ;
	__uint(key_size, sizeof(struct fivetuple)) ;
	__uint(value_size, sizeof(int)) ;
	__uint(max_entries, k_hashmap_size) ;
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} accept_map SEC(".maps");


struct {
	__uint(priority, 10);
} XDP_RUN_CONFIG(xsk_my_prog);

static __always_inline void display_one(int index) {
	void * mapped=bpf_map_lookup_elem(&xsks_map, &index) ;
	if (mapped) bpf_printk("xsks_map[%d]=%p", index, mapped) ;
}

static __always_inline void display_all(void) {
	int a;
#pragma unroll
	for(a=0; a<k_rx_queue_count_max; a+= 1)
	{
		display_one(a) ;
	}
}

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, XDP_ACTION_MAX);
	__type(key, int);
	__type(value, struct datarec);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} xdp_stats_map SEC(".maps");

static __always_inline
__u32 stats_record_action(struct xdp_md *ctx, __u32 action)
{
	if( k_tracing ) bpf_printk("stats_record_action action=%d", action);

	if (action >= XDP_ACTION_MAX)
		return XDP_ABORTED;

	/* Lookup in kernel BPF-side return pointer to actual data record */
	struct datarec *rec = bpf_map_lookup_elem(&xdp_stats_map, &action);
	if (!rec)
		return XDP_ABORTED;

	/* BPF_MAP_TYPE_PERCPU_ARRAY returns a data record specific to current
	 * CPU and XDP hooks runs under Softirq, which makes it safe to update
	 * without atomic operations.
	 */
	rec->rx_packets++;
	rec->rx_bytes += (ctx->data_end - ctx->data);

	return action;
}

/* Header cursor to keep track of current parsing position */
struct hdr_cursor {
	void *pos;
};

static __always_inline int parse_ethhdr(struct hdr_cursor *nh,
					void *data_end,
					struct ethhdr **ethhdr)
{
	struct ethhdr *eth = nh->pos;
	int hdrsize = sizeof(*eth);
	/* Byte-count bounds check; check if current pointer + size of header
	 * is after data_end.
	 */
	if (nh->pos + hdrsize > data_end)
		return -1;

	nh->pos += hdrsize;
	*ethhdr = eth;

	return eth->h_proto; /* network-byte-order */
}

static __always_inline int parse_ip4hdr(struct hdr_cursor *nh,
		                        void *data_end,
					struct iphdr **ip4hdr)
{
	struct iphdr *ip4h = nh->pos;
	int hdrsize = sizeof(*ip4h);
	if (nh->pos + hdrsize >data_end)
		return -1;
	int actual_hdrsize = ip4h->ihl*4;
	if (nh->pos + actual_hdrsize > data_end)
		return -1;
	nh->pos += actual_hdrsize;
	*ip4hdr = ip4h; /* Network byte order */
	return 0;
}

static __always_inline int parse_tcp4hdr(struct hdr_cursor *nh,
		                        void *data_end,
					struct tcphdr **tcp4hdr)
{
	struct tcphdr *tcp4h = nh->pos;
	int hdrsize = sizeof(*tcp4h);
	if (nh->pos + hdrsize >data_end)
		return -1;
	int actual_hdrsize=hdrsize ; // Ignore the possibility of TCP options
	nh->pos += actual_hdrsize;
	*tcp4hdr = tcp4h; /* Network byte order */
	return 0;
}

static __always_inline int parse_udp4hdr(struct hdr_cursor *nh,
		                        void *data_end,
					struct udphdr **udp4hdr)
{
	struct udphdr *udp4h = nh->pos;
	int hdrsize = sizeof(*udp4h);
	if (nh->pos + hdrsize >data_end)
		return -1;
	int actual_hdrsize=hdrsize ;
	nh->pos += actual_hdrsize;
	*udp4hdr = udp4h; /* Network byte order */
	return 0;
}

static void show_fivetuple(struct fivetuple *f) {
	if(k_tracing) {
		bpf_printk("fivetuple saddr=%08x daddr=%08x", f->saddr, f->daddr) ;
		bpf_printk(" sport=%04x dport=%04x", f->sport, f->dport) ;
		bpf_printk(" protocol=%04x padding=%u", f->protocol, f->padding) ;
	}

}

SEC("xdp")
int xsk_my_prog(struct xdp_md *ctx)
{

	struct fivetuple f ;
	if(k_tracing_detail) display_all() ;
    int index = ctx->rx_queue_index;
	/* A set entry here means that the correspnding queue_id
	 * has an active AF_XDP socket bound to it. */
	void * mapped=bpf_map_lookup_elem(&xsks_map, &index) ;
	if( k_tracing ) bpf_printk("xsks_map[%d]=%p", index, mapped) ;

    enum xdp_action action = XDP_PASS; /* Default action */
	void * v_permit = NULL ;
    if (mapped)
    {
    	void *data_end = (void *)(long)ctx->data_end;
    	void *data = (void *)(long)ctx->data;
    	struct ethhdr *eth;
        /* These keep track of the next header type and iterator pointer */
		struct hdr_cursor nh;
		int nh_type;

		/* Start next header cursor position at data start */
		nh.pos = data;

		/* Packet parsing in steps: Get each header one at a time, aborting if
		 * parsing fails. Each helper function does sanity checking (is the
		 * header type in the packet correct?), and bounds checking.
		 */
		nh_type = parse_ethhdr(&nh, data_end, &eth);
		if( k_tracing ) bpf_printk("nh_type=0x%04x ETH_P_IP=0x%04x", nh_type, ETH_P_IP);
		if (nh_type == bpf_htons(ETH_P_IP))
			{
						/* Assignment additions go below here */
				struct iphdr *iphdr;
				int rc;
				rc = parse_ip4hdr(&nh, data_end, &iphdr);
				if (rc != 0) goto out ;

				int protocol=iphdr->protocol;
				if( k_tracing ) bpf_printk("protocol=%d", protocol) ;

				f.protocol = protocol ;
				f.saddr = iphdr->saddr ;
				f.daddr = iphdr->daddr ;
				f.padding = 0 ;
				if ( protocol == IPPROTO_TCP ) {
					struct tcphdr *t ;
					rc = parse_tcp4hdr(&nh, data_end, &t);
					if (rc != 0) goto out ;
					f.sport = t->source ;
					f.dport = t->dest ;
					show_fivetuple(&f) ;
					v_permit=bpf_map_lookup_elem(&accept_map, &f) ;
				} else if ( protocol == IPPROTO_UDP ) {
					struct udphdr *u ;
					rc = parse_udp4hdr(&nh, data_end, &u);
					if (rc != 0) goto out ;
					f.sport = u->source ;
					f.dport = u->dest ;
					show_fivetuple(&f) ;
					v_permit=bpf_map_lookup_elem(&accept_map, &f) ;
				} else if ( protocol == IPPROTO_ICMP ) {
					f.sport = 0 ;
					f.dport = 0 ;
					show_fivetuple(&f) ;
					v_permit=bpf_map_lookup_elem(&accept_map, &f) ;
				}
			}
		else if (nh_type == bpf_htons(ETH_P_ARP) )
		{
			/* Always accept ARP packets */
			if( k_tracing ) bpf_printk("ARP packet");
			return stats_record_action(ctx,XDP_PASS) ;
		} else {
			if( k_tracing ) bpf_printk("Unknown nh_type=0x%04x", nh_type);
			return stats_record_action(ctx,XDP_PASS) ;
		}

		if( k_tracing ) bpf_printk("v_permit=%p", v_permit);

		if ( v_permit ) {
			action = *(int *) v_permit ;
		} else {
			action = XDP_REDIRECT ;
		}
		if ( action == XDP_REDIRECT) {
			stats_record_action(ctx, XDP_REDIRECT);
			if( k_tracing ) bpf_printk("returning through bpf_redirect_map");
			return bpf_redirect_map(&xsks_map, index, XDP_PASS);
		}
    }
out:
	return stats_record_action(ctx, action); /* read via xdp_stats */
}


char _license[] SEC("license") = "GPL";
__uint(xsk_prog_version, XSK_PROG_VERSION) SEC(XDP_METADATA_SECTION);

