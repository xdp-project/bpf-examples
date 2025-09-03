// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)

#ifndef BPF_LOCAL_HELPERS_H_
#define BPF_LOCAL_HELPERS_H_

#include "bpf_shared_data.h"

#define EEXIST      17  /* File exists */

#define BPF_MAP_TYPE_PIFO_GENERIC 31
#define BPF_MAP_TYPE_PIFO_XDP 32

/*
 * bpf_packet_dequeue
 *
 *      Dequeue the packet at the head of the PIFO in *map* and return a pointer
 *      to the packet (or NULL if the PIFO is empty).
 *
 * Returns
 *      On success, a pointer to the packet, or NULL if the PIFO is empty. The
 *      packet pointer must be freed using *bpf_packet_drop()* or returning
 *      the packet pointer. The *rank* pointer will be set to the rank of
 *      the dequeued packet on success, or a negative error code on error.
 */
static long (*bpf_packet_dequeue)(void *ctx, void *map, __u64 flags, __u64 *rank) = (void *) 208;;
static long (*bpf_packet_drop)(void *ctx, void *pkt) = (void *) 209;

struct parsing_context {
	void *data;            // Start of eth hdr
	void *data_end;        // End of safe acessible area
	void *meta;            // Meta data
	struct hdr_cursor nh;  // Position to parse next
	__u32 pkt_len;         // Full packet length (headers+data)
};

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-function"
static __always_inline void *
bpf_map_lookup_or_try_init(void *map, const void *key, const void *init)
{
        void *val;
        long err;

        val = bpf_map_lookup_elem(map, key);
        if (val)
                return val;

        err = bpf_map_update_elem(map, key, init, BPF_NOEXIST);
        if (err && err != -EEXIST)
                return NULL;

        return bpf_map_lookup_elem(map, key);
}

static __always_inline int bpf_max(__u64 left, __u64 right)
{
        return right > left ? right : left;
}


/*
 * Maps an IPv4 address into an IPv6 address according to RFC 4291 sec 2.5.5.2
 */
static void map_ipv4_to_ipv6(struct in6_addr *ipv6, __be32 ipv4)
{
	__builtin_memset(&ipv6->in6_u.u6_addr8[0], 0x00, 10);
	__builtin_memset(&ipv6->in6_u.u6_addr8[10], 0xff, 2);
	ipv6->in6_u.u6_addr32[3] = ipv4;
}

/*
 * Five-tuple helpers
 */

/* This function currently only supports UDP packets */
static __always_inline int parse_packet(struct parsing_context *pctx, struct packet_info *p_info)
{
	/* Parse Ethernet and IP/IPv6 headers */
	p_info->eth_type = parse_ethhdr(&pctx->nh, pctx->data_end, &p_info->eth);
	if (p_info->eth_type == bpf_htons(ETH_P_IP)) {
		p_info->ip_type = parse_iphdr(&pctx->nh, pctx->data_end, &p_info->iph);
		if (p_info->ip_type < 0)
			goto err;
		p_info->nt.ipv = 4;
		map_ipv4_to_ipv6(&p_info->nt.saddr.ip, p_info->iph->saddr);
		map_ipv4_to_ipv6(&p_info->nt.daddr.ip, p_info->iph->daddr);
	} else if (p_info->eth_type == bpf_htons(ETH_P_IPV6)) {
		p_info->ip_type = parse_ip6hdr(&pctx->nh, pctx->data_end, &p_info->ip6h);
		if (p_info->ip_type < 0)
			goto err;
		p_info->nt.ipv = 6;
 		p_info->nt.saddr.ip = p_info->ip6h->saddr;
		p_info->nt.daddr.ip = p_info->ip6h->daddr;
	} else {
		goto err;
	}

	/* Parse UDP header */
	if (p_info->ip_type != IPPROTO_UDP)
		goto err;
	if (parse_udphdr(&pctx->nh, pctx->data_end, &p_info->udph) < 0)
		goto err;

	p_info->nt.proto = IPPROTO_UDP;
	p_info->nt.saddr.port = p_info->udph->source;
	p_info->nt.daddr.port = p_info->udph->dest;

	return 0;
err:
	bpf_printk("Failed to parse UDP packet");
	return -1;
}

#pragma GCC diagnostic pop

#endif // BPF_LOCAL_HELPERS_H_
