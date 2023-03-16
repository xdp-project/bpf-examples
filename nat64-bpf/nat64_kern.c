/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright 2021 Toke Høiland-Jørgensen <toke@toke.dk> */


#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/compiler.h>
#include <linux/pkt_sched.h>
#include <linux/pkt_cls.h>
#include <stdbool.h>
#include "../include/xdp/parsing_helpers.h"
#include "nat64.h"

char _license[] SEC("license") = "GPL";

struct nat64_config config;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct in6_addr);
	__type(value, struct v6_addr_state);
	__uint(max_entries, 1);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} v6_state_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u32);
	__type(value, struct in6_addr);
	__uint(max_entries, 1);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} v4_reversemap SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(key_size, sizeof(struct in6_addr));
	__uint(value_size, sizeof(__u32));
	__uint(max_entries, 1);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} allowed_v6_src SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_QUEUE);
	__uint(key_size, 0);
	__uint(value_size, sizeof(__u32));
	__uint(max_entries, 1);
} reclaimed_addrs SEC(".maps");

#ifdef DEBUG
#define DBG(fmt, ...)                                   \
({							\
	char ____fmt[] = "nat64: " fmt;                 \
	bpf_trace_printk(____fmt, sizeof(____fmt),	\
			 ##__VA_ARGS__);		\
})
#else
#define DBG
#endif

struct icmpv6_pseudo {
	struct in6_addr saddr;
	struct in6_addr daddr;
	__u32 len;
	__u8 padding[3];
	__u8 nh;
} __attribute__((packed));

static __always_inline void
update_l4_checksum(struct __sk_buff *skb, struct ipv6hdr *ip6h,
                   struct iphdr *iph, int ip_type, bool v4to6)
{
	void *data = (void *)(unsigned long long)skb->data;
        int flags = BPF_F_PSEUDO_HDR;
        __u16 offset;
        __u32 csum;

	if (v4to6) {
		csum = bpf_csum_diff((__be32 *)&iph->saddr, 2 * sizeof(__u32),
				     (__be32 *)&ip6h->saddr,
				     2 * sizeof(struct in6_addr), 0);
		offset = (void *)(iph + 1) - data;
	} else {
		csum = bpf_csum_diff((__be32 *)&ip6h->saddr,
				     2 * sizeof(struct in6_addr),
				     (__be32 *)&iph->saddr, 2 * sizeof(__u32),
				     0);
		offset = (void *)(ip6h + 1) - data;
	}

	switch (ip_type) {
	case IPPROTO_TCP:
		offset += offsetof(struct tcphdr, check);
		break;
	case IPPROTO_UDP:
		offset += offsetof(struct udphdr, check);
                flags |= BPF_F_MARK_MANGLED_0;
		break;
	default:
		return;
	}

        bpf_l4_csum_replace(skb, offset, 0, csum, flags);
}

static __always_inline void
update_icmp_checksum(struct __sk_buff *skb, struct ipv6hdr *ip6h,
		     void *icmp_before, void *icmp_after, bool add)
{
	void *data = (void *)(unsigned long long)skb->data;
	struct icmpv6_pseudo ph = {
		.nh = IPPROTO_ICMPV6,
		.saddr = ip6h->saddr,
		.daddr = ip6h->daddr,
		.len = ip6h->payload_len
	};
        __u16 h_before, h_after, offset;
        __u32 csum, u_before, u_after;

        /* Do checksum update in two passes: first compute the incremental
         * checksum update of the ICMPv6 pseudo header, update the checksum
         * using bpf_l4_csum_replace(), and then do a separate update for the
         * ICMP type and code (which is two consecutive bytes, so cast them to
         * u16). The bpf_csum_diff() helper can be used to compute the
         * incremental update of the full block, whereas the
         * bpf_l4_csum_replace() helper can do the two-byte diff and update by
         * itself.
         */
	csum = bpf_csum_diff((__be32 *)&ph, add ? 0 : sizeof(ph),
                             (__be32 *)&ph, add ? sizeof(ph) : 0,
                             0);

        offset = ((void *)icmp_after - data) + 2;
        /* first two bytes of ICMP header, type and code */
        h_before = *(__u16 *)icmp_before;
        h_after = *(__u16 *)icmp_after;

        /* last four bytes of ICMP header, the data union */
        u_before = *(__u32 *)(icmp_before + 4);
        u_after = *(__u32 *)(icmp_after + 4);

        bpf_l4_csum_replace(skb, offset, 0, csum, BPF_F_PSEUDO_HDR);
        bpf_l4_csum_replace(skb, offset, h_before, h_after, 2);

        if (u_before != u_after)
                bpf_l4_csum_replace(skb, offset, u_before, u_after, 4);
}


static int rewrite_icmp(struct iphdr *iph, struct ipv6hdr *ip6h, struct __sk_buff *skb)
{
	void *data_end = (void *)(unsigned long long)skb->data_end;

	struct icmphdr old_icmp, *icmp = (void *)(iph + 1);
	struct icmp6hdr icmp6, *new_icmp6;
        __u32 mtu;

	if (icmp + 1 > data_end)
		return -1;

        old_icmp = *icmp;
        new_icmp6 = (void *)icmp;
	icmp6 = *new_icmp6;

	/* These translations are defined in RFC6145 section 4.2 */
	switch (icmp->type) {
	case ICMP_ECHO:
		icmp6.icmp6_type = ICMPV6_ECHO_REQUEST;
		break;
	case ICMP_ECHOREPLY:
		icmp6.icmp6_type = ICMPV6_ECHO_REPLY;
		break;
        case ICMP_DEST_UNREACH:
		icmp6.icmp6_type = ICMPV6_DEST_UNREACH;
		switch(icmp->code) {
		case ICMP_NET_UNREACH:
		case ICMP_HOST_UNREACH:
                case ICMP_SR_FAILED:
                case ICMP_NET_UNKNOWN:
                case ICMP_HOST_UNKNOWN:
                case ICMP_HOST_ISOLATED:
                case ICMP_NET_UNR_TOS:
                case ICMP_HOST_UNR_TOS:
			icmp6.icmp6_code = ICMPV6_NOROUTE;
			break;
                case ICMP_PROT_UNREACH:
			icmp6.icmp6_type = ICMPV6_PARAMPROB;
			icmp6.icmp6_code = ICMPV6_UNK_NEXTHDR;
                        icmp6.icmp6_pointer = bpf_htonl(offsetof(struct ipv6hdr, nexthdr));
                case ICMP_PORT_UNREACH:
			icmp6.icmp6_code = ICMPV6_PORT_UNREACH;
			break;
                case ICMP_FRAG_NEEDED:
                        icmp6.icmp6_type = ICMPV6_PKT_TOOBIG;
                        icmp6.icmp6_code = 0;
                        mtu = bpf_ntohs(icmp->un.frag.mtu) + 20;
                        /* RFC6145 section 6, "second approach" - should not be
                         * necessary, but might as well do this
                         */
                        if (mtu < 1280)
                                mtu = 1280;
                        icmp6.icmp6_mtu = bpf_htonl(mtu);
                case ICMP_NET_ANO:
                case ICMP_HOST_ANO:
                case ICMP_PKT_FILTERED:
                case ICMP_PREC_CUTOFF:
                        icmp6.icmp6_code = ICMPV6_ADM_PROHIBITED;
		default:
			return -1;
		}
		break;
        case ICMP_PARAMETERPROB:
                if (icmp->code == 1)
                        return -1;
                icmp6.icmp6_type = ICMPV6_PARAMPROB;
                icmp6.icmp6_code = ICMPV6_HDR_FIELD;
                /* The pointer field not defined in the Linux header. This
                 * translation is from Figure 3 of RFC6145.
                 */
                switch (icmp->un.reserved[0]) {
                case 0: /* version/IHL */
                        icmp6.icmp6_pointer = 0;
                        break;
                case 1: /* Type of Service */
                        icmp6.icmp6_pointer = bpf_htonl(1);
                        break;
                case 2: /* Total length */
                case 3:
                        icmp6.icmp6_pointer = bpf_htonl(4);
                        break;
                case 8: /* Time to Live */
                        icmp6.icmp6_pointer = bpf_htonl(7);
                        break;
                case 9: /* Protocol */
                        icmp6.icmp6_pointer = bpf_htonl(6);
                        break;
                case 12: /* Source address */
                case 13:
                case 14:
                case 15:
                        icmp6.icmp6_pointer = bpf_htonl(8);
                        break;
                case 16: /* Destination address */
                case 17:
                case 18:
                case 19:
                        icmp6.icmp6_pointer = bpf_htonl(24);
                        break;
                default:
                        return -1;
                }
	default:
		return -1;
	}

	*new_icmp6 = icmp6;
        update_icmp_checksum(skb, ip6h, &old_icmp, new_icmp6, true);

        /* FIXME: also need to rewrite IP header embedded in ICMP error */

	return 0;
}

static int nat64_handle_v4(struct __sk_buff *skb, struct hdr_cursor *nh)
{
	void *data_end = (void *)(unsigned long long)skb->data_end;
	void *data = (void *)(unsigned long long)skb->data;

        int ip_type, iphdr_len, ip_offset;
        struct in6_addr *dst_v6;
	struct ipv6hdr *ip6h;
        int ret = TC_ACT_OK;
	struct iphdr *iph;
        struct ethhdr *eth;
        __u32 dst_v4;

	struct ipv6hdr dst_hdr = {
		.version = 6,
		.saddr = config.v6_prefix,
	};

        ip_offset = (nh->pos - data) & 0x1fff;

        ip_type = parse_iphdr(nh, data_end, &iph);
        if (ip_type < 0)
                goto out;

        dst_v4 = bpf_ntohl(iph->daddr);
        if ((dst_v4 & config.v4_mask) != config.v4_prefix)
                goto out;

        /* At this point we know the destination IP is within the configured
         * subnet, so if we can't rewrite the packet it should be dropped (so as
         * not to leak traffic in that subnet).
         */
        ret = TC_ACT_SHOT;

        /* we don't bother dealing with IP options or fragmented packets. The
         * latter are identified by the 'frag_off' field having a value (either
         * the MF bit, or the fragmet offset, or both). However, this field also
         * contains the "don't fragment" (DF) bit, which we ignore, so mask that
         * out. The DF is the second-most-significant bit (as bit 0 is
         * reserved).
         */
        iphdr_len = iph->ihl * 4;
        if (iphdr_len != sizeof(struct iphdr) ||
            (iph->frag_off & ~bpf_htons(1<<14))) {
                DBG("v4: pkt src/dst %pI4/%pI4 has IP options or is fragmented, dropping\n",
                    &iph->daddr, &iph->saddr);
                goto out;
        }


        dst_v6 = bpf_map_lookup_elem(&v4_reversemap, &dst_v4);
        if (!dst_v6) {
                DBG("v4: no mapping found for dst %pI4\n", &iph->daddr);
                goto out;
        }

        DBG("v4: Found mapping for dst %pI4 to %pI6c\n", &iph->daddr, dst_v6);

        // src v4 as last octet of nat64 address
        dst_hdr.saddr.s6_addr32[3] = iph->saddr;
        dst_hdr.daddr = *dst_v6;
        dst_hdr.nexthdr = iph->protocol;
        dst_hdr.hop_limit = iph->ttl;
        /* weird definition in ipv6hdr */
        dst_hdr.priority = (iph->tos & 0x70) >> 4;
        dst_hdr.flow_lbl[0] = iph->tos << 4;
        dst_hdr.payload_len = bpf_htons(bpf_ntohs(iph->tot_len) - iphdr_len);

	switch (dst_hdr.nexthdr) {
	case IPPROTO_ICMP:
		if (rewrite_icmp(iph, &dst_hdr, skb))
			goto out;
		dst_hdr.nexthdr = IPPROTO_ICMPV6;
		break;
	case IPPROTO_TCP:
	case IPPROTO_UDP:
		update_l4_checksum(skb, &dst_hdr, iph, dst_hdr.nexthdr, true);
		break;
        default:
                break;
	}

	if (bpf_skb_change_proto(skb, bpf_htons(ETH_P_IPV6), 0))
                goto out;

	data = (void *)(unsigned long long)skb->data;
	data_end = (void *)(unsigned long long)skb->data_end;

        eth = data;
        ip6h = data + ip_offset;
        if (eth + 1 > data_end || ip6h + 1 > data_end)
                goto out;

        eth->h_proto = bpf_htons(ETH_P_IPV6);
        *ip6h = dst_hdr;

        ret = bpf_redirect_neigh(skb->ifindex, NULL, 0, 0);
out:
        return ret;
}

static long check_item(struct bpf_map *map, const void *key, void *value, void *ctx)
{
        struct v6_addr_state *state = value;
        __u64 timeout = *((__u64 *)ctx);

        if (state->last_seen < timeout && !state->static_conf) {
                __u32 v4_addr = state->v4_addr;
                bpf_map_delete_elem(map, key);
                bpf_map_delete_elem(&v4_reversemap, &v4_addr);
                bpf_map_push_elem(&reclaimed_addrs, &v4_addr, 0);

                /* only reclaim one address at a time, so mappings don't expire
                 * until they absolutely have to
                 */
                return 1;
        }

        return 0;
}

static __u32 reclaim_v4_addr(void)
{
        __u64 timeout = bpf_ktime_get_ns() - config.timeout_ns;
        __u32 src_v4;

        if (bpf_map_pop_elem(&reclaimed_addrs, &src_v4) == 0)
                return src_v4;

        bpf_for_each_map_elem(&v6_state_map, check_item, &timeout, 0);

        return bpf_map_pop_elem(&reclaimed_addrs, &src_v4) ? 0 : src_v4;
}

static struct v6_addr_state *alloc_new_state(struct in6_addr *src_v6)
{
        struct v6_addr_state new_v6_state = { .last_seen = bpf_ktime_get_ns() };
        __u32 max_v4 = (config.v4_prefix | ~config.v4_mask) - 1;
        __u32 src_v4 = 0;
        int i;

        for (i = 0; i < 10; i++) {
                __u32 next_v4, next_addr;

                next_addr = __sync_fetch_and_add(&config.next_addr, 0);
                next_v4 = config.v4_prefix + next_addr;

                if (next_v4 >= max_v4) {
                        src_v4 = reclaim_v4_addr();
                        break;
                }

                if (__sync_val_compare_and_swap(&config.next_addr,
                                                next_addr,
                                                next_addr + 1) == next_addr) {
                        src_v4 = next_v4;
                        break;
                }
        }

        /* If src_v4 is 0 here, we failed to find an available addr */
        if (!src_v4)
                return NULL;

        new_v6_state.v4_addr = src_v4;
        if (bpf_map_update_elem(&v6_state_map, src_v6, &new_v6_state, BPF_NOEXIST))
                goto err;
        if (bpf_map_update_elem(&v4_reversemap, &src_v4, src_v6, BPF_NOEXIST))
                goto err_v4;

        return bpf_map_lookup_elem(&v6_state_map, src_v6);

err_v4:
        bpf_map_delete_elem(&v6_state_map, src_v6);
err:
        /* failed to insert entry in maps, put the address back in the queue for
         * reclaiming
         */
        bpf_map_push_elem(&reclaimed_addrs, &src_v4, 0);
        return NULL;
}

static int cmp_v6addr(struct in6_addr *a, struct in6_addr *b)
{
        int i;
        for (i = 0; i < 4; i++) {
                if (a->s6_addr32[i] < b->s6_addr32[i])
                        return -1;
                if (a->s6_addr32[i] > b->s6_addr32[i])
                        return 1;
        }
        return 0;
}

static __always_inline __u16 csum_fold_helper(__u32 csum)
{
	__u32 sum;
	sum = (csum >> 16) + (csum & 0xffff);
	sum += (sum >> 16);
	return ~sum;
}

static int rewrite_icmpv6(struct ipv6hdr *ip6h, struct __sk_buff *skb)
{
	void *data_end = (void *)(unsigned long long)skb->data_end;

	struct icmp6hdr old_icmp6, *icmp6 = (void *)(ip6h + 1);
	struct icmphdr icmp, *new_icmp;
        __u32 mtu, ptr;

	if (icmp6 + 1 > data_end)
		return -1;

        old_icmp6 = *icmp6;
        new_icmp = (void *)icmp6;
	icmp = *new_icmp;

	/* These translations are defined in RFC6145 section 5.2 */
	switch (icmp6->icmp6_type) {
	case ICMPV6_ECHO_REQUEST:
		icmp.type = ICMP_ECHO;
		break;
	case ICMPV6_ECHO_REPLY:
		icmp.type = ICMP_ECHOREPLY;
		break;
	case ICMPV6_DEST_UNREACH:
		icmp.type = ICMP_DEST_UNREACH;
		switch(icmp6->icmp6_code) {
		case ICMPV6_NOROUTE:
		case ICMPV6_NOT_NEIGHBOUR:
		case ICMPV6_ADDR_UNREACH:
			icmp.code = ICMP_HOST_UNREACH;
			break;
		case ICMPV6_ADM_PROHIBITED:
			icmp.code = ICMP_HOST_ANO;
			break;
		case ICMPV6_PORT_UNREACH:
			icmp.code = ICMP_PORT_UNREACH;
			break;
		default:
			return -1;
		}
		break;
	case ICMPV6_PKT_TOOBIG:
		icmp.type = ICMP_DEST_UNREACH;
		icmp.code = ICMP_FRAG_NEEDED;

                mtu = bpf_htonl(icmp6->icmp6_mtu) - 20;
                if (mtu > 0xffff)
                        return -1;
                icmp.un.frag.mtu = bpf_htons(mtu);
		break;
	case ICMPV6_TIME_EXCEED:
		icmp.type = ICMP_TIME_EXCEEDED;
		break;
        case ICMPV6_PARAMPROB:
                switch (icmp6->icmp6_code) {
                case 0:
                        icmp.type = ICMP_PARAMETERPROB;
                        icmp.code = 0;
                        break;
                case 1:
                        icmp.type = ICMP_DEST_UNREACH;
                        icmp.code = ICMP_PROT_UNREACH;
                        ptr = bpf_ntohl(icmp6->icmp6_pointer);
                        /* Figure 6 in RFC6145 - using if statements b/c of
                         * range at the bottom
                         */
                        if (ptr == 0 || ptr == 1)
                                icmp.un.reserved[0] = ptr;
                        else if (ptr == 4 || ptr == 5)
                                icmp.un.reserved[0] = 2;
                        else if (ptr == 6)
                                icmp.un.reserved[0] = 9;
                        else if (ptr == 7)
                                icmp.un.reserved[0] = 8;
                        else if (ptr >= 8 && ptr <= 23)
                                icmp.un.reserved[0] = 12;
                        else if (ptr >= 24 && ptr <= 39)
                                icmp.un.reserved[0] = 16;
                        else
                                return -1;
                        break;
                default:
                        return -1;
                }
                break;
	default:
		return -1;
	}

	*new_icmp = icmp;
        update_icmp_checksum(skb, ip6h, &old_icmp6, new_icmp, false);

        /* FIXME: also need to rewrite IP header embedded in ICMP error */

	return 0;
}


static int nat64_handle_v6(struct __sk_buff *skb, struct hdr_cursor *nh)
{
	void *data_end = (void *)(unsigned long long)skb->data_end;
	void *data = (void *)(unsigned long long)skb->data;

	struct v6_trie_key saddr_key = { .t.prefixlen = 128 };
        struct in6_addr *dst_v6, subnet_v6 = {};
        __u32 *allowval, src_v4, dst_v4;
        int ip_type, ip_offset;
	struct ipv6hdr *ip6h;
        int ret = TC_ACT_OK;
	struct ethhdr *eth;
        struct iphdr *iph;

        struct v6_addr_state *v6_state;

	struct iphdr dst_hdr = {
		.version = 4,
                .ihl = 5,
                .frag_off = bpf_htons(1<<14), /* set Don't Fragment bit */
        };

        ip_offset = (nh->pos - data) & 0x1fff;

        ip_type = parse_ip6hdr(nh, data_end, &ip6h);
        if (ip_type < 0)
                goto out;

        dst_v6 = &ip6h->daddr;
        subnet_v6 = *dst_v6;
        /* v6 pxlen is always 96 */
        subnet_v6.s6_addr32[3] = 0;
        if (cmp_v6addr(&subnet_v6, &config.v6_prefix)) {
                DBG("v6: dst subnet %pI6c not in configured prefix %pI6c\n",
                    &subnet_v6, &config.v6_prefix);
                goto out;
        }

        /* At this point we know the destination IP is within the configured
         * subnet, so if we can't rewrite the packet it should be dropped (so as
         * not to leak traffic in that subnet).
         */
        ret = TC_ACT_SHOT;

        /* drop packets with IP options - parser skips options */
        if (ip_type != ip6h->nexthdr) {
                DBG("v6: dropping packet with IP options from %pI6c\n",
                    &ip6h->saddr);
                goto out;
        }

        /* drop a few special addresses */
        dst_v4 = ip6h->daddr.s6_addr32[3];
        if (!dst_v4 || /* 0.0.0.0 */
            (dst_v4 & bpf_htonl(0xFF000000)) == bpf_htonl(0x7F000000) || /* 127.x.x.x */
            (dst_v4 & bpf_htonl(0xF0000000)) == bpf_htonl(0xe0000000)) { /* multicast */
                DBG("v6: dropping invalid v4 dst %pI4 from %pI6c\n",
                    &dst_v4, &ip6h->saddr);
                goto out;
        }

        saddr_key.addr = ip6h->saddr;
        allowval = bpf_map_lookup_elem(&allowed_v6_src, &saddr_key);
        if (!allowval) {
                DBG("v6: saddr %pI6c not in allowed src\n", &ip6h->saddr);
                goto out;
        }

        v6_state = bpf_map_lookup_elem(&v6_state_map, &ip6h->saddr);
        if (!v6_state) {
                v6_state = alloc_new_state(&ip6h->saddr);
                if (!v6_state) {
                        DBG("v6: failed to allocate state for src %pI6c\n",
                            &ip6h->saddr);
                        goto out;
                }
                src_v4 = bpf_htonl(v6_state->v4_addr);
                DBG("v6: created new state for v6 %pI6c -> %pI4\n",
                    &ip6h->saddr, &src_v4);
        } else {
                v6_state->last_seen = bpf_ktime_get_ns();
                bpf_map_update_elem(&v6_state_map, &ip6h->saddr, v6_state, BPF_EXIST);

                src_v4 = bpf_htonl(v6_state->v4_addr);
                DBG("v6: updated old state for v6 %pI6c -> %pI4\n",
                    &ip6h->saddr, &src_v4);
        }

        dst_hdr.daddr = dst_v4;
        dst_hdr.saddr = bpf_htonl(v6_state->v4_addr);
        dst_hdr.protocol = ip6h->nexthdr;
        dst_hdr.ttl = ip6h->hop_limit;
        dst_hdr.tos = ip6h->priority << 4 | (ip6h->flow_lbl[0] >> 4);
        dst_hdr.tot_len = bpf_htons(bpf_ntohs(ip6h->payload_len) + sizeof(dst_hdr));

	switch (dst_hdr.protocol) {
	case IPPROTO_ICMPV6:
		if (rewrite_icmpv6(ip6h, skb))
			goto out;
		dst_hdr.protocol = IPPROTO_ICMP;
		break;
	case IPPROTO_TCP:
	case IPPROTO_UDP:
		update_l4_checksum(skb, ip6h, &dst_hdr, dst_hdr.protocol, false);
		break;
        default:
                break;
	}

        dst_hdr.check = csum_fold_helper(bpf_csum_diff((__be32 *)&dst_hdr, 0,
                                                       (__be32 *)&dst_hdr, sizeof(dst_hdr),
                                                       0));

        if (bpf_skb_change_proto(skb, bpf_htons(ETH_P_IP), 0))
                goto out;

	data = (void *)(unsigned long long)skb->data;
	data_end = (void *)(unsigned long long)skb->data_end;

        eth = data;
        iph = data + ip_offset;
        if (eth + 1 > data_end || iph + 1 > data_end)
                goto out;

        eth->h_proto = bpf_htons(ETH_P_IP);
        *iph = dst_hdr;

        ret = bpf_redirect(skb->ifindex, BPF_F_INGRESS);
out:
        return ret;
}

static int nat64_handler(struct __sk_buff *skb, bool egress)
{
	void *data_end = (void *)(unsigned long long)skb->data_end;
	void *data = (void *)(unsigned long long)skb->data;
	struct hdr_cursor nh  = { .pos = data };
	struct ethhdr *eth;
	int eth_type;

	/* Parse Ethernet and IP/IPv6 headers */
	eth_type = parse_ethhdr(&nh, data_end, &eth);
	if (eth_type == bpf_htons(ETH_P_IP) && egress)
		return nat64_handle_v4(skb, &nh);
	else if (eth_type == bpf_htons(ETH_P_IPV6) && !egress)
		return nat64_handle_v6(skb, &nh);

	return TC_ACT_OK;
}
SEC("tc")
int nat64_egress(struct __sk_buff *skb)
{
        return nat64_handler(skb, true);
}

SEC("tc")
int nat64_ingress(struct __sk_buff *skb)
{
        return nat64_handler(skb, false);
}
