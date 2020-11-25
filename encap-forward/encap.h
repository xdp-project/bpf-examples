#define NEXTHDR_IPV6		41

#ifdef IPV6
static void encap_ipv6(volatile void *data, volatile void *data_end)
{
	volatile struct ipv6hdr *ip6h;
	volatile struct ethhdr *eth;
	size_t len;

	struct ipv6hdr encap_hdr = {
		.version = 6,
		.nexthdr = NEXTHDR_IPV6,
		.hop_limit = 16,
		.saddr = { .s6_addr = { 0xfc, 0x00, 0xde, 0xad, 0xca, 0xfe,
					0x00, 0x02, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x02 } },
		.daddr = { .s6_addr = { 0xfc, 0x00, 0xde, 0xad, 0xca, 0xfe,
					0x00, 0x02, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x01 } },
	};

	eth = data;
	ip6h = (void *)(eth +1);
	if (ip6h + 1 > data_end)
		return;

	eth->h_proto = bpf_htons(ETH_P_IPV6);
	*ip6h = encap_hdr;

	len = (data_end - data);
	ip6h->payload_len = bpf_htons(len - sizeof(struct ethhdr) - sizeof(*ip6h));
}
#else

static __always_inline __u16 csum_fold_helper(__u32 csum)
{
	__u32 sum;
	sum = (csum >> 16) + (csum & 0xffff);
	sum += (sum >> 16);
	return ~sum;
}

static void encap_ipv4(volatile void *data, volatile void *data_end)
{
	volatile struct ethhdr *eth;
	volatile struct iphdr *iph;
	size_t len;

	struct iphdr encap_hdr = {
		.version = 4,
		.ihl = 5,
		.protocol = NEXTHDR_IPV6,
		.ttl = 16,
		.saddr = bpf_htonl(0x0a0b0202),
		.daddr = bpf_htonl(0x0a0b0201),
	};

	eth = data;
	iph = (void *)(eth +1);
	if (iph + 1 > data_end)
		return;

	eth->h_proto = bpf_htons(ETH_P_IP);
	*iph = encap_hdr;

	len = (data_end - data);
	iph->tot_len = bpf_htons(len - sizeof(struct ethhdr));
	iph->check = csum_fold_helper(bpf_csum_diff((__be32 *)iph, 0, (__be32 *)iph, sizeof(*iph), 0));
}

#endif
