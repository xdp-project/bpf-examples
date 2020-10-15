
static __always_inline __u16 csum_fold_helper(__u32 csum)
{
	__u32 sum;
	sum = (csum >> 16) + (csum & 0xffff);
	sum += (sum >> 16);
	return ~sum;
}

static void encap_ipv4_ipip(volatile void *data, volatile void *data_end)
{
	volatile struct iphdr *iph;
	size_t len;

	struct iphdr encap_hdr = {
		.version = 4,
		.ihl = 5,
		.protocol = IPPROTO_IPIP,
		.ttl = 16,
		.saddr = bpf_htonl(0x0a0b0202),
		.daddr = bpf_htonl(0x0a0b0201),
	};

	iph = data + sizeof(struct ethhdr);
	if (iph + 1 > data_end)
		return;

	*iph = encap_hdr;

	len = (data_end - data);
	iph->tot_len = bpf_htons(len - sizeof(struct ethhdr));
	iph->check = csum_fold_helper(bpf_csum_diff((__be32 *)iph, 0, (__be32 *)iph, sizeof(*iph), 0));
}
