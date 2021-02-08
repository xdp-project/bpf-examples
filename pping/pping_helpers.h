/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef PPING_HELPERS_H
#define PPING_HELPERS_H

#include <linux/in6.h>
#include <linux/tcp.h>
#include <string.h>
#include "pping.h"

#define MAX_TCP_OPTIONS 10

/*
 * Maps and IPv4 address into an IPv6 address according to RFC 4291 sec 2.5.5.2
 */
static __always_inline void map_ipv4_to_ipv6(__be32 ipv4, struct in6_addr *ipv6)
{
	/* __u16 ipv4_prefix[6] = {0x0, 0x0, 0x0, 0x0, 0x0, 0xffff}; */
	/* memcpy(&(ipv6->in6_u.u6_addr8), ipv4_prefix, sizeof(ipv4_prefix)); */
	memset(&(ipv6->in6_u.u6_addr8[0]), 0x00, 10);
	memset(&(ipv6->in6_u.u6_addr8[10]), 0xff, 2);
#if __UAPI_DEF_IN6_ADDR_ALT
	ipv6->in6_u.u6_addr32[3] = ipv4;
#else
	memcpy(&(ipv6->in6_u.u6_addr8[12]), &ipv4, sizeof(ipv4));
#endif
}

/*
 * Parses the TSval and TSecr values from the TCP options field. If sucessful
 * the TSval and TSecr values will be stored at tsval and tsecr (in network
 * byte order).
 * Returns 0 if sucessful and -1 on failure
 */
static __always_inline int parse_tcp_ts(struct tcphdr *tcph, void *data_end,
                                        __u32 *tsval, __u32 *tsecr)
{
	int len = tcph->doff << 2;
	void *opt_end = (void *)tcph + len;
	__u8 *pos = (__u8 *)(tcph + 1); //Current pos in TCP options
	__u8 i, opt, opt_size;

	if (tcph + 1 > data_end || len <= sizeof(struct tcphdr))
		return -1;

	for (i = 0; i < MAX_TCP_OPTIONS; i++) {
		if (pos + 1 > opt_end || pos + 1 > data_end)
			return -1;

		opt = *pos;
		if (opt == 0) // Reached end of TCP options
			return -1;

		if (opt == 1) { // TCP NOP option - advance one byte
			pos++;
			continue;
		}

		// Option > 1, should have option size
		if (pos + 2 > opt_end || pos + 2 > data_end)
			return -1;
		opt_size = *(pos + 1);

		// Option-kind is TCP timestap (yey!)
		if (opt == 8 && opt_size == 10) {
			if (pos + opt_size > opt_end ||
			    pos + opt_size > data_end)
				return -1;
			*tsval = *(__u32 *)(pos + 2);
			*tsecr = *(__u32 *)(pos + 6);
			return 0;
		}

		// Some other TCP option - advance option-length bytes
		pos += opt_size;
	}
	return -1;
}

#endif
