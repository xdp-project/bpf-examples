/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef PPING_HELPERS_H
#define PPING_HELPERS_H

#include "pping.h"
#include <linux/tcp.h>

#define MAX_TCP_OPTIONS 10

static __always_inline int fill_ipv4_flow(struct ipv4_flow *flow, __u32 saddr,
					  __u32 daddr, __u16 sport, __u16 dport)
{
	flow->saddr = saddr;
	flow->daddr = daddr;
	flow->sport = sport;
	flow->dport = dport;
	return 0;
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
