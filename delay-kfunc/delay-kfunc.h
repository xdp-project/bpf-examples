// SPDX-License-Identifier: GPL-2.0-or-later

#include <linux/bpf.h>

struct delay_stats {
	__u64 delay_ns;
	char comm[16];
	int pid;
	int ret;
};
