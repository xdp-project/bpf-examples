/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef NETSTACKLAT_H
#define NETSTACKLAT_H

#define HIST_MAX_LATENCY_SLOT 34 // 2^34 ns -> ~17s
/*
 * MAX_LATENCY_SLOT + 1 buckets for hist, + 1 "bucket" for the "sum key"
 * (https://github.com/cloudflare/ebpf_exporter?tab=readme-ov-file#sum-keys)
 * that ebpf_exporter expects for exp2 hists (see how it's used in the
 * increment_exp2_histogram_nosync() function)
 */
#define HIST_NBUCKETS (HIST_MAX_LATENCY_SLOT + 2)

#define NS_PER_S 1000000000

// The highest possible PID on a Linux system (from /include/linux/threads.h)
#define PID_MAX_LIMIT (4 * 1024 * 1024)

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof(arr[0]))
#endif

#ifndef max
#define max(a, b)                   \
	({                          \
		typeof(a) _a = (a); \
		typeof(b) _b = (b); \
		_a > _b ? _a : _b;  \
	})
#endif

enum netstacklat_hook {
	NETSTACKLAT_HOOK_INVALID = 0,
	NETSTACKLAT_HOOK_IP_RCV,
	NETSTACKLAT_HOOK_TCP_START,
	NETSTACKLAT_HOOK_UDP_START,
	NETSTACKLAT_HOOK_TCP_SOCK_ENQUEUED,
	NETSTACKLAT_HOOK_UDP_SOCK_ENQUEUED,
	NETSTACKLAT_HOOK_TCP_SOCK_READ,
	NETSTACKLAT_HOOK_UDP_SOCK_READ,
	NETSTACKLAT_N_HOOKS,
};

struct netstacklat_bpf_config
{
	bool filter_pid;
};

#endif

