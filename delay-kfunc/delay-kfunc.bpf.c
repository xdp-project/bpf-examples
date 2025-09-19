/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "vmlinux_local.h"
#include <linux/bpf.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "delay-kfunc.h"

char LICENSE[] SEC("license") = "GPL";

#define TIME_ROUNDS 10
#define TIME_ITER 100

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 0x1000);
} delay_ringbuf SEC(".maps");

__u64 loop_iterations = 10000;
__u64 avg_delay = 100;

static int recurse_loop(__u64 idx, void *ctx)
{
	return 0;
}

static int run_delay(__u64 idx, void *ctx)
{
	bpf_loop(100000, recurse_loop, NULL, 0);
	return 0;
}

SEC("fentry/veth_dellink")
int BPF_PROG(delay_function)
{
	__u64 start_ns = 0, end_ns = 0;
	struct delay_stats *stats;
	int cur_pid = bpf_get_current_pid_tgid() >> 32;
	int ret;

	start_ns = bpf_ktime_get_boot_ns();
	ret = bpf_loop(loop_iterations, run_delay, NULL, 0);

	stats = bpf_ringbuf_reserve(&delay_ringbuf, sizeof(*stats), 0);
	if (stats) {
		stats->pid = cur_pid;
		bpf_get_current_comm(stats->comm, sizeof(stats->comm));

		end_ns = bpf_ktime_get_boot_ns();
		stats->delay_ns = end_ns - start_ns;
		stats->ret = ret;
		bpf_ringbuf_submit(stats, 0);
	}

	return 0;
}

SEC("syscall")
int time_call(void *ctx)
{
	__u64 start_ns = 0, end_ns = 0;
	__u64 total_delay = 0, total_iter = 0;
	int i;

	for (i = 0; i < TIME_ROUNDS; i++) {
		start_ns = bpf_ktime_get_boot_ns();
		bpf_loop(TIME_ITER * (i + 1), run_delay, NULL, 0);
		end_ns = bpf_ktime_get_boot_ns();
		total_delay += end_ns - start_ns;
		total_iter += TIME_ITER * (i + 1);
	}
	avg_delay = total_delay / total_iter;

	return 0;
}
