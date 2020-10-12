// SPDX-License-Identifier: GPL-2.0

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_trace_helpers.h>
#include  <errno.h>

char _license[] SEC("license") = "GPL";

int seen_pin = 0;

SEC("lsm/bpf")
int BPF_PROG(sys_bpf_hook, int cmd, union bpf_attr *attr, unsigned int size)
{
	/* We need to allow a single pin action to pin ourselves after attach */
	if (cmd == BPF_OBJ_PIN && !seen_pin) {
		seen_pin = 1;
		return 0;
	}
	return -EACCES;
}
