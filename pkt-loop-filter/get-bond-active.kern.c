/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <linux/bpf.h>
#include <asm/ptrace.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "bpf-defs.h"

int bond_ifindex = 0;
int active_slave_ifindex = 0;
volatile const int netns_cookie = INIT_NS;

SEC("kprobe/bond_select_active_slave")
int BPF_KPROBE(handle_select_slave, struct bonding *bond)
{
        struct net_device *dev = BPF_PROBE_READ(bond, dev);
	struct net *net = BPF_CORE_READ(dev, nd_net.net);
	int ifindex = BPF_CORE_READ(dev, ifindex);
	__u64 cookie = read_net_cookie(net);

        if (cookie == netns_cookie && ifindex == bond_ifindex) {
                struct net_device *active_dev = BPF_PROBE_READ(bond, curr_active_slave, dev);
                active_slave_ifindex = BPF_CORE_READ(active_dev, ifindex);
        }

	return 0;
}

char _license[] SEC("license") = "GPL";
