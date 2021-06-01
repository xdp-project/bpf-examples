/* SPDX-License-Identifier: GPL-2.0+ */
//#include "vmlinux.h"

//#include "kernel_headers.h"
#include "vmlinux_local.h"

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#include <bpf/bpf_core_read.h>

#include <bpf/bpf_tracing.h> /* BPF_KPROBE */

#ifndef bpf_target_defined
#warning "Tracing need __TARGET_ARCH_xxx defines"
#endif

char _license[] SEC("license") = "GPL";

struct my_struct {
	int v;
	__u64 m2;
};

struct my_struct G = {};

SEC("kprobe/udp_send_skb")
int BPF_KPROBE(udp_send_skb, struct sk_buff *skb)
// int bpf_prog1(struct pt_regs *ctx, struct sk_buff *skb)
//int bpf_prog1(struct sk_buff *ctx)
{
	// unsigned long rc = 0;
	struct my_struct a;
        int x = 42; //skb->hash;

        BPF_CORE_READ_INTO(&x, skb, hash);

	G.v = 42;

	a.v = bpf_get_prandom_u32() * x;

	// bpf_override_return(ctx, rc);
	if (a.v == 43)
		return 0;
	return G.v;
}

/*
SEC("kprobe/tcp_v6_connect")
int BPF_KPROBE(tcp_v6_connect, struct sock *sk)
{
	return trace_connect(sk);
}
*/
