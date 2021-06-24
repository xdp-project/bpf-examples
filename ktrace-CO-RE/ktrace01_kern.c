/* SPDX-License-Identifier: GPL-2.0+ */

#include "vmlinux_local.h"

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#include <bpf/bpf_core_read.h> /* CO-RE */
#include <bpf/bpf_tracing.h> /* BPF_KPROBE */

#ifndef bpf_target_defined
#warning "Tracing need __TARGET_ARCH_xxx defines"
#endif

char _license[] SEC("license") = "GPL";

/* define our own struct definition if our vmlinux.h is outdated */
struct trace_event_raw_bpf_trace_printk___x {};

/* https://nakryiko.com/posts/bpf-tips-printk/ */
#undef  bpf_printk  // See /usr/include/bpf/bpf_helpers.h
#define bpf_printk(fmt, ...)					\
 ({								\
	static char ____fmt[] = fmt "\0";				\
	if (0 /* bpf_core_type_exists( struct trace_event_raw_bpf_trace_printk___x)*/) { \
		bpf_trace_printk(____fmt, sizeof(____fmt) - 1, ##__VA_ARGS__); \
	} else {							\
		____fmt[sizeof(____fmt) - 2] = '\n';			\
		bpf_trace_printk(____fmt, sizeof(____fmt), ##__VA_ARGS__); \
	}								\
 })
/* Gotcha: bpf_core_type_exists() needs __builtin_preserve_type_info */

SEC("kprobe/udp_send_skb")
int BPF_KPROBE(udp_send_skb, struct sk_buff *skb)
//int udp_send_skb(struct pt_regs *ctx)
{
	unsigned int len;
	__u32 h;

	BPF_CORE_READ_INTO(&h,    skb, hash);		/* skb->hash */
	BPF_CORE_READ_INTO(&len,  skb, len);		/* skb->len */

	bpf_printk("skb->hash=0x%x len=%d", h, len);

	return 0;
}
