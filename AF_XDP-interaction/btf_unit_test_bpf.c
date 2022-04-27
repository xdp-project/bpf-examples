/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#include <bpf/bpf_core_read.h> /* bpf_core_type_id_local */

/*
 * The xdp_hints_xxx struct's are stored in the XDP 'data_meta' area,
 * which is located just in-front-of the raw packet payload data.
 *
 * Explaining the struct attribute's:
 * ----------------------------------
 * The struct must be 4 byte aligned (kernel requirement), which here
 * is enforced by the struct __attribute__((aligned(4))).
 *
 * To avoid any C-struct padding attribute "packed" is used.
 *
 * NOTICE: Do NOT define __attribute__((preserve_access_index)) here,
 * as libbpf will try to find a matching kernel data-structure,
 * e.g. it will cause BPF-prog loading step to fail (with invalid func
 * unknown#195896080 which is 0xbad2310 in hex for "bad relo").
 */

struct xdp_hints_fail001 {
	__u64 hash64;
	__u32 btf_id;
	__u32 pad; /* Pad that breaks btf_id as last member */
} __attribute__((aligned(4))) __attribute__((packed));

/* Notice struct is without attribute "packed", thus (64-bit) C-compiler will
 * add padding.  This will cause btf_id to NOT be the last member (which is a
 * requirement).
 */
struct xdp_hints_fail002 {
	__u64 hash64;
	__u32 btf_id;
} __attribute__((aligned(4))) /* not packed */;


SEC("xdp")
int xdp_prog_fail001(struct xdp_md *ctx)
{
	struct xdp_hints_fail001 *meta;
	void *data;
	int err;

	err = bpf_xdp_adjust_meta(ctx, -(int)sizeof(*meta));
	if (err)
		return XDP_ABORTED;

	data = (void *)(unsigned long)ctx->data;
	meta = (void *)(unsigned long)ctx->data_meta;
	if (meta + 1 > data) /* Verify meta area is accessible */
		return XDP_ABORTED;

	meta->btf_id = bpf_core_type_id_local(struct xdp_hints_fail001);
	meta->hash64 = 0x4142434445464748;

	return XDP_PASS;
}

SEC("xdp")
int xdp_prog_fail002(struct xdp_md *ctx)
{
	struct xdp_hints_fail002 f002;
	f002.btf_id = bpf_core_type_id_local(struct xdp_hints_fail002);
	if (f002.btf_id == 0)
		return XDP_ABORTED;

	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
