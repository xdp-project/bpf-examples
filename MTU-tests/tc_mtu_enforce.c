/* TC-BPF program that enforce MTU based on BPF-helper
 */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

/* When testing a BPF-helper not upstream yet, it is possible to define
 * its call signature manually, which will only match our devel kernel.
 *
 * Generated signatur via command in kernel devel tree:
 *   ./scripts/bpf_doc.py --header | grep bpf_check_mtu
 */
// Example:
// static long (*bpf_check_mtu)(void *ctx, __u32 ifindex, __u32 *mtu_len, __s32 len_diff, __u64 flags) = (void *) 163;

enum  bpf_check_mtu_flags {
        BPF_MTU_CHK_SEGS  = (1U << 0),
};

SEC("classifier") int tc_check_mtu(struct __sk_buff *skb)
{
	/* Main point behind this test is using flag BPF_MTU_CHK_SEGS,
	 * because is will len check individual GSO/GRO segments in an SKB.
	 * BPF and kernel often skip checks if "skb_is_gso()".
	 */
	__u64 flags = BPF_MTU_CHK_SEGS;
	__u32 mtu_len = 0;
	__s32 delta = 0;

	if (bpf_check_mtu(skb, 0, &mtu_len, delta, flags)) {
		return BPF_DROP;
	}
	return BPF_OK;
}

char _license[] SEC("license") = "GPL";
