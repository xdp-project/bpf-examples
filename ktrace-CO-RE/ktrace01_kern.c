/* SPDX-License-Identifier: GPL-2.0+ */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

char _license[] SEC("license") = "GPL";

struct my_struct {
	int v;
	__u64 m2;
};

SEC("kprobe/open_ctree")
int bpf_prog1(struct pt_regs *ctx)
{
	unsigned long rc = 0;
	struct my_struct a;

        //a.v = 42;

	// bpf_override_return(ctx, rc);
        if (a.v == 43)
                return 0;
	return a.v;
}
