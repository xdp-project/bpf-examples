/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <iproute2/bpf_elf.h>

#include "pping.h"
#include "pping_helpers.h"

char _license[] SEC("license") = "GPL";

#ifdef HAVE_TC_LIBBPF /* detected by configure script in config.mk */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(key_size, sizeof(struct packet_id));
	__uint(value_size, sizeof(struct packet_timestamp));
	__uint(max_entries, 16384);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} ts_start SEC(".maps");

#else
struct bpf_elf_map SEC("maps") ts_start = {
	.type = BPF_MAP_TYPE_HASH,
	.size_key = sizeof(struct packet_id),
	.size_value = sizeof(struct packet_timestamp),
	.max_elem = 16384,
	.pinning = PIN_GLOBAL_NS,
};
#endif

// TC-BFP for parsing packet identifier from egress traffic and add to map
SEC(TCBPF_PROG_SEC)
int tc_bpf_prog_egress(struct __sk_buff *skb)
{
	struct parsing_context pctx;
	struct packet_id p_id = { 0 };
	struct packet_timestamp p_ts = { 0 };

	pctx.data = (void *)(long)skb->data;
	pctx.data_end = (void *)(long)skb->data_end;
	pctx.data_end_end = pctx.data + skb->len;
	pctx.nh.pos = pctx.data;

	if (parse_packet_identifier(&pctx, true, &p_id) < 0)
		goto end;

	p_ts.timestamp = bpf_ktime_get_ns(); // or bpf_ktime_get_boot_ns
	bpf_map_update_elem(&ts_start, &p_id, &p_ts, BPF_NOEXIST);

end:
	return BPF_OK;
}
