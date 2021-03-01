/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#include "pping.h"
#include "pping_helpers.h"

char _license[] SEC("license") = "GPL";

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(key_size, sizeof(struct packet_id));
	__uint(value_size, sizeof(__u64));
	__uint(max_entries, 16384);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} ts_start SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u32));
} rtt_events SEC(".maps");

// XDP program for parsing identifier in ingress traffic and check for match in map
SEC(XDP_PROG_SEC)
int xdp_prog_ingress(struct xdp_md *ctx)
{
	struct packet_id p_id = { 0 };
	__u64 *p_ts;
	struct rtt_event event = { 0 };
	struct parsing_context pctx = {
		.data = (void *)(long)ctx->data,
		.data_end = (void *)(long)ctx->data_end,
		.pkt_len = pctx.data_end - pctx.data,
		.nh = { .pos = pctx.data },
	};

	if (parse_packet_identifier(&pctx, false, &p_id) < 0)
		goto end;

	p_ts = bpf_map_lookup_elem(&ts_start, &p_id);
	if (!p_ts)
		goto end;

	event.rtt = bpf_ktime_get_ns() - *p_ts;
	/*
	 * Attempt to delete timestamp entry as soon as RTT is calculated.
	 * But could have potential concurrency issue where multiple packets
	 * manage to match against the identifier before it can be deleted.
	 */
	bpf_map_delete_elem(&ts_start, &p_id);

	__builtin_memcpy(&event.flow, &p_id.flow, sizeof(struct network_tuple));
	bpf_perf_event_output(ctx, &rtt_events, BPF_F_CURRENT_CPU, &event,
			      sizeof(event));

end:
	return XDP_PASS;
}
