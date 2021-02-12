/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#include "pping.h"
#include "pping_helpers.h"

char _license[] SEC("license") = "GPL";

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(key_size, sizeof(struct packet_id));
	__uint(value_size, sizeof(struct packet_timestamp));
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
	struct packet_timestamp *p_ts;
	struct rtt_event event = { 0 };

	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;

	if (parse_packet_identifier(data, data_end, false, &p_id) < 0)
		goto end;

	p_ts = bpf_map_lookup_elem(&ts_start, &p_id);

	// Only calculate RTT for first packet with matching identifer
	if (p_ts && p_ts->used == 0) {
		/*
		 * As used is not set atomically with the lookup, could 
		 * potentially have multiple "first" packets (on different 
		 * CPUs), but all those should then also have very similar RTT,
		 * so don't consider it a significant issue
		 */
		p_ts->used = 1;
		// TODO - Optional delete of entry (if identifier is garantued unique)

		__builtin_memcpy(&event.flow, &p_id.flow,
				 sizeof(struct network_tuple));
		event.rtt = bpf_ktime_get_ns() - p_ts->timestamp;
		bpf_perf_event_output(ctx, &rtt_events, BPF_F_CURRENT_CPU,
				      &event, sizeof(event));
	}

end:
	return XDP_PASS;
}
