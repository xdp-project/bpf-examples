/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <iproute2/bpf_elf.h>

#include "pping.h"
#include "pping_helpers.h"

#define RATE_LIMIT                                                             \
	100000000UL // 100ms. Temporary solution, should be set by userspace
#define BURST_DURATION                                                         \
	4000000 // 4ms, duration for when it may burst packet timestamps
#define BURST_SIZE                                                             \
	3 // Number of packets it may create timestamps for in a burst

char _license[] SEC("license") = "GPL";

#ifdef HAVE_TC_LIBBPF /* detected by configure script in config.mk */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(key_size, sizeof(struct packet_id));
	__uint(value_size, sizeof(__u64));
	__uint(max_entries, 16384);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} ts_start SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(key_size, sizeof(struct network_tuple));
	__uint(value_size, sizeof(struct flow_state));
	__uint(max_entries, 16384);
} flow_state SEC(".maps");

#else
struct bpf_elf_map SEC("maps") ts_start = {
	.type = BPF_MAP_TYPE_HASH,
	.size_key = sizeof(struct packet_id),
	.size_value = sizeof(__u64),
	.max_elem = 16384,
	.pinning = PIN_GLOBAL_NS,
};

struct bpf_elf_map SEC("maps") flow_state = {
	.type = BPF_MAP_TYPE_HASH,
	.size_key = sizeof(struct network_tuple),
	.size_value = sizeof(struct flow_state),
	.max_elem = 16384,
};
#endif

// TC-BFP for parsing packet identifier from egress traffic and add to map
SEC(TCBPF_PROG_SEC)
int tc_bpf_prog_egress(struct __sk_buff *skb)
{
	struct packet_id p_id = { 0 };
	__u64 p_ts;
	struct parsing_context pctx = {
		.data = (void *)(long)skb->data,
		.data_end = (void *)(long)skb->data_end,
		.pkt_len = skb->len,
		.nh = { .pos = pctx.data },
	};
	struct flow_state *f_state;
	struct flow_state new_state = { 0 }; // Rarely-ish used, but can't really dynamically allocate memory or?

	if (parse_packet_identifier(&pctx, true, &p_id) < 0)
		goto end;

	// Check flow state
	f_state = bpf_map_lookup_elem(&flow_state, &p_id.flow);
	if (!f_state) { // No previous state - attempt to create it
		bpf_map_update_elem(&flow_state, &p_id.flow, &new_state,
				    BPF_NOEXIST);
		f_state = bpf_map_lookup_elem(&flow_state, &p_id.flow);
		if (!f_state)
			goto end;
	}

	// Check if identfier is new
	/* The gap between checking and updating last_id may cause concurrency
	 * issues where multiple packets may simultaneously think they are the
	 * first with a new identifier. As long as all of the identifiers are
	 * the same though, only one should be able to create a timestamp entry.

	 * A bigger issue is that older identifiers (for example due to
         * out-of-order packets) may pass this check and update the current
	 * identifier to an old one. This means that both the packet with the
	 * old identifier itself, as well the next packet with the current
	 * identifier, may be considered packets with new identifiers (even if
	 * both have been seen before). For TCP timestamps this could be
	 * prevented by changing the check to '>=' instead, but it may not be
	 * suitable for other protocols, such as QUIC and its spinbit.
	 *
	 * For now, just hope that the rate limit saves us from creating an
	 * incorrect timestamp. That may however also fail, either due to the
	 * to it happening in a time it's not limited by rate sampling, or
	 * because of rate check failing due to concurrency issues.
	 */
	if (f_state->last_id == p_id.identifier)
		goto end;
	f_state->last_id = p_id.identifier;

	// Check rate-limit
	/*
	 * The window between checking and updating last_timestamp may cause
	 * concurrency issues, where multiple packets simultaneously pass the
	 * rate limit. However, as long as they have the same identifier, only
	 * a single timestamp entry should successfully be created.
	 */
	p_ts = bpf_ktime_get_ns(); // or bpf_ktime_get_boot_ns
	if (p_ts < f_state->last_timestamp ||
	    p_ts - f_state->last_timestamp < RATE_LIMIT)
		goto end;

	/*
	 * Updates attempt at creating timestamp, even if creation of timestamp
	 * fails (due to map being full). This should make the competition for
	 * the next available map slot somewhat fairer between heavy and sparse
	 * flows.
	 */
	f_state->last_timestamp = p_ts;
	bpf_map_update_elem(&ts_start, &p_id, &p_ts, BPF_NOEXIST);

end:
	return BPF_OK;
}
