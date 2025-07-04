/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h> /* CO-RE */
#include <bpf/bpf_tracing.h>

#include "trie.h"

char LICENSE[] SEC("license") = "GPL";

struct bpf_map___local {
	char name[BPF_OBJ_NAME_LEN];
} __attribute__((preserve_access_index));

struct lpm_trie___local {
	struct bpf_map___local map;
	unsigned int n_entries;
} __attribute__((preserve_access_index));

struct {
        __uint(type, BPF_MAP_TYPE_HASH);
        __uint(max_entries, 512);
        __type(key, struct bpf_map___local *);
        __type(value, struct latency_record);
} latency_start SEC(".maps");

struct {
        __uint(type, BPF_MAP_TYPE_HASH);
        __uint(max_entries, 512);
        __type(key, struct bpf_map___local *);
        __type(value, struct latency_record);
} latencies SEC(".maps");

SEC("fentry/trie_free")
int BPF_PROG(trie_free_entry, struct bpf_map___local *map)
{
	char *name = BPF_CORE_READ(map, name);
	struct latency_record r = {
		.val = bpf_ktime_get_ns(),
	};
	int i;
	struct lpm_trie___local *trie;

	/*
	 * Ideally we'd have access to the map ID but that's already
	 * freed before we enter trie_free().
	 */
	for (i = 0; i < BPF_OBJ_NAME_LEN; i++) {
		r.name[i] = name[i];
	}

	trie = container_of(map, struct lpm_trie___local, map);
	r.n_entries = BPF_CORE_READ(trie, n_entries);

	bpf_map_update_elem(&latency_start, &map, &r, BPF_ANY);
	return 0;
}

SEC("fexit/trie_free")
int BPF_PROG(trie_free_exit, struct bpf_map___local *map)
{
	struct latency_record *r;

	r = bpf_map_lookup_elem(&latency_start, &map);
	if (r) {
		/*
		 * Convert the record's start time into a latency result and
		 * copy it to the latencies map.
		 */
		__u64 delta_ns = bpf_ktime_get_ns() - r->val;
		r->val = delta_ns;

		bpf_map_update_elem(&latencies, &map, r, BPF_ANY);
		bpf_map_delete_elem(&latency_start, &map);
	}

        return 0;
}
