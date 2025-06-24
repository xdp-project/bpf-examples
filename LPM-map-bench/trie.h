/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef TRIE_H
#define TRIE_H

#define MAX_ENTRIES 100000000 // 100 million

struct trie_key {
        __u32 prefixlen;
        __u32 data;
};

struct latency_record {
	// map name
	char name[BPF_OBJ_NAME_LEN];
	// number of entries in map
	unsigned int n_entries;
	// duration (ns) of trie_free()
	__u64 val;
};

#endif
