/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef __PPING_DEBUG_CLEANUP_H
#define __PPING_DEBUG_CLEANUP_H

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "pping.h"

/*
 * Structs and functions that are only used for tracking the cleanup of the
 * packet timestamp and flow state maps.

 * Structs and contents of functions are guarded by ifdef DEBUGs to minimze
 * overhead, and kept in this file to keep the normal pping-related code
 * cleaner.
 */

#ifdef DEBUG

/*
 * Global entries with cleanup stats for each map (PPING_MAP_PACKETTS and
 * PPING_MAP_FLOWSTATE). The last_* members keep track of how many entries
 * that are deleted in the current cleaning cycle and are updated continuiously,
 * whereas the tot_* entries keeps the cumulative stats but are only updated at
 * the end of the current cleaning cycle.
 */

struct map_clean_stats {
	__u64 start_time;
	__u64 tot_runtime;
	__u64 tot_processed_entries;
	__u64 tot_timeout_del;
	__u64 tot_auto_del;
	__u64 last_runtime;
	__u32 last_processed_entries;
	__u32 last_timeout_del;
	__u32 last_auto_del;
	__u32 clean_cycles;
};

static volatile struct map_clean_stats clean_stats[2] = { 0 };

#endif


static __always_inline void debug_increment_autodel(enum pping_map map)
{
#ifdef DEBUG
	clean_stats[map].last_auto_del += 1;
#endif
}

static __always_inline void debug_increment_timeoutdel(enum pping_map map)
{
#ifdef DEBUG
	clean_stats[map].last_timeout_del += 1;
#endif
}

#ifdef DEBUG
static __always_inline void
send_map_clean_event(void *ctx, void *perf_buffer,
		     volatile const struct map_clean_stats *map_stats,
		     __u64 now, enum pping_map map)
{
	struct map_clean_event mce = {
		.event_type = EVENT_TYPE_MAP_CLEAN,
		.timestamp = now,
		.tot_timeout_del = map_stats->tot_timeout_del,
		.tot_auto_del = map_stats->tot_auto_del,
		.tot_processed_entries = map_stats->tot_processed_entries,
		.tot_runtime = map_stats->tot_runtime,
		.last_timeout_del = map_stats->last_timeout_del,
		.last_auto_del = map_stats->last_auto_del,
		.last_processed_entries = map_stats->last_processed_entries,
		.last_runtime = map_stats->last_runtime,
		.clean_cycles = map_stats->clean_cycles,
		.map = map,
		.reserved = { 0 }
	};

	bpf_perf_event_output(ctx, perf_buffer, BPF_F_CURRENT_CPU, &mce,
			      sizeof(mce));
}
#endif

static __always_inline void
debug_update_mapclean_stats(void *ctx, void *perf_buffer, bool final,
			    __u64 seq_num, __u64 time, enum pping_map map)
{
#ifdef DEBUG
	volatile struct map_clean_stats *map_stats = &clean_stats[map];

	if (final) { // post final entry
		if (map_stats->start_time) { // Non-empty map
			map_stats->last_processed_entries = seq_num + 1;
			map_stats->last_runtime = time - map_stats->start_time;
		} else {
			map_stats->last_processed_entries = 0;
			map_stats->last_runtime = 0;
		}

		//update totals
		map_stats->tot_runtime += map_stats->last_runtime;
		map_stats->tot_processed_entries +=
			map_stats->last_processed_entries;
		map_stats->tot_timeout_del += map_stats->last_timeout_del;
		map_stats->tot_auto_del += map_stats->last_auto_del;
		map_stats->clean_cycles += 1;

		send_map_clean_event(ctx, perf_buffer, map_stats, time, map);

		// Reset for next clean cycle
		map_stats->start_time = 0;
		map_stats->last_timeout_del = 0;
		map_stats->last_auto_del = 0;

	} else if (seq_num == 0) { // mark first entry
		map_stats->start_time = time;
	}
#endif
}

#endif
