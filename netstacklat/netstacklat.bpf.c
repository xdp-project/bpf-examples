/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "vmlinux_local.h"
#include <linux/bpf.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "netstacklat.h"
#include "bits.bpf.h"

#define READ_ONCE(x) (*(volatile typeof(x) *)&(x))

// Mimic macros from /include/net/tcp.h
#define tcp_sk(ptr) container_of(ptr, struct tcp_sock, inet_conn.icsk_inet.sk)
#define TCP_SKB_CB(__skb)	((struct tcp_skb_cb *)&((__skb)->cb[0]))

char LICENSE[] SEC("license") = "GPL";


volatile const __s64 TAI_OFFSET = (37LL * NS_PER_S);
volatile const struct netstacklat_bpf_config user_config = {
	.network_ns = 0,
	.filter_min_sockqueue_len = 0, /* zero means filter is inactive */
	.filter_pid = false,
	.filter_ifindex = false,
	.filter_cgroup = false,
	.groupby_ifindex = false,
	.groupby_cgroup = false,
	.include_hol_blocked = false,
};

/*
 * Alternative definition of sk_buff to handle renaming of the field
 * mono_delivery_time to tstamp_type. See
 * https://nakryiko.com/posts/bpf-core-reference-guide/#handling-incompatible-field-and-type-changes
 */
struct sk_buff___old {
	union {
		ktime_t tstamp;
		u64 skb_mstamp_ns;
	};
	__u8 mono_delivery_time: 1;
} __attribute__((preserve_access_index));

struct tcp_sock_ooo_range {
	struct bpf_spin_lock lock;
	u32 ooo_seq_end;
	/* indicates if ooo_seq_end is still valid (as 0 can be valid seq) */
	bool active;
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_HASH);
	__uint(max_entries, HIST_NBUCKETS * NETSTACKLAT_N_HOOKS * 64);
	__type(key, struct hist_key);
	__type(value, u64);
} netstack_latency_seconds SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, PID_MAX_LIMIT + 1);
	__type(key, u32);
	__type(value, u64);
} netstack_pidfilter SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, IFINDEX_MAX + 1);
	__type(key, u32);
	__type(value, u64);
} netstack_ifindexfilter SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_PARSED_CGROUPS);
	__type(key, u64);
	__type(value, u64);
} netstack_cgroupfilter SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_SK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct tcp_sock_ooo_range);
} netstack_tcp_ooo_range SEC(".maps");

/*
 * Is a < b considering u32 wrap around?
 * Based on the before() function in /include/net/tcp.h
 */
static bool u32_lt(u32 a, u32 b)
{
	return (s32)(a - b) < 0;
}

static u64 *lookup_or_zeroinit_histentry(void *map, const struct hist_key *key)
{
	u64 zero = 0;
	u64 *val;

	val = bpf_map_lookup_elem(map, key);
	if (val)
		return val;

	// Key not in map - try insert it and lookup again
	bpf_map_update_elem(map, key, &zero, BPF_NOEXIST);
	return bpf_map_lookup_elem(map, key);
}

static u32 get_exp2_histogram_bucket_idx(u64 value, u32 max_bucket)
{
	u32 bucket = log2l(value);

	// Right-inclusive histogram, so "round up" the log value
	if (bucket > 0 && 1ULL << bucket < value)
		bucket++;

	if (bucket > max_bucket)
		bucket = max_bucket;

	return bucket;
}

/*
 * Same call signature as the increment_exp2_histogram_nosync macro from
 * https://github.com/cloudflare/ebpf_exporter/blob/master/examples/maps.bpf.h
 * but provided as a function.
 *
 * Unlike the macro, only works with keys of type struct hist_key. The hist_key
 * struct must be provided by value (rather than as a pointer) to keep the same
 * call signature as the ebpf-exporter macro, although this will get inefficent
 * if struct hist_key grows large.
 */
static void increment_exp2_histogram_nosync(void *map, struct hist_key key,
					    u64 value, u32 max_bucket)
{
	u64 *bucket_count;

	// Increment histogram
	key.bucket = get_exp2_histogram_bucket_idx(value, max_bucket);
	bucket_count = lookup_or_zeroinit_histentry(map, &key);
	if (bucket_count)
		(*bucket_count)++;

	// Increment sum at end of histogram
	if (value == 0)
		return;

	key.bucket = max_bucket + 1;
	bucket_count = lookup_or_zeroinit_histentry(map, &key);
	if (bucket_count)
		*bucket_count += value;
}

static ktime_t time_since(ktime_t tstamp)
{
	ktime_t now;

	if (tstamp <= 0)
		return -1;

	now = bpf_ktime_get_tai_ns() - TAI_OFFSET;
	if (tstamp > now)
		return -1;

	return now - tstamp;
}

static void record_latency(ktime_t latency, const struct hist_key *key)
{
	increment_exp2_histogram_nosync(&netstack_latency_seconds, *key, latency,
					HIST_MAX_LATENCY_SLOT);
}

static void record_latency_since(ktime_t tstamp, const struct hist_key *key)
{
	ktime_t latency = time_since(tstamp);
	if (latency >= 0)
		record_latency(latency, key);
}

static bool filter_ifindex(u32 ifindex)
{
	u64 *ifindex_ok;

	if (!user_config.filter_ifindex)
		// No ifindex filter - all ok
		return true;

	ifindex_ok = bpf_map_lookup_elem(&netstack_ifindexfilter, &ifindex);
	if (!ifindex_ok)
		return false;

	return *ifindex_ok > 0;
}

static __u64 get_network_ns(struct sk_buff *skb, struct sock *sk)
{
	/*
	 * Favor reading from sk due to less redirection (fewer probe reads)
	 * and skb->dev is not always set.
	 */
	if (sk)
		return BPF_CORE_READ(sk->__sk_common.skc_net.net, ns.inum);
	else if (skb)
		return BPF_CORE_READ(skb->dev, nd_net.net, ns.inum);
	return 0;
}

static bool filter_network_ns(struct sk_buff *skb, struct sock *sk)
{
	if (user_config.network_ns == 0)
		return true;

	return get_network_ns(skb, sk) == user_config.network_ns;
}

static bool filter_network(struct sk_buff *skb, struct sock *sk)
{
	if (!filter_ifindex(skb ? skb->skb_iif : sk ? sk->sk_rx_dst_ifindex : 0))
		return false;

	return filter_network_ns(skb, sk);
}

static void record_skb_latency(struct sk_buff *skb, struct sock *sk, enum netstacklat_hook hook)
{
	struct hist_key key = { .hook = hook };

	if (bpf_core_field_exists(skb->tstamp_type)) {
		/*
		 * For kernels >= v6.11 the tstamp_type being non-zero
		 * (SKB_CLOCK_REALTIME) implies that skb->tstamp holds a
		 * preserved TX timestamp rather than a RX timestamp. See
		 * https://lore.kernel.org/all/20240509211834.3235191-2-quic_abchauha@quicinc.com/
		 */
		if (BPF_CORE_READ_BITFIELD(skb, tstamp_type) > 0)
			return;

	} else {
		/*
		 * For kernels < v6.11, the field was called mono_delivery_time
		 * instead, see https://lore.kernel.org/all/20220302195525.3480280-1-kafai@fb.com/
		 * Kernels < v5.18 do not have the mono_delivery_field either,
		 * but we do not support those anyways (as they lack the
		 * bpf_ktime_get_tai_ns helper)
		 */
		struct sk_buff___old *skb_old = (void *)skb;
		if (BPF_CORE_READ_BITFIELD(skb_old, mono_delivery_time) > 0)
			return;
	}

	if (!filter_network(skb, sk))
		return;

	if (user_config.groupby_ifindex)
		key.ifindex = skb->skb_iif;

	record_latency_since(skb->tstamp, &key);
}

static bool filter_pid(u32 pid)
{
	u64 *pid_ok;

	if (!user_config.filter_pid)
		// No PID filter - all PIDs ok
		return true;

	pid_ok = bpf_map_lookup_elem(&netstack_pidfilter, &pid);
	if (!pid_ok)
		return false;

	return *pid_ok > 0;
}

static bool filter_cgroup(u64 cgroup_id)
{
	if (!user_config.filter_cgroup)
		// No cgroup filter - all cgroups ok
		return true;

	return bpf_map_lookup_elem(&netstack_cgroupfilter, &cgroup_id) != NULL;
}

static bool filter_current_task(u64 cgroup)
{
	bool ok = true;
	__u32 tgid;

	if (user_config.filter_pid) {
		tgid = bpf_get_current_pid_tgid() >> 32;
		ok = ok && filter_pid(tgid);
	}

	if (user_config.filter_cgroup)
		ok = ok && filter_cgroup(cgroup);

	return ok;
}

static __u32 sk_queue_len(const struct sk_buff_head *list)
{
	return READ_ONCE(list->qlen);
}

static bool sk_backlog_empty(const struct sock *sk)
{
	return READ_ONCE(sk->sk_backlog.tail) == NULL;
}

static bool filter_min_sockqueue_len(struct sock *sk)
{
	const u32 min_qlen = user_config.filter_min_sockqueue_len;

	if (min_qlen == 0)
		return true;

	if (sk_queue_len(&sk->sk_receive_queue) >= min_qlen)
		return true;

	/* Packets can also be on the sk_backlog, but we don't know the number
	 * of SKBs on the queue, because sk_backlog.len is in bytes (based on
	 * skb->truesize).  Thus, if any backlog exists we don't filter.
	 */
	if (!sk_backlog_empty(sk))
		return true;

	return false;
}

static void record_socket_latency(struct sock *sk, struct sk_buff *skb,
				  ktime_t tstamp, enum netstacklat_hook hook)
{
	struct hist_key key = { .hook = hook };
	u64 cgroup = 0;

	if (!filter_min_sockqueue_len(sk))
		return;

	if (user_config.filter_cgroup || user_config.groupby_cgroup)
		cgroup = bpf_get_current_cgroup_id();

	if (!filter_current_task(cgroup))
		return;

	if (!filter_network(skb, sk))
		return;

	if (user_config.groupby_ifindex)
		key.ifindex = skb ? skb->skb_iif : sk->sk_rx_dst_ifindex;
	if (user_config.groupby_cgroup)
		key.cgroup = cgroup;

	record_latency_since(tstamp, &key);
}

static void tcp_update_ooo_range(struct sock *sk, struct sk_buff *skb)
{
	struct tcp_sock_ooo_range *tp_ooo_range;

	tp_ooo_range = bpf_sk_storage_get(&netstack_tcp_ooo_range, sk, NULL,
					  BPF_SK_STORAGE_GET_F_CREATE);
	if (!tp_ooo_range)
		return;

	bpf_spin_lock(&tp_ooo_range->lock);
	if (tp_ooo_range->active) {
		if (u32_lt(tp_ooo_range->ooo_seq_end, TCP_SKB_CB(skb)->end_seq))
			tp_ooo_range->ooo_seq_end = TCP_SKB_CB(skb)->end_seq;
	} else {
		tp_ooo_range->ooo_seq_end = TCP_SKB_CB(skb)->end_seq;
		tp_ooo_range->active = true;
	}
	bpf_spin_unlock(&tp_ooo_range->lock);

}

static bool tcp_read_in_ooo_range(struct sock *sk)
{
	struct tcp_sock_ooo_range *tp_ooo_range;
	struct tcp_sock *tp = tcp_sk(sk);
	u32 last_read_seq;
	bool ret;
	int err;

	tp_ooo_range = bpf_sk_storage_get(&netstack_tcp_ooo_range, sk, NULL, 0);
	if (!tp_ooo_range)
                /* no recorded ooo-range for sock, so cannot be in ooo-range */
		return false;

	err = bpf_core_read(&last_read_seq, sizeof(last_read_seq), &tp->copied_seq);
	if (err) {
		/*
		 * Shouldn't happen.
		 * Should probably emit some warning if reading copied_seq
		 * unexpectedly fails. Assume not in ooo-range to avoid
		 * systematically filtering out ALL values if this does happen.
		 */
		bpf_printk("failed to read tcp_sock->copied_seq: err=%d", err);
		return false;
	}

	bpf_spin_lock(&tp_ooo_range->lock);
	if (!tp_ooo_range->active) {
		ret = false;
	} else {
		if (u32_lt(tp_ooo_range->ooo_seq_end, last_read_seq)) {
			tp_ooo_range->active = false;
			ret = false;
		} else {
			ret = true;
		}
	}

	bpf_spin_unlock(&tp_ooo_range->lock);
	return ret;
}

SEC("fentry/ip_rcv_core")
int BPF_PROG(netstacklat_ip_rcv_core, struct sk_buff *skb, void *block,
	     void *tp, void *res, bool compat_mode)
{
	record_skb_latency(skb, NULL, NETSTACKLAT_HOOK_IP_RCV);
	return 0;
}

SEC("fentry/ip6_rcv_core")
int BPF_PROG(netstacklat_ip6_rcv_core, struct sk_buff *skb, void *block,
	     void *tp, void *res, bool compat_mode)
{
	record_skb_latency(skb, NULL, NETSTACKLAT_HOOK_IP_RCV);
	return 0;
}

SEC("fentry/tcp_v4_rcv")
int BPF_PROG(netstacklat_tcp_v4_rcv, struct sk_buff *skb)
{
	record_skb_latency(skb, NULL, NETSTACKLAT_HOOK_TCP_START);
	return 0;
}

SEC("fentry/tcp_v6_rcv")
int BPF_PROG(netstacklat_tcp_v6_rcv, struct sk_buff *skb)
{
	record_skb_latency(skb, NULL, NETSTACKLAT_HOOK_TCP_START);
	return 0;
}

SEC("fentry/udp_rcv")
int BPF_PROG(netstacklat_udp_rcv, struct sk_buff *skb)
{
	record_skb_latency(skb, NULL, NETSTACKLAT_HOOK_UDP_START);
	return 0;
}

SEC("fentry/udpv6_rcv")
int BPF_PROG(netstacklat_udpv6_rcv, struct sk_buff *skb)
{
	record_skb_latency(skb, NULL, NETSTACKLAT_HOOK_UDP_START);
	return 0;
}

SEC("fexit/tcp_queue_rcv")
int BPF_PROG(netstacklat_tcp_queue_rcv, struct sock *sk, struct sk_buff *skb)
{
	record_skb_latency(skb, sk, NETSTACKLAT_HOOK_TCP_SOCK_ENQUEUED);
	return 0;
}

SEC("fexit/__udp_enqueue_schedule_skb")
int BPF_PROG(netstacklat_udp_enqueue_schedule_skb, struct sock *sk,
	     struct sk_buff *skb, int retval)
{
	if (retval == 0)
		record_skb_latency(skb, sk, NETSTACKLAT_HOOK_UDP_SOCK_ENQUEUED);
	return 0;
}

SEC("fentry/tcp_recv_timestamp")
int BPF_PROG(netstacklat_tcp_recv_timestamp, void *msg, struct sock *sk,
	     struct scm_timestamping_internal *tss)
{
	struct timespec64 *ts = &tss->ts[0];

	/* skip if preceeding sock read ended in ooo-range */
	if (!user_config.include_hol_blocked && tcp_read_in_ooo_range(sk))
		return 0;

	record_socket_latency(sk, NULL,
			      (ktime_t)ts->tv_sec * NS_PER_S + ts->tv_nsec,
			      NETSTACKLAT_HOOK_TCP_SOCK_READ);
	return 0;
}

SEC("fentry/skb_consume_udp")
int BPF_PROG(netstacklat_skb_consume_udp, struct sock *sk, struct sk_buff *skb,
	     int len)
{
	record_socket_latency(sk, skb, skb->tstamp,
			      NETSTACKLAT_HOOK_UDP_SOCK_READ);
	return 0;
}

/* This program should also be disabled if tcp-socket-read is disabled */
SEC("fentry/tcp_data_queue_ofo")
int BPF_PROG(netstacklat_tcp_data_queue_ofo, struct sock *sk,
	     struct sk_buff *skb)
{
	if (user_config.include_hol_blocked)
		/*
		 * It's better to not load this program at all if the ooo-range
		 * tracking isn't needed (like done by netstacklat.c).
		 * But if an external loader (like ebpf-exporter) is used,
		 * this should at least minimze the unncecessary overhead.
		 */
		return 0;

	if (!filter_network(skb, sk))
		return 0;

	tcp_update_ooo_range(sk, skb);
	return 0;
}
