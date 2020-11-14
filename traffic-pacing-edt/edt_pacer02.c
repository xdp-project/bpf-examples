/* SPDX-License-Identifier: GPL-2.0+ */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <xdp/parsing_helpers.h>
#include "iproute2_compat.h"

char _license[] SEC("license") = "GPL";

#define NS_PER_SEC 1000000000

/* skb->len in bytes, thus easier to keep rate in bytes */
#define RATE_IN_BITS	(1000 * 1000 * 1000)
#define RATE_IN_BYTES	(RATE_IN_BITS / 8)

/* FIXME add proper READ_ONCE / WRITE_ONCE macros, for now use for annotation */
#define READ_ONCE(V)		(V)
#define WRITE_ONCE(X,V)	(X) = (V)

struct edt_val {
	__u64	rate;
	__u64	t_last;
	__u64	t_horizon_drop;
	__u64	t_horizon_ecn;
};

/* The tc tool (iproute2) use another ELF map layout than libbpf (struct
 * bpf_map_def), see struct bpf_elf_map from iproute2.
 */
struct bpf_elf_map SEC("maps") time_delay_map = {
	.type		= BPF_MAP_TYPE_ARRAY,
	.size_key	= sizeof(__u32),
	.size_value	= sizeof(struct edt_val),
	.max_elem	= 1,
	//.pinning	= PIN_GLOBAL_NS,
};

/* Role of EDT (Earliest Departure Time) is to schedule departure of packets to
 * be send in the future.
 */
static __always_inline int sched_departure(struct __sk_buff *skb)
{
	struct edt_val *edt;
	__u64 t_xmit_ns;
	__u64 t_next;
	__u64 t_curr;
	int key = 0;
	__u64 now;

	edt = bpf_map_lookup_elem(&time_delay_map, &key);
	if (!edt)
		return BPF_DROP;

	/* Calc transmission time it takes to send packet 'bytes' */
	t_xmit_ns = ((__u64)skb->len) * NS_PER_SEC / RATE_IN_BYTES;
	// t_xmit_ns = ((__u64)skb->len) * NS_PER_SEC / edt->rate;

	now = bpf_ktime_get_ns();

	/* Allow others to set skb tstamp prior to us */
	t_curr  = skb->tstamp;
	if (t_curr < now)
		t_curr = now;

	/* The 't_last' timestamp can be in the future. Packets scheduled a head
	 * of his packet can be seen as the queue size measured in time, via
	 * correlating this to 'now' timestamp.
	 */
	t_next = READ_ONCE(edt->t_last) + t_xmit_ns;

	/* If packet doesn't get scheduled into the future, then there is
	 * no-queue and we are not above rate limit. Send packet immediately and
	 * move forward t_last timestamp to now.
	 */
	if (t_next <= t_curr) {
		WRITE_ONCE(edt->t_last, t_curr);
		return BPF_OK;
	}

	// TODO Add horizon
	// TODO Add ECN marking horizon

	/* Advance "time queue" */
	WRITE_ONCE(edt->t_last, t_next);

	/* Schedule packet to be send at future timestamp */
	skb->tstamp = t_next;
	return BPF_OK;
}

SEC("classifier") int tc_edt_simple(struct __sk_buff *skb)
{
	volatile void *data, *data_end;
	int ret = BPF_OK;
	struct ethhdr *eth;

	data     = (void *)(long)skb->data;
	data_end = (void *)(long)skb->data_end;
	eth = (struct ethhdr *)data;

	if (data + sizeof(*eth) > data_end)
		return BPF_DROP;

	/* Keep ARP resolution working */
	if (eth->h_proto == bpf_htons(ETH_P_ARP)) {
		ret = BPF_OK;
		goto out;
	}

	// TODO: match on vlan16 and only apply EDT on that
	return sched_departure(skb);

 out:
	return ret;
}
