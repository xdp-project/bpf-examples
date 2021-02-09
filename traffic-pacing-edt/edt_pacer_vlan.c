/* SPDX-License-Identifier: GPL-2.0+ */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/compiler.h>

#include <stdbool.h>

#define VLAN_MAX_DEPTH 2
#include <xdp/parsing_helpers.h>

char _license[] SEC("license") = "GPL";

#define NS_PER_SEC 1000000000

/* Strategy: Shape at MAC (Medium Access Control) layer with Ethernet
 *
 * Production use-case is pacing traffic at 1Gbit/s wirespeed, using a
 * 10Gbit/s NIC, because 1G end-user switch cannot handle bursts.
 *
 *            (https://en.wikipedia.org/wiki/Interpacket_gap
 * 12 bytes = interframe gap (IFG) 96 bit

 *            (https://en.wikipedia.org/wiki/Ethernet_frame)
 *  8 bytes = MAC preamble
 *  4 bytes = Ethernet Frame Check Sequence (FCS) CRC
 * 46 bytes = Minimum Payload size
 *
 * 14 bytes = Ethernet header
 *  8 bytes = 2x VLAN headers
 */
//#define RATE_IN_BITS	(1000 * 1000 * 1000ULL) /* Full 1Gbit/s */
#define RATE_IN_BITS	(990 * 1000 * 1000ULL)
//#define RATE_IN_BITS	(950 * 1000 * 1000ULL)
#define OVERHEAD	(12 + 8 + 4 + 8)  /* 14 already in wire_len */
//#define OVERHEAD	(12 + 8 + 4)      /* 14 already in wire_len */
#define ETH_MIN		(84)

/* skb->len in bytes, thus convert rate to bytes */
#define RATE_IN_BYTES	(RATE_IN_BITS / 8)

/* Controlling how large queue (in time) is allow to grow */
#define T_HORIZON_DROP		(40 * 1000 * 1000ULL)
#define T_HORIZON_TARGET	(5 * 1000 * 1000ULL)
#define T_HORIZON_ECN		(1 * 1000 * 1000ULL)

/* Codel: If queue exceed target for more than one interval, start dropping */
#define T_EXCEED_INTERVAL	(100 * 1000 * 1000ULL) /* 100 ms in ns*/

#define CODEL_TARGET		T_HORIZON_TARGET
#define CODEL_EXCEED_INTERVAL	T_EXCEED_INTERVAL
#include "codel_impl.h"

struct edt_val {
	__u64	rate;
	__u64	t_last;
	__u64	t_horizon_drop;
	__u64	t_horizon_ecn;
	struct codel_state codel;
} __aligned(64); /* Align struct to cache-size to avoid false-sharing */

#ifdef HAVE_TC_LIBBPF /* detected by configure script in config.mk */
/* Use BTF format to create map */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 4096); /* Max possible VLANs */
	__type(key, __u32);
	__type(value, struct edt_val);
//	__uint(pinning, LIBBPF_PIN_BY_NAME);
} time_delay_map SEC(".maps");

#else
/* The (iproute2) tc tool (without libbpf support) use another ELF map
 * layout than libbpf (struct bpf_map_def), see struct bpf_elf_map
 * from iproute2.
 */
#include "iproute2_compat.h"
struct bpf_elf_map SEC("maps") time_delay_map = {
	.type		= BPF_MAP_TYPE_ARRAY,
	.size_key	= sizeof(__u32),
	.size_value	= sizeof(struct edt_val),
	.max_elem	= 4096, /* Max possible VLANs */
//	.pinning	= PIN_GLOBAL_NS,
};
#endif


/* Role of EDT (Earliest Departure Time) is to schedule departure of packets to
 * be send in the future.
 */
static __always_inline int sched_departure(struct __sk_buff *skb, __u32 key)
{
	struct edt_val *edt;
	__u64 rate_in_bytes;
	__u64 t_queue_sz;
	__u64 t_xmit_ns;
	__u64 wire_len;
	__u64 t_next;
	__u64 t_curr;
	__u64 now;

	edt = bpf_map_lookup_elem(&time_delay_map, &key);
	if (!edt)
		return BPF_DROP;

	rate_in_bytes = RATE_IN_BYTES;
	if (edt->rate > 0)
		rate_in_bytes = edt->rate;

	/* Calc transmission time it takes to send packet 'bytes'.
	 *
	 * Details on getting precise bytes on wire.  The skb->len does include
	 * length of GRO/GSO segments, but not the segment headers that gets
	 * added on transmit.  Fortunately skb->wire_len at TC-egress hook (not
	 * ingress) include these headers. (See: qdisc_pkt_len_init())
	 */
	wire_len = skb->wire_len + OVERHEAD;
	wire_len = wire_len > ETH_MIN ? wire_len : ETH_MIN;

	t_xmit_ns = (wire_len) * NS_PER_SEC / rate_in_bytes;

	// now = bpf_ktime_get_ns();
	now = bpf_ktime_get_boot_ns(); /* Use same ktime as bpftrace */

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
	 * no-queue and we are not above rate limit. Normally send packet
	 * immediately and move forward t_last timestamp to now.
	 *
	 * But in our use-case the traffic need smoothing at a earlier
	 * stage, as bursts at lower rates can hurt the crapy switch.
	 * Thus, schedule SKB transmissing as new + t_xmit_ns.
	 */
	if (t_next <= t_curr) {
#if 1
		__u64 t_curr_next;
		__u32 min_len = 1538;

		/* Minimum delay for all packet if no time-queue */
		wire_len = (wire_len > min_len) ?  wire_len : min_len;
		t_xmit_ns = (wire_len) * NS_PER_SEC / rate_in_bytes;
		t_curr_next = t_curr + t_xmit_ns;

		WRITE_ONCE(edt->t_last, t_curr_next);
		skb->tstamp = t_curr_next;
		skb->mark = 1; /* No queue - add minimum delay */
#else
		WRITE_ONCE(edt->t_last, t_curr);
#endif
		return BPF_OK;

	}

	/* Calc queue size measured in time */
	t_queue_sz = t_next - now;

	/* FQ-pacing qdisc also have horizon, but cannot use that, because this
	 * BPF-prog will have updated map (t_last) on packet and assumes it got
	 * its part of bandwidth.
	 */
	if (t_queue_sz >= T_HORIZON_DROP /* edt->t_horizon_drop */)
		return BPF_DROP;

	/* If TCP didn't react to ECN marking, then start dropping some */
	// if (codel_drop(edt, t_queue_sz, now))
	if (codel_drop(&edt->codel, t_queue_sz, t_next))
		return BPF_DROP;

	skb->mark = 2; /* (time) queue exist - and small/below T_HORIZON_ECN */

	/* ECN marking horizon */
	if (t_queue_sz >= T_HORIZON_ECN) {
		skb->mark = 3; /* (time) queue exist - and is large */
		bpf_skb_ecn_set_ce(skb);
	}

	/* Advance "time queue" */
	WRITE_ONCE(edt->t_last, t_next);

	/* Schedule packet to be send at future timestamp */
	skb->tstamp = t_next;
	return BPF_OK;
}

static __always_inline
__u16 get_inner_qinq_vlan(struct __sk_buff *skb, struct collect_vlans *vlans)
{
	__u16 vlan_key;

	/* NIC can HW "offload" the outer VLAN, moving it to skb context */
	if (skb->vlan_present)
		vlan_key = vlans->id[0]; /* Inner vlan placed as first inline */
	else
		vlan_key = vlans->id[1]; /* All VLAN headers inline */

	return vlan_key;
}

static __always_inline
__u16 get_vlan(struct __sk_buff *skb, struct collect_vlans *vlans)
{
	__u16 vlan_key;

	/* Handle extracting VLAN if skb context have VLAN offloaded */
	if (skb->vlan_present)
		vlan_key = skb->vlan_tci & VLAN_VID_MASK;
	else
		vlan_key = vlans->id[0];

	return vlan_key;
}

static __always_inline
__u16 extract_vlan_key(struct __sk_buff *skb, struct collect_vlans *vlans)
{
	int QinQ = 0;

	/* The inner VLAN is the key to extract. But it is complicated
	 * due to NIC "offloaded" VLAN (skb->vlan_present).  In case
	 * BPF-prog is loaded on outer VLAN net_device, the BPF-prog
	 * sees the inner-VLAN at the first and only VLAN.
	 */
	if (skb->vlan_present) {
		if (vlans->id[0])
			QinQ = 1;
	} else {
		if (vlans->id[1])
			QinQ = 1;
	}

	if (QinQ)
		return get_inner_qinq_vlan(skb, vlans);
	else
		return get_vlan(skb, vlans);
}

SEC("classifier") int tc_edt_vlan(struct __sk_buff *skb)
{
	void *data     = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
	struct collect_vlans vlans = { 0 };
	struct ethhdr *eth;
	int ret = BPF_OK;
	__u16 vlan_key;

	/* These keep track of the next header type and iterator pointer */
	struct hdr_cursor nh;
	int eth_type;
	nh.pos = data;

	eth_type = parse_ethhdr_vlan(&nh, data_end, &eth, &vlans);
	if (eth_type < 0)
		return BPF_DROP;

	/* Keep ARP resolution working */
	if (eth_type == bpf_htons(ETH_P_ARP)) {
		ret = BPF_OK;
		goto out;
	}

	if (!proto_is_vlan(eth->h_proto) && !skb->vlan_present) {
		/* Skip non-VLAN frames */
		return BPF_OK;
	}

	vlan_key = extract_vlan_key(skb, &vlans);

	/* Each (inner) VLAN id gets it own EDT pacing */
	return sched_departure(skb, vlan_key);

 out:
	return ret;
}
