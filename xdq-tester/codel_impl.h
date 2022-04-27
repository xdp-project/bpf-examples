#include <stdbool.h>

#ifndef __CODEL_IMPL_H
#define __CODEL_IMPL_H

#ifndef CODEL_TARGET
#define CODEL_TARGET (10 * 1000 * 1000ULL) /* 10 ms in nanosec */
#endif

#ifndef CODEL_EXCEED_INTERVAL
#define CODEL_EXCEED_INTERVAL	(100 * 1000 * 1000ULL) /* 100 ms in ns*/
#endif

/* Codel like dropping scheme, inspired by:
 * - RFC:  https://queue.acm.org/detail.cfm?id=2209336
 * - Code: https://queue.acm.org/appendices/codel.html
 * - Kernel: include/net/codel_impl.h
 */
struct codel_state {
	/* codel like dropping scheme */
	__u64	first_above_time; /* Time when above target (0 if below)*/
	__u64	drop_next;	  /* Time to drop next packet */
	__u32	count;	/* Packets dropped since going into drop state */
	__u32	dropping; /* Equal to 1 if in drop state */
};

/* Table lookup for square-root shifted 16 bit */
static __always_inline __u32 get_sqrt_sh16(__u64 cnt)
{
	switch (cnt) {
	case 1:	return 65536; /* 65536 * sqrt(1) */
	case 2:	return 92682; /* 65536 * sqrt(2) */
	case 3:	return 113512; /* 65536 * sqrt(3) */
	case 4:	return 131072; /* 65536 * sqrt(4) */
	case 5:	return 146543; /* 65536 * sqrt(5) */
	case 6:	return 160530; /* 65536 * sqrt(6) */
	case 7:	return 173392;
	case 8:	return 185364;
	case 9:	return 196608;
	case 10: return 207243;
	case 11: return 217358;
	case 12: return 227023;
	case 13: return 236293;
	case 14: return 245213;
	case 15: return 253820;
	case 16: return 262144; /* 100 ms / sqrt(16) = 25 ms */
	case 17: return 270212;
	case 18: return 278046;
	case 19: return 285664;
	case 20: return 293086;
	case 21: return 300324;
	case 22: return 307391;
	case 23: return 314300;
	case 24: return 321060;
	case 25: return 327680; /* 100 ms / sqrt(25) = 20 ms */
	case 26: return 334169;
	case 27: return 340535;
	case 28: return 346784;
	case 29: return 352922;
	case 30: return 358955;
	case 31: return 364889;
	case 32: return 370728;
	case 33: return 376476;
	case 34: return 382137;
	case 35: return 387716;
	case 36: return 393216; /* 100 / sqrt(36) = 16.66 ms */
	default:
		return 463410; /* 65536*sqrt(50) => 100/sqrt(50) = 14.14 ms */
	}
}

static __always_inline __u64 get_next_interval_sqrt(__u64 cnt)
{
	__u64 val = ((__u64)CODEL_EXCEED_INTERVAL << 16) / get_sqrt_sh16(cnt);
	return val;
}

static __always_inline __u64
codel_control_law(__u64 t, __u64 cnt)
{
	return t + get_next_interval_sqrt(cnt);
}

static __always_inline
bool codel_should_drop(struct codel_state *codel, __u64 t_queue_sz, __u64 now)
{
	__u64 interval = CODEL_EXCEED_INTERVAL;

	if (t_queue_sz < CODEL_TARGET) {
		/* went below so we'll stay below for at least interval */
		codel->first_above_time = 0;
		return false;
	}

	if (codel->first_above_time == 0) {
		/* just went above from below. If we stay above
		 * for at least interval we'll say it's ok to drop
		 */
		codel->first_above_time = now + interval;
		return false;
	} else if (now >= codel->first_above_time) {
		return true;
	}
	return false;
}

static __always_inline
bool codel_drop(struct codel_state *codel, __u64 t_queue_sz, __u64 now)
{
	__u64 interval = CODEL_EXCEED_INTERVAL;

	/* If horizon have been exceed for a while, inc drop intensity*/
	bool drop = codel_should_drop(codel, t_queue_sz, now);

	if (codel->dropping) { /* In dropping state */
		if (!drop) {
			/* time below target - leave dropping state */
			codel->dropping = false;
			return false;
		} else if (now >= codel->drop_next) {
			/* It's time for the next drop. Drop the current
			 * packet. Schedule the next drop
			 */
			codel->count += 1;
			// schedule the next drop.
                        codel->drop_next =
				codel_control_law(codel->drop_next, codel->count);
			return true;
		}
	} else if (drop &&
		   ((now - codel->drop_next < interval) ||
		    (now - codel->first_above_time >= interval))) {
		/* If we get here, then we're not in dropping state.
		 * Decide  whether it's time to enter dropping state.
		 */
		__u32 count = codel->count;

		codel->dropping = true;

		/* If we're in a drop cycle, drop rate that controlled queue
                 * on the last cycle is a good starting point to control it now.
		 */
		if (now - codel->drop_next < interval)
			count = count > 2 ? (count - 2) : 1;
		else
			count = 1;

		codel->count = count;
		codel->drop_next = codel_control_law(now, count);
		return true;
	}
	return false;
}

#endif /* __CODEL_IMPL_H */
