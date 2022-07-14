#ifndef __PKT_LOOP_FILTER_H__
#define __PKT_LOOP_FILTER_H__

#define MAX_IFINDEXES 10

#define NS_PER_SEC 1000000000ULL
#define STATE_LIFETIME (10 * NS_PER_SEC)
#define LOCK_LIFETIME (5 * NS_PER_SEC)

struct pkt_loop_key {
        __u8 src_mac[6];
        __u16 src_vlan;
};

struct pkt_loop_data {
        __u64 expiry_time;
        __u64 lock_time;
        __u32 ifindex;
        __u32 drops;

};

#endif
