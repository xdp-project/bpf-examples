/* SPDX-License-Identifier: GPL-2.0-or-later */

#ifndef BPF_DEFS_H
#define BPF_DEFS_H

/* cookie for init ns; hoping this is stable */
#define INIT_NS 1

/* partial structs for reading bond parameters.
 *
 * These are deliberately *not* declared with the preserve_access_index, as
 * we'll read them with plan BPF_PROBE_READ() below; this is to make sure they
 * work even without module BTF, and the fields we need are only the first ones
 * of each struct which have been stable for a long time.
 */
struct slave {
	struct net_device *dev; /* first - useful for panic debug */
};

struct bonding {
	struct   net_device *dev; /* first - useful for panic debug */
	struct   slave *curr_active_slave;
};

/* local partial kernel struct definitions with just the members we need */
struct net {
	__u64 net_cookie;
} __attribute__((preserve_access_index));

typedef struct {
	__s64 counter;
} atomic64_t;

struct net___old {
	atomic64_t net_cookie;
} __attribute__((preserve_access_index));

struct net_device {
	int ifindex;
	struct {
		struct net *net;
	} nd_net;
} __attribute__((preserve_access_index));

struct netdev_notifier_info {
	struct net_device *dev;
} __attribute__((preserve_access_index));

static inline __u64 read_net_cookie(struct net *net)
{
	if (bpf_core_field_exists(net->net_cookie)) {
		return BPF_CORE_READ(net, net_cookie);
	} else {
		struct net___old *n_old = (void *)net;
		atomic64_t cookie_old;

		cookie_old = BPF_CORE_READ(n_old, net_cookie);
		return cookie_old.counter;
	}
}

#endif
