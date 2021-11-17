/* SPDX-License-Identifier: GPL-2.0+ */

/* Used by both kernel side BPF-progs and userspace programs,
 * for sharing common DEFINEs.
 */
#ifndef __AF_XDP_KERN_SHARED_H
#define __AF_XDP_KERN_SHARED_H

/* Assume netdev has no more than 64 queues */
#define MAX_AF_SOCKS	64

#endif /* __AF_XDP_KERN_SHARED_H */
