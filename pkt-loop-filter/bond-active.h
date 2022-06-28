/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef BOND_ACTIVE_H
#define BOND_ACTIVE_H

#include <bpf/libbpf.h>

int get_bond_active_ifindex(int bond_ifindex);
int get_netns_cookie(__u64 *cookie);

#endif
