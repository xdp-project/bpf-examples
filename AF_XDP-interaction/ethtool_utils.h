/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */

#ifndef __ETHTOOL_UTILS_H
#define __ETHTOOL_UTILS_H

int ethtool_get_max_channels(const char *ifname);
int ethtool_get_channels(const char *ifname);

#endif /* __ETHTOOL_UTILS_H */
