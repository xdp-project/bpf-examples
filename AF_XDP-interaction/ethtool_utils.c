/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */

#include <net/if.h>
#include <sys/ioctl.h>
#include <linux/ethtool.h>
#include <linux/sockios.h>
#ifndef SIOCETHTOOL
#define SIOCETHTOOL	0x8946		/* Ethtool interface		*/
#endif

#include <errno.h>
#include <string.h> /* memcpy */
#include <unistd.h> /* close */

#ifndef max
# define max(x, y) ((x) < (y) ? (y) : (x))
#endif


/* Based on xsk_get_max_queues(), but needed info on max_queues before
 * xsk objects are created.
 */
int ethtool_get_max_queues(const char *ifname)
{
	struct ethtool_channels channels = { .cmd = ETHTOOL_GCHANNELS };
	struct ifreq ifr = {};
	int fd, err, ret;

	fd = socket(AF_LOCAL, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (fd < 0)
		return -errno;

	ifr.ifr_data = (void *)&channels;
	memcpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);
	ifr.ifr_name[IFNAMSIZ - 1] = '\0';
	err = ioctl(fd, SIOCETHTOOL, &ifr);
	if (err && errno != EOPNOTSUPP) {
		ret = -errno;
		goto out;
	}

	if (err) {
		/* If the device says it has no channels, then all traffic
		 * is sent to a single stream, so max queues = 1.
		 */
		ret = 1;
	} else {
		/* Take the max of rx, tx, combined. Drivers return
		 * the number of channels in different ways.
		 */
		ret = max(channels.max_rx, channels.max_tx);
		ret = max(ret, (int)channels.max_combined);
	}

out:
	close(fd);
	return ret;
}
