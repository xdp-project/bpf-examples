/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <net/if.h>
#include <linux/if_arp.h>

#include <bpf/libbpf.h>

#include "bond-active.h"

int main(int argc, char *argv[])
{
        int ifindex, active_ifindex;
        const char *ifname;

	if (argc < 2) {
		fprintf(stderr, "Usage: %s <ifname>\n", argv[0]);
		return 1;
	}

        ifname = argv[1];
        ifindex = if_nametoindex(ifname);
        if (!ifindex) {
                fprintf(stderr, "Couldn't find interface '%s'\n", ifname);
                return 1;
        }

        active_ifindex = get_bond_active_ifindex(ifindex);
        if (active_ifindex < 0)
                return active_ifindex;

        printf("Bond with ifindex %d has active ifindex: %d\n", ifindex, active_ifindex);
        return 0;
}
