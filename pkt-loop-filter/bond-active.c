/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <net/if.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <linux/in.h>

#include <bpf/libbpf.h>

#include "get-bond-active.kern.skel.h"

#ifndef SO_NETNS_COOKIE
#define SO_NETNS_COOKIE		71
#endif

#define INIT_NS 1

int get_netns_cookie(__u64 *cookie)
{
        unsigned int sockopt_sz = sizeof(__u64);
        __u64 value;
        int fd, err;

        fd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
        if (fd < 0)
                return fd;

        err = getsockopt(fd, SOL_SOCKET, SO_NETNS_COOKIE, &value, &sockopt_sz);
        if (err) {
                if (errno != ENOPROTOOPT) {
                        err = -errno;
                        fprintf(stderr, "Couldn't getsockopt(): %s\n", strerror(-err));
                        goto out;
                }
                fprintf(stderr, "SO_NETNS_COOKIE sockopt not supported; things won't work outside init NS\n");
                value = INIT_NS;
                err = 0;
        }

        *cookie = value;
out:
        close(fd);
        return err;
}

int get_bond_active_ifindex(int bond_ifindex)
{
        char ifname[IF_NAMESIZE], fname[100], buf[50];
	struct get_bond_active_kern *skel = NULL;
	struct bpf_link *trace_link = NULL;
        int ret = 0, fd = -1;
        __u64 netns_cookie;
        size_t len;

        if (!if_indextoname(bond_ifindex, ifname))
                return -errno;

        /* We write the current value back to this file to trigger the kprobe
         * that allows us to read the active ifindex
         */
        snprintf(fname, sizeof(fname), "/sys/class/net/%s/bonding/primary_reselect", ifname);
        fname[sizeof(fname)-1] = '\0';

        ret = get_netns_cookie(&netns_cookie);
        if (ret)
                return ret;

	skel = get_bond_active_kern__open();
	ret = libbpf_get_error(skel);
	if (ret) {
		fprintf(stderr, "Couldn't open BPF skeleton: %s\n", strerror(errno));
		return ret;
	}

        skel->bss->bond_ifindex = bond_ifindex;
        skel->rodata->netns_cookie = netns_cookie;

	ret = get_bond_active_kern__load(skel);
	if (ret) {
		fprintf(stderr, "Failed to load object\n");
		goto out;
	}

	trace_link = bpf_program__attach(skel->progs.handle_select_slave);
	if (!trace_link) {
		fprintf(stderr, "Couldn't attach tracing prog: %s\n", strerror(errno));
		ret = -EFAULT;
		goto out;
	}

        fd = open(fname, O_RDWR);
        if (fd < 0) {
                ret = -errno;
                fprintf(stderr, "Couldn't open %s: %s\n", fname, strerror(-ret));
                goto out;
        }

        len = read(fd, buf, sizeof(buf));
        if (len < 0) {
                ret = -errno;
                fprintf(stderr, "Couldn't read from %s: %s\n", fname, strerror(-ret));
        }

        ret = write(fd, buf, len);
        if (ret < 0) {
                ret = -errno;
                fprintf(stderr, "Couldn't write to %s: %s\n", fname, strerror(-ret));
                goto out;
        }

        ret = skel->bss->active_slave_ifindex;

out:
	bpf_link__destroy(trace_link);
	get_bond_active_kern__destroy(skel);
        if (fd >= 0)
                close(fd);

	return ret;
}
