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

int main(int argc, char *argv[])
{
	const char *filename = "preserve_dscp_kern.o";
	char *ifname_pre, *ifname_post;
	int ifindex_pre, ifindex_post;
	struct bpf_map *map = NULL;
	int err = 0, fd, iftype;
	struct bpf_object *obj;
	char buf[100];
	ssize_t len;
	DECLARE_LIBBPF_OPTS(bpf_tc_hook, hook, .attach_point = BPF_TC_EGRESS);
	DECLARE_LIBBPF_OPTS(bpf_tc_opts, attach_pre);
	DECLARE_LIBBPF_OPTS(bpf_tc_opts, attach_post);


	if (argc < 3) {
		fprintf(stderr, "Usage: %s <if pre> <if post> [--unload]\n", argv[0]);
		return 1;
	}
	ifname_pre = argv[1];
	ifname_post = argv[2];

	ifindex_pre = if_nametoindex(ifname_pre);
	if (!ifindex_pre) {
		fprintf(stderr, "Couldn't find interface '%s'\n", ifname_pre);
		return 1;
	}

	/* Get type of interface to know if it has ethernet headers */
	snprintf(buf, sizeof(buf)-1, "/sys/class/net/%s/type", ifname_pre);
	buf[sizeof(buf)-1] = '\0';
	fd = open(buf, 0);
	if (fd < 0 || (len = read(fd, buf, sizeof(buf))) == -1) {
		fprintf(stderr, "Couldn't get interface type for '%s'\n", ifname_pre);
		return 1;
	}
	buf[len] = '\0';
	close(fd);
	iftype = atoi(buf);

	ifindex_post = if_nametoindex(ifname_post);
	if (!ifindex_post) {
		fprintf(stderr, "Couldn't find interface '%s'\n", ifname_post);
		return 1;
	}

	if (argc == 4 && strcmp(argv[3], "--unload") == 0) {
		int _err;
		hook.attach_point = BPF_TC_INGRESS | BPF_TC_EGRESS;
		hook.ifindex = ifindex_pre;
		_err = bpf_tc_hook_destroy(&hook);
		if (_err)
			fprintf(stderr, "Couldn't remove clsact qdisc on %s\n", ifname_pre);

		hook.ifindex = ifindex_post;
		err = bpf_tc_hook_destroy(&hook);
		if (err)
			fprintf(stderr, "Couldn't remove clsact qdisc on %s\n", ifname_post);
		else
			err = _err;
		return err;
	} else if (argc > 3) {
		fprintf(stderr, "Usage: %s <if pre> <if post> [--unload]\n", argv[0]);
		return 1;
	}

	obj = bpf_object__open(filename);
	err = libbpf_get_error(obj);
	if (err) {
		fprintf(stderr, "Couldn't open file: %s\n", filename);
		return err;
	}

	while ((map = bpf_object__next_map(obj, map))) {
		if (strstr(bpf_map__name(map), ".rodata")) {
			int ip_only = (iftype == ARPHRD_NONE);
			bpf_map__set_initial_value(map, &ip_only, sizeof(ip_only));
		}
	}

	err = bpf_object__load(obj);
	if (err) {
		fprintf(stderr, "Failed to load object\n");
		goto out;
	}

	attach_pre.prog_fd = bpf_program__fd(bpf_object__find_program_by_name(obj, "read_dscp"));
	if (attach_pre.prog_fd < 0) {
		fprintf(stderr, "Couldn't find program 'read_dscp'\n");
		err = -ENOENT;
		goto out;
	}

	attach_post.prog_fd = bpf_program__fd(bpf_object__find_program_by_name(obj, "write_dscp"));
	if (attach_post.prog_fd < 0) {
		fprintf(stderr, "Couldn't find program 'write_dscp'\n");
		err = -ENOENT;
		goto out;
	}

	hook.ifindex = ifindex_pre;
	err = bpf_tc_hook_create(&hook);
	if (err && err != -EEXIST) {
		fprintf(stderr, "Couldn't create hook for ifindex %d\n", ifindex_pre);
		goto out;
	}

	err = bpf_tc_attach(&hook, &attach_pre);
	if (err) {
		fprintf(stderr, "Couldn't attach program to ifindex %d\n", hook.ifindex);
		goto out;
	}

	hook.ifindex = ifindex_post;
	err = bpf_tc_hook_create(&hook);
	if (err && err != -EEXIST) {
		fprintf(stderr, "Couldn't create hook for ifindex %d\n", ifindex_post);
		goto out;
	}

	err = bpf_tc_attach(&hook, &attach_post);
	if (err) {
		fprintf(stderr, "Couldn't attach program to ifindex %d\n", hook.ifindex);
		goto out;
	}

out:
	bpf_object__close(obj);
	return err;
}
