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

#define MAX_IFINDEXES 10

int main(int argc, char *argv[])
{
	int err = 0, i, num_ifindexes = 0, _err, ingress_fd, egress_fd;
	const char *filename = "pkt-loop-filter.kern.o";
	struct bpf_link *trace_link = NULL;
	struct bpf_program *trace_prog;
	struct bpf_object *obj = NULL;
	int ifindex[MAX_IFINDEXES];
	bool unload = false;
	char pin_path[100];
	DECLARE_LIBBPF_OPTS(bpf_tc_hook, hook, .attach_point = BPF_TC_INGRESS | BPF_TC_EGRESS);

	if (argc < 2) {
		fprintf(stderr, "Usage: %s <ifname> [..ifname] [--unload]\n", argv[0]);
		return 1;
	}

	for (i = 0; i < MAX_IFINDEXES; i++) {
		char *ifname = argv[i+1];

		if (i + 1 >= argc)
			break;

		if (!strcmp(ifname, "--unload")) {
			unload = true;
			continue;
		}

		ifindex[num_ifindexes] = if_nametoindex(ifname);
		if (!ifindex[num_ifindexes]) {
			fprintf(stderr, "Couldn't find interface '%s'\n", ifname);
			return 1;
		}
		num_ifindexes++;
	}

	if (!num_ifindexes) {
		fprintf(stderr, "Need at least one interface name\n");
		return 1;
	}

	snprintf(pin_path, sizeof(pin_path), "/sys/fs/bpf/pkt-loop-filter-%d", ifindex[0]);
	pin_path[sizeof(pin_path) - 1] = '\0';

	if (unload)
		goto unload;

	obj = bpf_object__open(filename);
	err = libbpf_get_error(obj);
	if (err) {
		fprintf(stderr, "Couldn't open file: %s\n", filename);
		return err;
	}

	err = bpf_object__load(obj);
	if (err) {
		fprintf(stderr, "Failed to load object\n");
		goto out;
	}

	egress_fd = bpf_program__fd(bpf_object__find_program_by_name(obj, "record_egress_pkt"));
	if (egress_fd < 0) {
		fprintf(stderr, "Couldn't find program 'record_egress_pkt'\n");
		err = -ENOENT;
		goto out;
	}

	ingress_fd = bpf_program__fd(bpf_object__find_program_by_name(obj, "filter_ingress_pkt"));
	if (ingress_fd < 0) {
		fprintf(stderr, "Couldn't find program 'filter_ingress_pkt'\n");
		err = -ENOENT;
		goto out;
	}

	trace_prog = bpf_object__find_program_by_name(obj, "handle_device_notify");
	if (!trace_prog) {
		fprintf(stderr, "Couldn't find program 'handle_device_notify'\n");
		err = -ENOENT;
		goto out;
	}

	for (i = 0; i < num_ifindexes; i++) {
		DECLARE_LIBBPF_OPTS(bpf_tc_opts, attach_egress,
				    .prog_fd = egress_fd);
		DECLARE_LIBBPF_OPTS(bpf_tc_opts, attach_ingress,
				    .prog_fd = ingress_fd);
		char ifname[IF_NAMESIZE];

		if (!if_indextoname(ifindex[i], ifname)) {
			err = -errno;
			perror("if_indextoname");
			goto out;
		}

		hook.ifindex = ifindex[i];
		hook.attach_point = BPF_TC_EGRESS | BPF_TC_INGRESS;
		err = bpf_tc_hook_create(&hook);
		if (err && err != -EEXIST) {
			fprintf(stderr, "Couldn't create egress hook for interface %s\n", ifname);
			goto unload;
		}

		hook.attach_point = BPF_TC_EGRESS;
		err = bpf_tc_attach(&hook, &attach_egress);
		if (err) {
			fprintf(stderr, "Couldn't attach egress program to interface %s: %s\n", ifname, strerror(errno));
			goto unload;
		}

		hook.attach_point = BPF_TC_INGRESS;
		err = bpf_tc_attach(&hook, &attach_ingress);
		if (err) {
			fprintf(stderr, "Couldn't attach ingress program to interface %s: %s\n", ifname, strerror(errno));
			goto unload;
		}
	}

	trace_link = bpf_program__attach(trace_prog);
	if (!trace_link) {
		fprintf(stderr, "Couldn't attach tracing prog: %s\n", strerror(errno));
		err = -EFAULT;
		goto unload;
	}


	err = bpf_link__pin(trace_link, pin_path);
	if (err) {
		fprintf(stderr, "Couldn't pin bpf_link: %s\n", strerror(errno));
		goto unload;
	}

out:
	bpf_link__destroy(trace_link);
	bpf_object__close(obj);
	return err;

unload:
	for (i = 0; i < num_ifindexes; i++) {
		char ifname[IF_NAMESIZE];

		hook.ifindex = ifindex[i];
		hook.attach_point = BPF_TC_EGRESS | BPF_TC_INGRESS;
		_err = bpf_tc_hook_destroy(&hook);
		if (_err) {
			fprintf(stderr, "Couldn't remove clsact qdisc on %s\n",
				if_indextoname(ifindex[i], ifname));
			err = _err;
		}

	}
	unlink(pin_path);
	goto out;
}
