/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Copyright 2022 Jesper Dangaard Brouer */

static const char *__doc__ =
	"TC queue policy - Controlling TC qdisc TXQ selection via BPF";

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include <net/if.h>
#include <linux/if_arp.h>
#include <getopt.h>
#include <linux/in6.h>
#include <arpa/inet.h>
#include <linux/bpf.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

static const struct option long_options[] = {
	{ "help",             no_argument,       NULL, 'h' },
	{ "interface",        required_argument, NULL, 'i' },
	{ "unload",           no_argument,       NULL, 'u' },
	{ 0, 0, NULL, 0 }
};

struct user_config {
	int ifindex;
	char ifname[IF_NAMESIZE+1];
	bool unload;
};

/* Auto-generated skeleton: Contains BPF-object inlined as code */
#include "tc_txq_policy_kern.skel.h"

static void print_usage(char *argv[])
{
	int i;

	printf("\nDOCUMENTATION:\n%s\n", __doc__);
	printf("\n");
	printf(" Usage: %s (options-see-below)\n", argv[0]);
	printf(" Listing options:\n");
	for (i = 0; long_options[i].name != 0; i++) {
		printf(" --%-12s", long_options[i].name);
		if (long_options[i].flag != NULL)
			printf(" flag (internal value:%d)",
			       *long_options[i].flag);
		else
			printf(" short-option: -%c", long_options[i].val);
		printf("\n");
	}
	printf("\n");
}

static int parse_arguments(int argc, char *argv[],
			   struct user_config *cfg)
{
	int err, opt;

	cfg->ifindex = 0;

	while ((opt = getopt_long(argc, argv, "i:hu", long_options,
				  NULL)) != -1) {
		switch (opt) {
		case 'i':
			if (strlen(optarg) > IF_NAMESIZE) {
				fprintf(stderr, "interface name too long\n");
				return -EINVAL;
			}
			strncpy(cfg->ifname, optarg, IF_NAMESIZE);

			cfg->ifindex = if_nametoindex(cfg->ifname);
			if (cfg->ifindex == 0) {
				err = -errno;
				fprintf(stderr,
					"Could not get index of interface %s: [%d] %s\n",
					cfg->ifname, errno, strerror(errno));
				return err;
			}
			break;
		case 'u':
			cfg->unload = true;
			break;
		default:
			print_usage(argv);
			fprintf(stderr, "Unknown option %s\n", argv[optind]);
			return -EINVAL;
		}
	}

	if (cfg->ifindex == 0) {
		fprintf(stderr,
			"An interface (-i or --interface) must be provided\n");
		return -EINVAL;
	}

	return 0;
}

struct tc_txq_policy_kern *
get_bpf_skel_object(struct user_config *cfg)
{
	struct tc_txq_policy_kern *obj; /* Skeleton gave us this */
	char buf[100];
	int err;

	/* Skeleton header file have BPF-object as inline code */
	obj = tc_txq_policy_kern__open();
	err = libbpf_get_error(obj);
	if (err) {
		libbpf_strerror(err, buf, sizeof(buf));
		fprintf(stderr, "Couldn't open BPF skeleton:(%d) %s\n", err, buf);
		return NULL;
	}

	/* Add code here that change BPF-obj config before loading */

	/* Loading BPF-code into kernel, verifier will check, but not attach */
	err = tc_txq_policy_kern__load(obj);
	if (err) {
		libbpf_strerror(err, buf, sizeof(buf));
		fprintf(stderr, "Couldn't load BPF skeleton:(%d) %s\n", err, buf);
		tc_txq_policy_kern__destroy(obj);
		return NULL;
	}

	return obj;
}

int teardown(struct user_config *cfg)
{
	DECLARE_LIBBPF_OPTS(bpf_tc_hook, hook,
			    .attach_point = BPF_TC_EGRESS,
			    .ifindex = cfg->ifindex);
	int err;

	err = bpf_tc_hook_destroy(&hook);
	if (err)
		fprintf(stderr, "Couldn't remove clsact qdisc on %s\n", cfg->ifname);

	return err;
}

int tc_attach_egress(struct user_config *cfg, struct tc_txq_policy_kern *obj)
{
	int err = 0;
	int fd;
	DECLARE_LIBBPF_OPTS(bpf_tc_hook, hook, .attach_point = BPF_TC_EGRESS);
	DECLARE_LIBBPF_OPTS(bpf_tc_opts, attach_egress);

	/* Selecting BPF-prog here: */
	fd = bpf_program__fd(obj->progs.queue_map_4);
	if (fd < 0) {
		fprintf(stderr, "Couldn't find egress program\n");
		err = -ENOENT;
		goto out;
	}
	attach_egress.prog_fd = fd;

	hook.ifindex = cfg->ifindex;

	err = bpf_tc_hook_create(&hook);
	if (err && err != -EEXIST) {
		fprintf(stderr, "Couldn't create TC-BPF hook for ifindex %d (err:%d)\n",
			cfg->ifindex, err);
		goto out;
	}

	hook.attach_point = BPF_TC_EGRESS;
	err = bpf_tc_attach(&hook, &attach_egress);
	if (err) {
		fprintf(stderr, "Couldn't attach egress program to ifindex %d (err:%d)\n",
			hook.ifindex, err);
		goto out;
	}

out:
	return err;
}


int main(int argc, char *argv[])
{
	struct user_config cfg = {
		.unload = false,
	};
	struct tc_txq_policy_kern *obj; /* Skeleton gave us this */
	int err;

	err = parse_arguments(argc, argv, &cfg);
	if (err)
		return EXIT_FAILURE;

	if (cfg.unload)
		return teardown(&cfg);

	obj = get_bpf_skel_object(&cfg);
	if (obj == NULL)
		return EXIT_FAILURE;

	err = tc_attach_egress(&cfg, obj);
	if (err) {
		err = EXIT_FAILURE;
		goto out;
	}
out:
	tc_txq_policy_kern__destroy(obj);
	return err;
}
