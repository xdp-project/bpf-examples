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
	{ 0, 0, NULL, 0 }
};

struct user_config {
	int ifindex;
	char ifname[IF_NAMESIZE+1];
	bool unload;
};

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

int main(int argc, char *argv[])
{
	struct user_config cfg = {
		.unload = false,
	};
	int err;

	err = parse_arguments(argc, argv, &cfg);
	if (err)
		return EXIT_FAILURE;

}
