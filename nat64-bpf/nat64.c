/* SPDX-License-Identifier: GPL-2.0-or-later */
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

#include <libmnl/libmnl.h>
#include <linux/rtnetlink.h>

#include "logging.h"

#include "nat64.h"
#include "nat64_kern.skel.h"

#define NS_PER_SECOND 1000000000UL
#define NS_PER_MS 1000000UL

static const struct option long_options[] = {
	{ "help",             no_argument,       NULL, 'h' },
	{ "unload",           no_argument,       NULL, 'u' },
	{ "interface",        required_argument, NULL, 'i' }, // Name of interface to run on
	{ "allowed-src",      required_argument, NULL, 'a' }, // v6 prefix to allow as source
	{ "v6-prefix",        required_argument, NULL, '6' }, // v6 prefix to use for nat64
	{ "v4-prefix",        required_argument, NULL, '4' }, // v4 prefix to use for nat64
	{ "timeout",          required_argument, NULL, 't' }, // Address mapping timeout interval in s
	{ "verbose",          required_argument, NULL, 'v' }, // verbose logging
	{ 0, 0, NULL, 0 }
};

struct nat64_user_config {
	struct nat64_config c;
	int ifindex;
	char ifname[IF_NAMESIZE+1];
	struct in6_addr v6_allow;
	__u32 v6_allow_pxlen;
	__u32 v4_pxlen;
	bool unload;
};



static int parse_v6_prefix(char *str, struct in6_addr *v6addr)
{
	char *net;
	int pxlen;

	net = strstr(str, "/");
	if (!net) {
		fprintf(stderr, "Invalid v6 prefix: %s\n", str);
		return -EINVAL;
	}
	pxlen = atoi(net + 1);
	*net = '\0';
	if (inet_pton(AF_INET6, str, v6addr) != 1) {
		fprintf(stderr, "Invalid v6 addr: %s\n", str);
		return -EINVAL;
	}
	return pxlen;
}

static int parse_arguments(int argc, char *argv[], struct nat64_user_config *config)
{
	struct in6_addr v6addr;
	struct in_addr v4addr;
	int pxlen, seconds;
	int err, opt;
	char *net;

	config->ifindex = 0;
	config->c.timeout_ns = 7200 * NS_PER_SECOND;
	config->c.next_addr = 1;

	/* Default to special prefix 64:ff9b::/96 */
	config->c.v6_prefix.s6_addr[1] = 0x64;
	config->c.v6_prefix.s6_addr[2] = 0xff;
	config->c.v6_prefix.s6_addr[3] = 0x9b;

	while ((opt = getopt_long(argc, argv, "i:6:4:t:a:huv", long_options,
				  NULL)) != -1) {
		switch (opt) {
		case 'i':
			if (strlen(optarg) > IF_NAMESIZE) {
				fprintf(stderr, "interface name too long\n");
				return -EINVAL;
			}
			strncpy(config->ifname, optarg, IF_NAMESIZE);

			config->ifindex = if_nametoindex(config->ifname);
			if (config->ifindex == 0) {
				err = -errno;
				fprintf(stderr,
					"Could not get index of interface %s: %s\n",
					config->ifname, strerror(err));
				return err;
			}
			break;
		case 'a':
			pxlen = parse_v6_prefix(optarg, &v6addr);
			if (pxlen < 0)
				return pxlen;
			config->v6_allow = v6addr;
			config->v6_allow_pxlen = pxlen;
			break;
		case '6':
			pxlen = parse_v6_prefix(optarg, &v6addr);
			if (pxlen < 0)
				return pxlen;
			if (pxlen != 96) {
				fprintf(stderr, "v6 prefix must have pxlen 96\n");
				return -EINVAL;
			}
			if (v6addr.s6_addr32[3]) {
				fprintf(stderr, "Not a /96 network address: %s\n", optarg);
				return -EINVAL;
			}
			config->c.v6_prefix = v6addr;
			break;
		case '4':
			net = strstr(optarg, "/");
			if (!net) {
				fprintf(stderr, "Invalid v6 prefix: %s\n", optarg);
				return -EINVAL;
			}
			pxlen = atoi(net + 1);
			if (pxlen < 1 || pxlen > 31) {
				fprintf(stderr, "v4_pxlen must be between 1 and 31\n");
				return -EINVAL;
			}
			*net = '\0';
			if (inet_pton(AF_INET, optarg, &v4addr) != 1) {
				fprintf(stderr, "Invalid v4 addr: %s\n", optarg);
				return -EINVAL;
			}
			config->c.v4_mask = 0xFFFFFFFF << (32 - pxlen);
			config->v4_pxlen = pxlen;
			config->c.v4_prefix = ntohl(v4addr.s_addr);
			if (config->c.v4_prefix & ~config->c.v4_mask) {
				fprintf(stderr, "Not a network address: %s\n", optarg);
				return -EINVAL;
			}
			break;
		case 't':
			seconds = atoi(optarg);
			if (seconds < 1 || seconds > 100000) {
				fprintf(stderr, "Timeout must be in the interval between 1 and 100000 seconds\n");
				return -EINVAL;
			}

			config->c.timeout_ns = (__u64)seconds * NS_PER_SECOND;
			break;
		case 'u':
			config->unload = true;
			break;
		case 'v':
			increase_log_level();
			break;
		default:
			fprintf(stderr, "Unknown option %s\n", argv[optind]);
			return -EINVAL;
		}
	}

	if (config->ifindex == 0) {
		fprintf(stderr,
			"An interface (-i or --interface) must be provided\n");
		return -EINVAL;
	}
	if (!config->c.v4_prefix) {
		fprintf(stderr,
			"A v4 prefix (-4 or --v4-prefix) must be provided\n");
		return -EINVAL;
	}

	return 0;
}

static int do_v4_neigh(struct mnl_socket *nl, struct nat64_user_config *cfg, bool create)
{
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct nlmsghdr *nlh;
	uint32_t seq, portid;
	struct rtmsg *rtm;
	int ret, err = 0;

	struct {
		__u16 family;
		struct in6_addr addr;
	} __attribute__((packed)) via = {
		.family = AF_INET6,
		.addr = cfg->c.v6_prefix
	};


	nlh = mnl_nlmsg_put_header(buf);
	if (create) {
		nlh->nlmsg_type = RTM_NEWROUTE;
		nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_ACK;
	} else {
		nlh->nlmsg_type = RTM_DELROUTE;
		nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	}
	nlh->nlmsg_seq = seq = time(NULL);

	rtm = mnl_nlmsg_put_extra_header(nlh, sizeof(struct rtmsg));
	rtm->rtm_family = AF_INET;
	rtm->rtm_dst_len = cfg->v4_pxlen;
	rtm->rtm_src_len = 0;
	rtm->rtm_tos = 0;
	rtm->rtm_protocol = RTPROT_STATIC;
	rtm->rtm_table = RT_TABLE_MAIN;
	rtm->rtm_type = RTN_UNICAST;
	rtm->rtm_scope = RT_SCOPE_UNIVERSE;
	rtm->rtm_flags = RTNH_F_ONLINK;

	mnl_attr_put_u32(nlh, RTA_DST, htonl(cfg->c.v4_prefix));
	mnl_attr_put_u32(nlh, RTA_OIF, cfg->ifindex);
	mnl_attr_put(nlh, RTA_VIA, sizeof(via), &via);

	portid = mnl_socket_get_portid(nl);
	if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0) {
		perror("mnl_socket_sendto");
		err = -errno;
		goto out;
	}

	ret = mnl_socket_recvfrom(nl, buf, sizeof(buf));
	if (ret < 0) {
		perror("mnl_socket_recvfrom");
		err = -errno;
		goto out;
	}

	ret = mnl_cb_run(buf, ret, seq, portid, NULL, NULL);
	if (ret < 0) {
		if ((create && errno != EEXIST) ||
		    !(create && errno != ENOENT && errno != ESRCH))
			err = -errno;
		goto out;
	}

out:
	return err;
}

static int do_v4_route(struct mnl_socket *nl, struct nat64_user_config *cfg, bool create)
{
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct nlmsghdr *nlh;
	uint32_t seq, portid;
	struct ndmsg *ndm;
	int ret, err = 0;

	__u8 lladdr[6] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55 };
	nlh = mnl_nlmsg_put_header(buf);
	if (create) {
		nlh->nlmsg_type = RTM_NEWNEIGH;
		nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_ACK;
	} else {
		nlh->nlmsg_type = RTM_DELNEIGH;
		nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	}
	nlh->nlmsg_seq = seq = time(NULL);

	ndm = mnl_nlmsg_put_extra_header(nlh, sizeof(struct ndmsg));
	ndm->ndm_family = AF_INET6;
	ndm->ndm_ifindex = cfg->ifindex;
	ndm->ndm_state = NUD_PERMANENT;
	ndm->ndm_type = 0;

	mnl_attr_put(nlh, NDA_LLADDR, sizeof(lladdr), &lladdr);
	mnl_attr_put(nlh, NDA_DST, sizeof(struct in6_addr), &cfg->c.v6_prefix);

	portid = mnl_socket_get_portid(nl);
	if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0) {
		perror("mnl_socket_sendto");
		err = -errno;
		goto out;
	}

	ret = mnl_socket_recvfrom(nl, buf, sizeof(buf));
	if (ret < 0) {
		perror("mnl_socket_recvfrom");
		err = -errno;
		goto out;
	}

	ret = mnl_cb_run(buf, ret, seq, portid, NULL, NULL);
	if (ret < 0) {
		if ((create && errno != EEXIST) ||
		    !(create && errno != ENOENT && errno != ESRCH))
			err = -errno;
		goto out;
	}

out:
	return err;
}

static int do_netlink(struct nat64_user_config *cfg, bool create)
{
	struct mnl_socket *nl;
	int err = 0;

	nl = mnl_socket_open(NETLINK_ROUTE);
	if (nl == NULL) {
		perror("mnl_socket_open");
		err = -errno;
		goto out;
	}

	if (mnl_socket_bind(nl, 0, MNL_SOCKET_AUTOPID) < 0) {
		perror("mnl_socket_bind");
		err = -errno;
		goto out;
	}

	err = do_v4_route(nl, cfg, create);
	err = err ?: do_v4_neigh(nl, cfg, create);

out:
	mnl_socket_close(nl);
	return err;
}


int teardown(struct nat64_user_config *cfg)
{
	DECLARE_LIBBPF_OPTS(bpf_tc_hook, hook,
			    .attach_point = BPF_TC_INGRESS | BPF_TC_EGRESS,
			    .ifindex = cfg->ifindex);
	int err;

	err = bpf_tc_hook_destroy(&hook);
	if (err)
		fprintf(stderr, "Couldn't remove clsact qdisc on %s\n", cfg->ifname);

	err = do_netlink(cfg, false);
	if (err)
		fprintf(stderr, "Couldn't remove route on %s: %s\n",
			cfg->ifname, strerror(-err));

	return err;
}


int main(int argc, char *argv[])
{
	struct v6_trie_key prefix_key = {};
	struct nat64_user_config cfg = {};
	struct nat64_kern *obj;
	unsigned int num_addr;
	char buf[100];
	int err = 0;
	DECLARE_LIBBPF_OPTS(bpf_tc_hook, hook, .attach_point = BPF_TC_INGRESS | BPF_TC_EGRESS);
	DECLARE_LIBBPF_OPTS(bpf_tc_opts, attach_egress);
	DECLARE_LIBBPF_OPTS(bpf_tc_opts, attach_ingress);

	init_lib_logging();

	err = parse_arguments(argc, argv, &cfg);
	if (err)
		return EXIT_FAILURE;

	hook.ifindex = cfg.ifindex;
	if (cfg.unload)
		return teardown(&cfg);

	obj = nat64_kern__open();
	err = libbpf_get_error(obj);
	if (err) {
		libbpf_strerror(err, buf, sizeof(buf));
		fprintf(stderr, "Couldn't open BPF skeleton: %s\n", buf);
		return err;
	}

	num_addr = (cfg.c.v4_prefix | ~cfg.c.v4_mask) - cfg.c.v4_prefix - 2;

	obj->bss->config = cfg.c;
	bpf_map__set_max_entries(obj->maps.v6_state_map, num_addr);
	bpf_map__set_max_entries(obj->maps.v4_reversemap, num_addr);
	bpf_map__set_max_entries(obj->maps.reclaimed_addrs, num_addr);

	err = nat64_kern__load(obj);
	if (err) {
		libbpf_strerror(err, buf, sizeof(buf));
		fprintf(stderr, "Couldn't load BPF skeleton: %s\n", buf);
		goto out;
	}

	if (cfg.v6_allow_pxlen) {
		__u32 value = 0;

		prefix_key.t.prefixlen = cfg.v6_allow_pxlen;
		prefix_key.addr = cfg.v6_allow;
		err = bpf_map_update_elem(bpf_map__fd(obj->maps.allowed_v6_src),
					  &prefix_key, &value, 0);
		if (err) {
			fprintf(stderr, "Couldn't insert allowed prefix\n");
			goto out;
		}
	}


	attach_ingress.prog_fd = bpf_program__fd(obj->progs.nat64_ingress);
	if (attach_ingress.prog_fd < 0) {
		fprintf(stderr, "Couldn't find ingress program\n");
		err = -ENOENT;
		goto out;
	}

	attach_egress.prog_fd = bpf_program__fd(obj->progs.nat64_egress);
	if (attach_egress.prog_fd < 0) {
		fprintf(stderr, "Couldn't find egress program\n");
		err = -ENOENT;
		goto out;
	}

	err = bpf_tc_hook_create(&hook);
	if (err && err != -EEXIST) {
		fprintf(stderr, "Couldn't create ingress hook for ifindex %d\n", cfg.ifindex);
		goto out;
	}

	hook.attach_point = BPF_TC_INGRESS;
	err = bpf_tc_attach(&hook, &attach_ingress);
	if (err) {
		fprintf(stderr, "Couldn't attach ingress program to ifindex %d\n",
			hook.ifindex);
		goto out;
	}

	hook.attach_point = BPF_TC_EGRESS;
	err = bpf_tc_attach(&hook, &attach_egress);
	if (err) {
		fprintf(stderr, "Couldn't attach egress program to ifindex %d\n",
			hook.ifindex);
		goto out;
	}

	err = do_netlink(&cfg, true);
	if (err) {
		fprintf(stderr, "Couldn't create route: %s\n", strerror(-err));
		err = teardown(&cfg);
	}

out:
	nat64_kern__destroy(obj);
	return err;
}
