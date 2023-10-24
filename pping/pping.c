/* SPDX-License-Identifier: GPL-2.0-or-later */
static const char *__doc__ =
	"Passive Ping - monitor flow RTT based on header inspection";

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <linux/if_link.h>
#include <net/if.h> // For if_nametoindex
#include <arpa/inet.h> // For inet_ntoa and ntohs

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <getopt.h>
#include <stdbool.h>
#include <ctype.h>
#include <signal.h> // For detecting Ctrl-C
#include <sys/resource.h> // For setting rlmit
#include <time.h>
#include <pthread.h>
#include <xdp/libxdp.h>
#include <sys/signalfd.h>
#include <sys/timerfd.h>
#include <sys/epoll.h>
#include <linux/unistd.h>
#include <linux/membarrier.h>
#include <limits.h>

#include "json_writer.h"
#include "pping.h" //common structs for user-space and BPF parts
#include "lhist.h"

// Maximum string length for IP prefix (including /xx[x] and '\0')
#define INET_PREFIXSTRLEN (INET_ADDRSTRLEN + 3)
#define INET6_PREFIXSTRLEN (INET6_ADDRSTRLEN + 4)

#define PERF_BUFFER_PAGES 64 // Related to the perf-buffer size?

#define MON_TO_REAL_UPDATE_FREQ                                                \
	(1 * NS_PER_SECOND) // Update offset between CLOCK_MONOTONIC and CLOCK_REALTIME once per second

#define PROG_INGRESS_TC "pping_tc_ingress"
#define PROG_INGRESS_XDP "pping_xdp_ingress"
#define PROG_EGRESS_TC "pping_tc_egress"

#define MAX_EPOLL_EVENTS 64

/* Used to pack both type of event and other arbitrary data in a  single
 * epoll_event.data.u64 member. The topmost bits are used for the type of event,
 * while the lower bits given by the PPING_EPEVENT_MASK can be used for another
 * value */
#define PPING_EPEVENT_TYPE_PERFBUF (1ULL << 63)
#define PPING_EPEVENT_TYPE_SIGNAL (1ULL << 62)
#define PPING_EPEVENT_TYPE_PIPE (1ULL << 61)
#define PPING_EPEVENT_TYPE_AGGTIMER (1ULL << 60)
#define PPING_EPEVENT_MASK                                                     \
	(~(PPING_EPEVENT_TYPE_PERFBUF | PPING_EPEVENT_TYPE_SIGNAL |            \
	   PPING_EPEVENT_TYPE_PIPE | PPING_EPEVENT_TYPE_AGGTIMER))

#define AGG_BATCH_SIZE 64 // Batch size for fetching aggregation maps (bpf_map_lookup_batch)

/* Value that can be returned by functions to indicate the program should abort
 * Should ideally not collide with any error codes (including libbpf ones), but
 * can also be seperated by returning as positive (as error codes are generally
 * returned as negative values). */
#define PPING_ABORT 5555

#define ARG_AGG_REVERSE 256
#define AGG_ARG_TIMEOUT 257

enum pping_output_format {
	PPING_OUTPUT_STANDARD,
	PPING_OUTPUT_JSON,
	PPING_OUTPUT_PPVIZ
};

/*
 * BPF implementation of pping using libbpf.
 * Uses TC-BPF for egress and XDP for ingress.
 * - On egrees, packets are parsed for an identifer,
 *   if found added to hashmap using flow+identifier as key,
 *   and current time as value.
 * - On ingress, packets are parsed for reply identifer,
 *   if found looksup hashmap using reverse-flow+identifier as key,
 *   and calculates RTT as different between now and stored timestamp.
 * - Calculated RTTs are pushed to userspace
 *   (together with the related flow) and printed out.
 */

// Structure to contain arguments for periodic_map_cleanup (for passing to pthread_create)
// Also keeps information about the thread in which the cleanup function runs
struct map_cleanup_args {
	pthread_t tid;
	struct bpf_link *tsclean_link;
	struct bpf_link *flowclean_link;
	__u64 cleanup_interval;
	int pipe_wfd;
	int pipe_rfd;
	int err;
	bool valid_thread;
};

struct output_context {
	FILE *stream;
	json_writer_t *jctx;
	enum pping_output_format format;
};

struct aggregation_config {
	__u64 aggregation_interval;
	__u64 timeout_interval;
	__u64 n_bins;
	__u64 bin_width;
	__u8 ipv4_prefix_len;
	__u8 ipv6_prefix_len;
};

struct aggregation_maps {
	int map_active_fd;
	int map_v4_fd[2];
	int map_v6_fd[2];
	int map_globcnt_fd;
};

struct aggregation_context {
	struct aggregation_maps maps;
	struct global_counters prev_counters;
};

// Store configuration values in struct to easily pass around
struct pping_config {
	struct bpf_config bpf_config;
	struct bpf_tc_opts tc_ingress_opts;
	struct bpf_tc_opts tc_egress_opts;
	struct map_cleanup_args clean_args;
	struct aggregation_config agg_conf;
	struct aggregation_context agg_ctx;
	struct output_context *out_ctx;
	char *object_path;
	char *ingress_prog;
	char *egress_prog;
	char *cleanup_ts_prog;
	char *cleanup_flow_prog;
	char *packet_map;
	char *flow_map;
	char *event_map;
	int ifindex;
	struct xdp_program *xdp_prog;
	int ingress_prog_id;
	int egress_prog_id;
	char ifname[IF_NAMESIZE];
	char filename[PATH_MAX];
	enum pping_output_format format;
	enum xdp_attach_mode xdp_mode;
	bool write_to_file;
	bool force;
	bool created_tc_hook;
};

static const struct option long_options[] = {
	{ "help",                 no_argument,       NULL, 'h' },
	{ "interface",            required_argument, NULL, 'i' }, // Name of interface to run on
	{ "rate-limit",           required_argument, NULL, 'r' }, // Sampling rate-limit in ms
	{ "rtt-rate",             required_argument, NULL, 'R' }, // Sampling rate in terms of flow-RTT (ex 1 sample per RTT-interval)
	{ "rtt-type",             required_argument, NULL, 't' }, // What type of RTT the RTT-rate should be applied to ("min" or "smoothed"), only relevant if rtt-rate is provided
	{ "force",                no_argument,       NULL, 'f' }, // Overwrite any existing XDP program on interface, remove qdisc on cleanup
	{ "cleanup-interval",     required_argument, NULL, 'c' }, // Map cleaning interval in s, 0 to disable
	{ "format",               required_argument, NULL, 'F' }, // Which format to output in (standard/json/ppviz)
	{ "ingress-hook",         required_argument, NULL, 'I' }, // Use tc or XDP as ingress hook
	{ "xdp-mode",             required_argument, NULL, 'x' }, // Which xdp-mode to use (unspecified, native or generic)
	{ "tcp",                  no_argument,       NULL, 'T' }, // Calculate and report RTTs for TCP traffic (with TCP timestamps)
	{ "icmp",                 no_argument,       NULL, 'C' }, // Calculate and report RTTs for ICMP echo-reply traffic
	{ "include-local",        no_argument,       NULL, 'l' }, // Also report "internal" RTTs
	{ "include-SYN",          no_argument,       NULL, 's' }, // Include SYN-packets in tracking (may fill up flow state with half-open connections)
	{ "aggregate",            required_argument, NULL, 'a' }, // Aggregate RTTs every X seconds instead of reporting them individually
        { "aggregate-subnets-v4", required_argument, NULL, '4' }, // Set the subnet size for IPv4 when aggregating (default 24)
	{ "aggregate-subnets-v6", required_argument, NULL, '6' }, // Set the subnet size for IPv6 when aggregating (default 48)
	{ "aggregate-reverse",    no_argument,       NULL, ARG_AGG_REVERSE }, // Aggregate RTTs by dst IP of reply packet (instead of src like default)
	{ "aggregate-timeout",    required_argument, NULL, AGG_ARG_TIMEOUT }, // Interval for timing out subnet entries in seconds (default 30s)
	{ "write",                required_argument, NULL, 'w' }, // Write output to file (instead of stdout)
	{ 0, 0, NULL, 0 }
};

/*
 * Copied from Jesper Dangaaard Brouer's traffic-pacing-edt example
 */
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
		else if (isalnum(long_options[i].val))
			printf(" short-option: -%c", long_options[i].val);
		printf("\n");
	}
	printf("\n");
}

/*
 * Simple convenience wrapper around libbpf_strerror for which you don't have
 * to provide a buffer. Instead uses its own static buffer and returns a pointer
 * to it.
 *
 * This of course comes with the tradeoff that it is no longer thread safe and
 * later invocations overwrite previous results.
 */
static const char *get_libbpf_strerror(int err)
{
	static char buf[200];
	libbpf_strerror(err, buf, sizeof(buf));
	return buf;
}

static int parse_bounded_double(double *res, const char *str, double low,
				double high, const char *name)
{
	char *endptr;
	errno = 0;

	*res = strtod(str, &endptr);
	if (endptr == str || strlen(str) != endptr - str) {
		fprintf(stderr, "%s %s is not a valid number\n", name, str);
		return -EINVAL;
	}

	if (errno == ERANGE) {
		fprintf(stderr, "%s %s overflowed\n", name, str);
		return -ERANGE;
	}

	if (*res < low || *res > high) {
		fprintf(stderr, "%s must be in range [%g, %g]\n", name, low, high);
		return -ERANGE;
	}

	return 0;
}

static int parse_bounded_long(long long *res, const char *str, long long low,
			      long long high, const char *name)
{
	char *endptr;
	errno = 0;

	*res = strtoll(str, &endptr, 10);
	if (endptr == str || strlen(str) != endptr - str) {
		fprintf(stderr, "%s %s is not a valid integer\n", name, str);
		return -EINVAL;
	}

	if (errno == ERANGE) {
		fprintf(stderr, "%s %s overflowed\n", name, str);
		return -ERANGE;
	}

	if (*res < low || *res > high) {
		fprintf(stderr, "%s must be in range [%lld, %lld]\n", name, low,
			high);
		return -ERANGE;
	}

	return 0;
}

static int parse_arguments(int argc, char *argv[], struct pping_config *config)
{
	int err, opt, len;
	double user_float;
	long long user_int;

	config->ifindex = 0;
	config->force = false;

	config->bpf_config.localfilt = true;
	config->bpf_config.track_tcp = false;
	config->bpf_config.track_icmp = false;
	config->bpf_config.skip_syn = true;
	config->bpf_config.push_individual_events = true;
	config->bpf_config.agg_rtts = false;
	config->bpf_config.agg_by_dst = false;

	while ((opt = getopt_long(argc, argv, "hflTCsi:r:R:t:c:F:I:x:a:4:6:w:",
				  long_options, NULL)) != -1) {
		switch (opt) {
		case 'i':
			len = strlen(optarg);
			if (len >= IF_NAMESIZE) {
				fprintf(stderr, "interface name too long\n");
				return -EINVAL;
			}
			memcpy(config->ifname, optarg, len);
			config->ifname[len] = '\0';

			config->ifindex = if_nametoindex(config->ifname);
			if (config->ifindex == 0) {
				err = -errno;
				fprintf(stderr,
					"Could not get index of interface %s: %s\n",
					config->ifname,
					get_libbpf_strerror(err));
				return err;
			}
			break;
		case 'r':
			err = parse_bounded_double(&user_float, optarg, 0,
						   7 * S_PER_DAY * MS_PER_S,
						   "rate-limit");
			if (err)
				return -EINVAL;

			config->bpf_config.rate_limit = user_float * NS_PER_MS;
			break;
		case 'R':
			err = parse_bounded_double(&user_float, optarg, 0,
						   10000, "rtt-rate");
			if (err)
				return -EINVAL;
			config->bpf_config.rtt_rate =
				DOUBLE_TO_FIXPOINT(user_float);
			break;
		case 't':
			if (strcmp(optarg, "min") == 0) {
				config->bpf_config.use_srtt = false;
			} else if (strcmp(optarg, "smoothed") == 0) {
				config->bpf_config.use_srtt = true;
			} else {
				fprintf(stderr,
					"rtt-type must be \"min\" or \"smoothed\"\n");
				return -EINVAL;
			}
			break;
		case 'c':
			err = parse_bounded_double(&user_float, optarg, 0,
						   7 * S_PER_DAY,
						   "cleanup-interval");
			if (err)
				return -EINVAL;

			config->clean_args.cleanup_interval =
				user_float * NS_PER_SECOND;
			break;
		case 'F':
			if (strcmp(optarg, "standard") == 0) {
				config->format = PPING_OUTPUT_STANDARD;
			} else if (strcmp(optarg, "json") == 0) {
				config->format = PPING_OUTPUT_JSON;
			} else if (strcmp(optarg, "ppviz") == 0) {
				config->format = PPING_OUTPUT_PPVIZ;
			} else {
				fprintf(stderr,
					"format must be \"standard\", \"json\" or \"ppviz\"\n");
				return -EINVAL;
			}
			break;
		case 'I':
			if (strcmp(optarg, "xdp") == 0) {
				config->ingress_prog = PROG_INGRESS_XDP;
			} else if (strcmp(optarg, "tc") == 0) {
				config->ingress_prog = PROG_INGRESS_TC;
			} else {
				fprintf(stderr,
					"ingress-hook must be \"xdp\" or \"tc\"\n");
				return -EINVAL;
			}
			break;
		case 'l':
			config->bpf_config.localfilt = false;
			break;
		case 'f':
			config->force = true;
			break;
		case 'T':
			config->bpf_config.track_tcp = true;
			break;
		case 'C':
			config->bpf_config.track_icmp = true;
			break;
		case 's':
			config->bpf_config.skip_syn = false;
			break;
		case 'x':
			if (strcmp(optarg, "unspecified") == 0) {
				config->xdp_mode = XDP_MODE_UNSPEC;
			} else if (strcmp(optarg, "native") == 0) {
				config->xdp_mode = XDP_MODE_NATIVE;
			} else if (strcmp(optarg, "generic") == 0) {
				config->xdp_mode = XDP_MODE_SKB;
			} else {
				fprintf(stderr,
					"xdp-mode must be 'unspecified', 'native' or 'generic'\n");
				return -EINVAL;
			}
			break;
		case 'a':
			/* Aggregated output currently disables individual RTT */
			config->bpf_config.push_individual_events = false;
			config->bpf_config.agg_rtts = true;

			err = parse_bounded_long(&user_int, optarg, 1,
						 7 * S_PER_DAY, "aggregate");
			if (err)
				return -EINVAL;

			config->agg_conf.aggregation_interval =
				user_int * NS_PER_SECOND;
			break;
		case '4':
			err = parse_bounded_long(&user_int, optarg, 0, 32,
						 "aggregate-subnets-v4");
			if (err)
				return -EINVAL;
			config->agg_conf.ipv4_prefix_len = user_int;
			break;
		case '6':
			err = parse_bounded_long(&user_int, optarg, 0, 64,
						 "aggregate-subnets-v6");
			if (err)
				return -EINVAL;
			config->agg_conf.ipv6_prefix_len = user_int;
			break;
		case ARG_AGG_REVERSE:
			config->bpf_config.agg_by_dst = true;
			break;
		case AGG_ARG_TIMEOUT:
			err = parse_bounded_long(&user_int, optarg, 0,
						 7 * S_PER_DAY,
						 "aggregate-timeout");
			if (err)
				return -EINVAL;
			config->agg_conf.timeout_interval =
				user_int * NS_PER_SECOND;
			break;
		case 'w':
			len = strlen(optarg);
			if (len >= sizeof(config->filename)) {
				fprintf(stderr, "File name too long\n");
				return -ENAMETOOLONG;
			}

			memcpy(config->filename, optarg, len);
			config->filename[len] = '\0';
			config->write_to_file = true;
			break;
		case 'h':
			printf("HELP:\n");
			print_usage(argv);
			exit(0);
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

	config->bpf_config.ipv4_prefix_mask =
		htonl(0xffffffffUL << (32 - config->agg_conf.ipv4_prefix_len));
	config->bpf_config.ipv6_prefix_mask =
		htobe64(0xffffffffffffffffUL
			<< (64 - config->agg_conf.ipv6_prefix_len));

	return 0;
}

const char *tracked_protocols_to_str(struct pping_config *config)
{
	bool tcp = config->bpf_config.track_tcp;
	bool icmp = config->bpf_config.track_icmp;
	return tcp && icmp ? "TCP, ICMP" : tcp ? "TCP" : "ICMP";
}

const char *output_format_to_str(enum pping_output_format format)
{
	switch (format) {
	case PPING_OUTPUT_STANDARD:
		return "standard";
	case PPING_OUTPUT_JSON:
		return "json";
	case PPING_OUTPUT_PPVIZ:
		return "ppviz";
	default:
		return "unkown format";
	}
}

static int set_rlimit(long int lim)
{
	struct rlimit rlim = {
		.rlim_cur = lim,
		.rlim_max = lim,
	};

	return !setrlimit(RLIMIT_MEMLOCK, &rlim) ? 0 : -errno;
}

static int init_rodata(struct bpf_object *obj, void *src, size_t size)
{
	struct bpf_map *map = NULL;
	bpf_object__for_each_map(map, obj) {
		if (strstr(bpf_map__name(map), ".rodata"))
			return bpf_map__set_initial_value(map, src, size);
	}

	// No .rodata map found
	return -EINVAL;
}

/*
 * Attempt to attach program in section sec of obj to ifindex.
 * If sucessful, will return the positive program id of the attached.
 * On failure, will return a negative error code.
 */
static int xdp_attach(struct bpf_object *obj, const char *prog_name,
		      int ifindex, struct xdp_program **xdp_prog,
		      enum xdp_attach_mode xdp_mode)
{
	struct xdp_program *prog;
	int err;
	DECLARE_LIBXDP_OPTS(xdp_program_opts, opts,
			    .prog_name = prog_name,
			    .obj = obj);

	prog = xdp_program__create(&opts);
	if (!prog)
		return -errno;

	err = xdp_program__attach(prog, ifindex, xdp_mode, 0);
	if (err) {
		xdp_program__close(prog);
		return err;
	}

	*xdp_prog = prog;
	return 0;
}

static int xdp_detach(struct xdp_program *prog, int ifindex,
		      enum xdp_attach_mode xdp_mode)
{
	int err;

	err = xdp_program__detach(prog, ifindex, xdp_mode, 0);
	xdp_program__close(prog);
	return err;
}

/*
 * Will attempt to attach program at section sec in obj to ifindex at
 * attach_point.
 * On success, will fill in the passed opts, optionally set new_hook depending
 * if it created a new hook or not, and return the id of the attached program.
 * On failure it will return a negative error code.
 */
static int tc_attach(struct bpf_object *obj, int ifindex,
		     enum bpf_tc_attach_point attach_point,
		     const char *prog_name, struct bpf_tc_opts *opts,
		     bool *new_hook)
{
	int err;
	int prog_fd;
	bool created_hook = true;
	DECLARE_LIBBPF_OPTS(bpf_tc_hook, hook, .ifindex = ifindex,
			    .attach_point = attach_point);

	err = bpf_tc_hook_create(&hook);
	if (err == -EEXIST)
		created_hook = false;
	else if (err)
		return err;

	prog_fd = bpf_program__fd(
		bpf_object__find_program_by_name(obj, prog_name));
	if (prog_fd < 0) {
		err = prog_fd;
		goto err_after_hook;
	}

	opts->prog_fd = prog_fd;
	opts->prog_id = 0;
	err = bpf_tc_attach(&hook, opts);
	if (err)
		goto err_after_hook;

	if (new_hook)
		*new_hook = created_hook;
	return opts->prog_id;

err_after_hook:
	/*
	 * Destroy hook if it created it.
	 * This is slightly racy, as some other program may still have been
	 * attached to the hook between its creation and this error cleanup.
	 */
	if (created_hook) {
		hook.attach_point = BPF_TC_INGRESS | BPF_TC_EGRESS;
		bpf_tc_hook_destroy(&hook);
	}
	return err;
}

static int tc_detach(int ifindex, enum bpf_tc_attach_point attach_point,
		     const struct bpf_tc_opts *opts, bool destroy_hook)
{
	int err;
	int hook_err = 0;
	DECLARE_LIBBPF_OPTS(bpf_tc_hook, hook, .ifindex = ifindex,
			    .attach_point = attach_point);
	DECLARE_LIBBPF_OPTS(bpf_tc_opts, opts_info, .handle = opts->handle,
			    .priority = opts->priority);

	// Check we are removing the correct program
	err = bpf_tc_query(&hook, &opts_info);
	if (err)
		return err;
	if (opts->prog_id != opts_info.prog_id)
		return -ENOENT;

	// Attempt to detach program
	opts_info.prog_fd = 0;
	opts_info.prog_id = 0;
	opts_info.flags = 0;
	err = bpf_tc_detach(&hook, &opts_info);

	/*
	 * Attempt to destroy hook regardsless if detach succeded.
	 * If the hook is destroyed sucessfully, program should
	 * also be detached.
	 */
	if (destroy_hook) {
		hook.attach_point = BPF_TC_INGRESS | BPF_TC_EGRESS;
		hook_err = bpf_tc_hook_destroy(&hook);
	}

	err = destroy_hook ? hook_err : err;
	return err;
}

/*
 * Attach program prog_name (of typer iter/bpf_map_elem) from obj to map_name
 */
static int iter_map_attach(struct bpf_object *obj, const char *prog_name,
			   const char *map_name, struct bpf_link **link)
{
	struct bpf_program *prog;
	struct bpf_link *linkptr;
	union bpf_iter_link_info linfo = { 0 };
	int map_fd, err;
	DECLARE_LIBBPF_OPTS(bpf_iter_attach_opts, iter_opts,
			    .link_info = &linfo,
			    .link_info_len = sizeof(linfo));

	map_fd = bpf_object__find_map_fd_by_name(obj, map_name);
	if (map_fd < 0)
		return map_fd;
	linfo.map.map_fd = map_fd;

	prog = bpf_object__find_program_by_name(obj, prog_name);
	err = libbpf_get_error(prog);
	if (err)
		return err;

	linkptr = bpf_program__attach_iter(prog, &iter_opts);
	err = libbpf_get_error(linkptr);
	if (err)
		return err;

	*link = linkptr;
	return 0;
}

/*
 * Execute the iter/bpf_map_elem program attached through link on map elements
 */
static int iter_map_execute(struct bpf_link *link)
{
	int iter_fd, err;
	char buf[64];

	if (!link)
		return -EINVAL;

	iter_fd = bpf_iter_create(bpf_link__fd(link));
	if (iter_fd < 0)
		return iter_fd;

	while ((err = read(iter_fd, &buf, sizeof(buf))) > 0)
		;

	close(iter_fd);
	return err;
}

/*
 * Returns time as nanoseconds in a single __u64.
 * On failure, the value 0 is returned (and errno will be set).
 */
static __u64 get_time_ns(clockid_t clockid)
{
	struct timespec t;
	if (clock_gettime(clockid, &t) != 0)
		return 0;

	return (__u64)t.tv_sec * NS_PER_SECOND + (__u64)t.tv_nsec;
}

static void abort_main_thread(int pipe_wfd, int err)
{
	int ret = write(pipe_wfd, &err, sizeof(err));
	if (ret != sizeof(err)) {
		fprintf(stderr,
			"!!!WARNING!!! - Unable to abort main thread:\n");
	}
}

static void *periodic_map_cleanup(void *args)
{
	struct map_cleanup_args *argp = args;
	struct timespec interval;
	interval.tv_sec = argp->cleanup_interval / NS_PER_SECOND;
	interval.tv_nsec = argp->cleanup_interval % NS_PER_SECOND;
	char buf[256];
	int err1, err2;

	argp->err = 0;
	while (true) {
		err1 = iter_map_execute(argp->tsclean_link);
		if (err1) {
			// Running in separate thread so can't use get_libbpf_strerror
			libbpf_strerror(err1, buf, sizeof(buf));
			fprintf(stderr,
				"Error while cleaning timestamp map: %s\n",
				buf);
		}

		err2 = iter_map_execute(argp->flowclean_link);
		if (err2) {
			libbpf_strerror(err2, buf, sizeof(buf));
			fprintf(stderr, "Error while cleaning flow map: %s\n",
				buf);
		}

		if (err1 || err2) {
			fprintf(stderr,
				"Failed cleaning maps - aborting program\n");
			argp->err = err1 ? err1 : err2;
			abort_main_thread(argp->pipe_wfd, argp->err);
			break;
		}

		nanosleep(&interval, NULL);
	}
	pthread_exit(&argp->err);
}

static __u64 convert_monotonic_to_realtime(__u64 monotonic_time)
{
	static __u64 offset = 0;
	static __u64 offset_updated = 0;
	__u64 now_mon = get_time_ns(CLOCK_MONOTONIC);
	__u64 now_rt;

	if (offset == 0 ||
	    (now_mon > offset_updated &&
	     now_mon - offset_updated > MON_TO_REAL_UPDATE_FREQ)) {
		now_mon = get_time_ns(CLOCK_MONOTONIC);
		now_rt = get_time_ns(CLOCK_REALTIME);

		if (now_rt < now_mon)
			return 0;
		offset = now_rt - now_mon;
		offset_updated = now_mon;
	}
	return monotonic_time + offset;
}

// Stolen from xdp-tool/lib/util/util.c
int try_snprintf(char *buf, size_t buf_len, const char *format, ...)
{
	va_list args;
	int len;

	va_start(args, format);
	len = vsnprintf(buf, buf_len, format, args);
	va_end(args);

	if (len < 0)
		return -EINVAL;
	else if ((size_t)len >= buf_len)
		return -ENAMETOOLONG;

	return 0;
}

/*
 * Is the passed ip an IPv4 address mapped into the IPv6 space as specified by
 * RFC 4291 sec 2.5.5.2?
 */
static bool is_ipv4_in_ipv6(const struct in6_addr *ip)
{
	__u16 ipv4_prefix[] = { 0x0, 0x0, 0x0, 0x0, 0x0, 0xFFFF };

	return memcmp(ipv4_prefix, ip, sizeof(ipv4_prefix)) == 0;
}

/*
 * Wrapper around inet_ntop designed to handle the "bug" that mapped IPv4
 * addresses are formated as IPv6 addresses for AF_INET6
 */
static int format_ip_address(char *buf, size_t size, int af,
			     const struct in6_addr *addr)
{
	if (af == AF_UNSPEC)
		af = is_ipv4_in_ipv6(addr) ? AF_INET : AF_INET6;

	if (af == AF_INET)
		return inet_ntop(af, &addr->s6_addr[12], buf, size) ? -errno :
								      0;
	else if (af == AF_INET6)
		return inet_ntop(af, addr, buf, size) ? -errno : 0;
	return -EINVAL;
}

/* Formats IPv4 or IPv6 IP-prefix string from a struct ipprefix_key */
static int format_ipprefix(char *buf, size_t size, int af,
			   struct ipprefix_key *prefix, __u8 prefix_len)
{
	union {
		struct in_addr ipv4;
		struct in6_addr ipv6;
	} ip;
	size_t iplen;
	int err;

	if (af == AF_INET) {
		if (size < INET_PREFIXSTRLEN)
			return -ENOSPC;
		if (prefix_len > 32)
			return -EINVAL;

		ip.ipv4.s_addr = prefix->v4;
	} else if (af == AF_INET6) {
		if (size < INET6_PREFIXSTRLEN)
			return -ENOSPC;
		if (prefix_len > 64)
			return -EINVAL;

		memcpy(&ip.ipv6, &prefix->v6, sizeof(__u64));
		memset(&ip.ipv6.s6_addr32[2], 0, sizeof(__u64));
	} else {
		return -EINVAL;
	}

	err = inet_ntop(af, &ip, buf, size) ? 0 : -errno;
	if (err)
		return err;

	iplen = strlen(buf);
	err = try_snprintf(buf + iplen, size - iplen, "/%u", prefix_len);
	buf[size - 1] = '\0';

	return err;
}

static char *ipproto_to_str(char *buf, size_t size, __u8 proto)
{
	/* Rather than doing additional checks to ensure we return a null
           terminated truncated string, just outright fail if passed buffer
           is too small to fit largest possible string */
	if (size < 7)
		return NULL;

	switch (proto) {
	case IPPROTO_TCP:
		strcpy(buf, "TCP");
		break;
	case IPPROTO_ICMP:
		strcpy(buf, "ICMP");
		break;
	case IPPROTO_ICMPV6:
		strcpy(buf, "ICMPv6");
		break;
	default:
		snprintf(buf, size, "%d", proto);
		break;
	}

	return buf;
}

static const char *flowevent_to_str(enum flow_event_type fe)
{
	switch (fe) {
	case FLOW_EVENT_NONE:
		return "none";
	case FLOW_EVENT_OPENING:
		return "opening";
	case FLOW_EVENT_CLOSING:
	case FLOW_EVENT_CLOSING_BOTH:
		return "closing";
	default:
		return "unknown";
	}
}

static const char *eventreason_to_str(enum flow_event_reason er)
{
	switch (er) {
	case EVENT_REASON_NONE:
		return "none";
	case EVENT_REASON_SYN:
		return "SYN";
	case EVENT_REASON_SYN_ACK:
		return "SYN-ACK";
	case EVENT_REASON_FIRST_OBS_PCKT:
		return "first observed packet";
	case EVENT_REASON_FIN:
		return "FIN";
	case EVENT_REASON_RST:
		return "RST";
	case EVENT_REASON_FLOW_TIMEOUT:
		return "flow timeout";
	default:
		return "unknown";
	}
}

static const char *eventsource_to_str(enum flow_event_source es)
{
	switch (es) {
	case EVENT_SOURCE_PKT_SRC:
		return "src";
	case EVENT_SOURCE_PKT_DEST:
		return "dest";
	case EVENT_SOURCE_GC:
		return "garbage collection";
	default:
		return "unknown";
	}
}

static void print_flow_ppvizformat(FILE *stream,
				   const struct network_tuple *flow)
{
	char saddr[INET6_ADDRSTRLEN];
	char daddr[INET6_ADDRSTRLEN];

	format_ip_address(saddr, sizeof(saddr), flow->ipv, &flow->saddr.ip);
	format_ip_address(daddr, sizeof(daddr), flow->ipv, &flow->daddr.ip);
	fprintf(stream, "%s:%d+%s:%d", saddr, ntohs(flow->saddr.port), daddr,
		ntohs(flow->daddr.port));
}

static void print_ns_datetime(FILE *stream, __u64 monotonic_ns)
{
	char timestr[9];
	__u64 ts = convert_monotonic_to_realtime(monotonic_ns);
	time_t ts_s = ts / NS_PER_SECOND;

	strftime(timestr, sizeof(timestr), "%H:%M:%S", localtime(&ts_s));
	fprintf(stream, "%s.%09llu", timestr, ts % NS_PER_SECOND);
}

static void print_event_standard(FILE *stream, const union pping_event *e)
{
	char protostr[16];

	if (e->event_type == EVENT_TYPE_RTT) {
		print_ns_datetime(stream, e->rtt_event.timestamp);
		fprintf(stream, " %.6g ms %.6g ms %s ",
			(double)e->rtt_event.rtt / NS_PER_MS,
			(double)e->rtt_event.min_rtt / NS_PER_MS,
			ipproto_to_str(protostr, sizeof(protostr),
				       e->rtt_event.flow.proto));
		print_flow_ppvizformat(stream, &e->rtt_event.flow);
		fprintf(stream, "\n");
	} else if (e->event_type == EVENT_TYPE_FLOW) {
		print_ns_datetime(stream, e->flow_event.timestamp);
		fprintf(stream, " %s ",
			ipproto_to_str(protostr, sizeof(protostr),
				       e->rtt_event.flow.proto));
		print_flow_ppvizformat(stream, &e->flow_event.flow);
		fprintf(stream, " %s due to %s from %s\n",
			flowevent_to_str(e->flow_event.flow_event_type),
			eventreason_to_str(e->flow_event.reason),
			eventsource_to_str(e->flow_event.source));
	}
}

static void print_event_ppviz(FILE *stream, const union pping_event *e)
{
	// ppviz format does not support flow events
	if (e->event_type != EVENT_TYPE_RTT)
		return;

	const struct rtt_event *re = &e->rtt_event;
	__u64 time = convert_monotonic_to_realtime(re->timestamp);

	fprintf(stream, "%.9g %.9g %.9g ", (double)time / NS_PER_SECOND,
		(double)re->rtt / NS_PER_SECOND,
		(double)re->min_rtt / NS_PER_SECOND);
	print_flow_ppvizformat(stream, &re->flow);
	fprintf(stream, "\n");
}

static void print_common_fields_json(json_writer_t *ctx,
				     const union pping_event *e)
{
	const struct network_tuple *flow = &e->rtt_event.flow;
	char saddr[INET6_ADDRSTRLEN];
	char daddr[INET6_ADDRSTRLEN];
	char protostr[16];

	format_ip_address(saddr, sizeof(saddr), flow->ipv, &flow->saddr.ip);
	format_ip_address(daddr, sizeof(daddr), flow->ipv, &flow->daddr.ip);

	jsonw_u64_field(ctx, "timestamp",
			convert_monotonic_to_realtime(e->rtt_event.timestamp));
	jsonw_string_field(ctx, "src_ip", saddr);
	jsonw_hu_field(ctx, "src_port", ntohs(flow->saddr.port));
	jsonw_string_field(ctx, "dest_ip", daddr);
	jsonw_hu_field(ctx, "dest_port", ntohs(flow->daddr.port));
	jsonw_string_field(ctx, "protocol",
			   ipproto_to_str(protostr, sizeof(protostr),
					  flow->proto));
}

static void print_rttevent_fields_json(json_writer_t *ctx,
				       const struct rtt_event *re)
{
	jsonw_u64_field(ctx, "rtt", re->rtt);
	jsonw_u64_field(ctx, "min_rtt", re->min_rtt);
	jsonw_u64_field(ctx, "sent_packets", re->sent_pkts);
	jsonw_u64_field(ctx, "sent_bytes", re->sent_bytes);
	jsonw_u64_field(ctx, "rec_packets", re->rec_pkts);
	jsonw_u64_field(ctx, "rec_bytes", re->rec_bytes);
	jsonw_bool_field(ctx, "match_on_egress", re->match_on_egress);
}

static void print_flowevent_fields_json(json_writer_t *ctx,
					const struct flow_event *fe)
{
	jsonw_string_field(ctx, "flow_event",
			   flowevent_to_str(fe->flow_event_type));
	jsonw_string_field(ctx, "reason", eventreason_to_str(fe->reason));
	jsonw_string_field(ctx, "triggered_by", eventsource_to_str(fe->source));
}

static void print_event_json(json_writer_t *jctx, const union pping_event *e)
{
	if (e->event_type != EVENT_TYPE_RTT && e->event_type != EVENT_TYPE_FLOW)
		return;

	jsonw_start_object(jctx);
	print_common_fields_json(jctx, e);
	if (e->event_type == EVENT_TYPE_RTT)
		print_rttevent_fields_json(jctx, &e->rtt_event);
	else // flow-event
		print_flowevent_fields_json(jctx, &e->flow_event);
	jsonw_end_object(jctx);
}

static void print_event(struct output_context *out_ctx,
			const union pping_event *pe)
{
	if (!out_ctx->stream)
		return;

	switch (out_ctx->format) {
	case PPING_OUTPUT_STANDARD:
		print_event_standard(out_ctx->stream, pe);
		break;
	case PPING_OUTPUT_JSON:
		if (out_ctx->jctx)
			print_event_json(out_ctx->jctx, pe);
		break;
	case PPING_OUTPUT_PPVIZ:
		print_event_ppviz(out_ctx->stream, pe);
		break;
	}
}

static void warn_map_full(FILE *stream, const struct map_full_event *e)
{
	print_ns_datetime(stream, e->timestamp);
	fprintf(stream, " Warning: Unable to create %s entry for flow ",
		e->map == PPING_MAP_FLOWSTATE ? "flow" : "timestamp");
	print_flow_ppvizformat(stream, &e->flow);
	fprintf(stream, "\n");
}

static void print_map_clean_info(FILE *stream, const struct map_clean_event *e)
{
	fprintf(stream,
		"%s: cycle: %u, entries: %u, time: %llu, timeout: %u, tot timeout: %llu, selfdel: %u, tot selfdel: %llu\n",
		e->map == PPING_MAP_PACKETTS ? "packet_ts" : "flow_state",
		e->clean_cycles, e->last_processed_entries, e->last_runtime,
		e->last_timeout_del, e->tot_timeout_del, e->last_auto_del,
		e->tot_auto_del);
}

static void handle_event(void *ctx, int cpu, void *data, __u32 data_size)
{
	struct output_context *out_ctx = *(struct output_context **)ctx;
	const union pping_event *e = data;

	if (data_size < sizeof(e->event_type))
		return;

	switch (e->event_type) {
	case EVENT_TYPE_MAP_FULL:
		warn_map_full(stderr, &e->map_event);
		break;
	case EVENT_TYPE_MAP_CLEAN:
		print_map_clean_info(stderr, &e->map_clean_event);
		break;
	case EVENT_TYPE_RTT:
	case EVENT_TYPE_FLOW:
		print_event(out_ctx, e);
		break;
	default:
		fprintf(stderr, "Warning: Unknown event type %llu\n",
			e->event_type);
	};
}

static void handle_missed_events(void *ctx, int cpu, __u64 lost_cnt)
{
	fprintf(stderr, "Lost %llu events on CPU %d\n", lost_cnt, cpu);
}

static bool ecncounters_empty(const struct ecn_counters *counters)
{
	static const struct ecn_counters empty = { 0 };

	return memcmp(counters, &empty, sizeof(empty)) == 0;
}

static bool pping_errors_empty(const struct pping_error_counters *errors)
{
	static const struct pping_error_counters empty = { 0 };

	return memcmp(errors, &empty, sizeof(empty)) == 0;
}

static void print_counter_standard(FILE *stream, const char *name, __u64 val,
				   bool *first)
{
	if (val == 0)
		return;

	if (*first)
		*first = false;
	else
		fprintf(stream, ", ");

	fprintf(stream, "%s=%llu", name, val);
}

static void print_pktbytes_tuple_standard(FILE *stream, const char *tuple_name,
					  __u64 pkts, __u64 bytes,
					  bool *first_tuple)
{
	bool first = true;

	if (pkts == 0)
		return;

	if (*first_tuple)
		*first_tuple = false;
	else
		fprintf(stream, ", ");

	fprintf(stream, "%s=(", tuple_name);
	print_counter_standard(stream, "pkts", pkts, &first);
	print_counter_standard(stream, "bytes", bytes, &first);
	fprintf(stream, ")");
}

static void print_ecncounters_standard(FILE *stream,
				       const struct ecn_counters *counters)
{
	bool first = true;

	fprintf(stream, "ECN=(");
	print_counter_standard(stream, "Not-ECT", counters->no_ect, &first);
	print_counter_standard(stream, "ECT1", counters->ect1, &first);
	print_counter_standard(stream, "ECT0", counters->ect0, &first);
	print_counter_standard(stream, "CE", counters->ce, &first);
	fprintf(stream, ")");
}

static void
print_ppingerrors_standard(FILE *stream,
			   const struct pping_error_counters *errors)
{
	bool first = true;

	fprintf(stream, "errors=(");
	print_counter_standard(stream, "store-packet-ts", errors->pktts_store,
			       &first);
	print_counter_standard(stream, "create-flow-state", errors->flow_create,
			       &first);
	print_counter_standard(stream, "create-agg-subnet-state",
			       errors->agg_subnet_create, &first);
	fprintf(stream, ")");
}

static void
print_globalcounters_standard(FILE *stream, __u64 t_monotonic,
			      const struct global_counters *counters)
{
	char protostr[16];
	bool first = true;
	int proto;

	print_ns_datetime(stream, t_monotonic);
	fprintf(stream, ": ");

	print_pktbytes_tuple_standard(stream, "non-IP", counters->nonip_pkts,
				      counters->nonip_bytes, &first);
	print_pktbytes_tuple_standard(stream, "TCP", counters->tcp_pkts,
				      counters->tcp_bytes, &first);
	print_pktbytes_tuple_standard(stream, "UDP", counters->udp_pkts,
				      counters->udp_bytes, &first);
	print_pktbytes_tuple_standard(stream, "ICMP", counters->icmp_pkts,
				      counters->icmp_bytes, &first);
	print_pktbytes_tuple_standard(stream, "ICMPv6", counters->icmp6_pkts,
				      counters->icmp6_bytes, &first);

	for (proto = 0; proto < N_IPPROTOS; proto++) {
		if (counters->other_ipprotos[proto] > 0) { // Check to avoid uncecessary ipproto_to_str
			ipproto_to_str(protostr, sizeof(protostr), proto);
			print_pktbytes_tuple_standard(
				stream, protostr,
				counters->other_ipprotos[proto], 0, &first);
		}
	}

	if (first) // Global counters are empty
		fprintf(stream, "pkts=0, bytes=0");

	if (!ecncounters_empty(&counters->ecn)) {
		fprintf(stream, ", ");
		print_ecncounters_standard(stream, &counters->ecn);
	}

	if (!pping_errors_empty(&counters->err)) {
		fprintf(stream, ", ");
		print_ppingerrors_standard(stream, &counters->err);
	}

	fprintf(stream, "\n");
}

static void print_counter_json(json_writer_t *jctx, const char *name, __u64 val)
{
	if (val > 0)
		jsonw_u64_field(jctx, name, val);
}

static void print_pktbytes_tuple_json(json_writer_t *jctx,
				      const char *tuple_name, __u64 pkts,
				      __u64 bytes)
{
	// Don't include empty pkt/byte tuples
	if (pkts == 0)
		return;

	jsonw_name(jctx, tuple_name);
	jsonw_start_object(jctx);
	print_counter_json(jctx, "packets", pkts);
	print_counter_json(jctx, "bytes", bytes);
	jsonw_end_object(jctx);
}

static void print_ecncounters_json(json_writer_t *jctx,
				   const struct ecn_counters *counters)
{
	jsonw_start_object(jctx);
	print_counter_json(jctx, "no_ECT", counters->no_ect);
	print_counter_json(jctx, "ECT1", counters->ect1);
	print_counter_json(jctx, "ECT0", counters->ect0);
	print_counter_json(jctx, "CE", counters->ce);
	jsonw_end_object(jctx);
}

static void print_ppingerrors_json(json_writer_t *jctx,
				   const struct pping_error_counters *errors)
{
	jsonw_start_object(jctx);
	print_counter_json(jctx, "store_packet_ts", errors->pktts_store);
	print_counter_json(jctx, "create_flow_state", errors->flow_create);
	print_counter_json(jctx, "create_agg_subnet_state",
			   errors->agg_subnet_create);
	jsonw_end_object(jctx);
}

static void print_globalcounters_json(json_writer_t *jctx, __u64 t_monotonic,
				      const struct global_counters *counters)
{
	char protostr[16];
	int proto;

	jsonw_start_object(jctx);
	jsonw_u64_field(jctx, "timestamp",
			convert_monotonic_to_realtime(t_monotonic));

	jsonw_name(jctx, "protocol_counters");
	jsonw_start_object(jctx);

	print_pktbytes_tuple_json(jctx, "non_IP", counters->nonip_pkts,
				  counters->nonip_bytes);
	print_pktbytes_tuple_json(jctx, "TCP", counters->tcp_pkts,
				  counters->tcp_bytes);
	print_pktbytes_tuple_json(jctx, "UDP", counters->udp_pkts,
				  counters->udp_bytes);
	print_pktbytes_tuple_json(jctx, "ICMP", counters->icmp_pkts,
				  counters->icmp_bytes);
	print_pktbytes_tuple_json(jctx, "ICMPv6", counters->icmp6_pkts,
				  counters->icmp6_bytes);

	for (proto = 0; proto < N_IPPROTOS; proto++) {
		if (counters->other_ipprotos[proto] > 0) {
			ipproto_to_str(protostr, sizeof(protostr), proto);
			print_pktbytes_tuple_json(
				jctx, protostr, counters->other_ipprotos[proto],
				0);
		}
	}

	jsonw_end_object(jctx);

	jsonw_name(jctx, "ecn_counters");
	print_ecncounters_json(jctx, &counters->ecn);

	jsonw_name(jctx, "errors");
	print_ppingerrors_json(jctx, &counters->err);

	jsonw_end_object(jctx);
}

static void print_globalcounters(struct output_context *out_ctx,
				 __u64 t_monotonic,
				 const struct global_counters *counters)
{
	if (out_ctx->format == PPING_OUTPUT_STANDARD)
		print_globalcounters_standard(out_ctx->stream, t_monotonic,
					      counters);
	else if (out_ctx->jctx)
		print_globalcounters_json(out_ctx->jctx, t_monotonic, counters);
}

static void update_ecncounters(struct ecn_counters *to,
			       const struct ecn_counters *from)
{
	to->no_ect += from->no_ect;
	to->ect1 += from->ect1;
	to->ect0 += from->ect0;
	to->ce += from->ce;
}

static void update_pping_errors(struct pping_error_counters *to,
				const struct pping_error_counters *from)
{
	to->pktts_store += from->pktts_store;
	to->flow_create += from->flow_create;
	to->agg_subnet_create += from->agg_subnet_create;
}

static void update_globalcounters(struct global_counters *to,
				  const struct global_counters *from)
{
	int proto;

	to->nonip_pkts += from->nonip_pkts;
	to->nonip_bytes += from->nonip_bytes;
	to->tcp_pkts += from->tcp_pkts;
	to->tcp_bytes += from->tcp_bytes;
	to->udp_pkts += from->udp_pkts;
	to->udp_bytes += from->udp_bytes;
	to->icmp_pkts += from->icmp_pkts;
	to->icmp_bytes += from->icmp_bytes;
	to->icmp6_pkts += from->icmp6_pkts;
	to->icmp6_bytes += from->icmp6_bytes;

	for (proto = 0; proto < N_IPPROTOS; proto++) {
		to->other_ipprotos[proto] += from->other_ipprotos[proto];
	}

	update_ecncounters(&to->ecn, &from->ecn);
	update_pping_errors(&to->err, &from->err);
}

static void merge_percpu_globalcounters(struct global_counters *merged,
					const struct global_counters *percpu,
					int n_cpus)
{
	int cpu;

	memset(merged, 0, sizeof(*merged));

	for (cpu = 0; cpu < n_cpus; cpu++) {
		update_globalcounters(merged, &percpu[cpu]);
	}
}

static void diff_ecncounters(struct ecn_counters *diff,
			     const struct ecn_counters *prev,
			     const struct ecn_counters *next)
{
	diff->no_ect = next->no_ect - prev->no_ect;
	diff->ect1 = next->ect1 - prev->ect1;
	diff->ect0 = next->ect0 - prev->ect0;
	diff->ce = next->ce - prev->ce;
}

static void diff_pping_errors(struct pping_error_counters *diff,
			      const struct pping_error_counters *prev,
			      const struct pping_error_counters *next)
{
	diff->pktts_store = next->pktts_store - prev->pktts_store;
	diff->flow_create = next->flow_create - prev->flow_create;
	diff->agg_subnet_create =
		next->agg_subnet_create - prev->agg_subnet_create;
}

static void diff_globalcounters(struct global_counters *diff,
				const struct global_counters *prev,
				const struct global_counters *next)
{
	int proto;

	diff->nonip_pkts = next->nonip_pkts - prev->nonip_pkts;
	diff->nonip_bytes = next->nonip_bytes - prev->nonip_bytes;
	diff->tcp_pkts = next->tcp_pkts - prev->tcp_pkts;
	diff->tcp_bytes = next->tcp_bytes - prev->tcp_bytes;
	diff->udp_pkts = next->udp_pkts - prev->udp_pkts;
	diff->udp_bytes = next->udp_bytes - prev->udp_bytes;
	diff->icmp_pkts = next->icmp_pkts - prev->icmp_pkts;
	diff->icmp_bytes = next->icmp_bytes - prev->icmp_bytes;
	diff->icmp6_pkts = next->icmp6_pkts - prev->icmp6_pkts;
	diff->icmp6_bytes = next->icmp6_bytes - prev->icmp6_bytes;

	for (proto = 0; proto < N_IPPROTOS; proto++) {
		diff->other_ipprotos[proto] = next->other_ipprotos[proto] -
					      prev->other_ipprotos[proto];
	}

	diff_ecncounters(&diff->ecn, &prev->ecn, &next->ecn);
	diff_pping_errors(&diff->err, &prev->err, &next->err);
}

static int report_globalcounters(struct output_context *out_ctx,
				 struct aggregation_context *agg_ctx)
{
	int n_cpus = libbpf_num_possible_cpus();
	__u64 t = get_time_ns(CLOCK_MONOTONIC);
	struct global_counters tot_cnt, diff;
	struct global_counters *cpu_cnt;
	__u32 key = 0;
	int err;

	cpu_cnt = calloc(n_cpus, sizeof(*cpu_cnt));
	if (!cpu_cnt)
		return -errno;

	err = bpf_map_lookup_elem(agg_ctx->maps.map_globcnt_fd, &key, cpu_cnt);
	if (err)
		goto exit;

	merge_percpu_globalcounters(&tot_cnt, cpu_cnt, n_cpus);
	diff_globalcounters(&diff, &agg_ctx->prev_counters, &tot_cnt);
	agg_ctx->prev_counters = tot_cnt;

	print_globalcounters(out_ctx, t, &diff);

exit:
	free(cpu_cnt);
	return err;
}

static __u64 sum_trafficcounts_pkts(const struct traffic_counters *counters)
{
	return counters->tcp_ts_pkts + counters->tcp_nots_pkts +
	       counters->other_pkts;
}

static __u64 sum_trafficcounts_bytes(const struct traffic_counters *counters)
{
	return counters->tcp_ts_bytes + counters->tcp_nots_bytes +
	       counters->other_bytes;
}

static bool trafficcounts_empty(const struct traffic_counters *counters)
{
	static const struct traffic_counters empty = { 0 };

	return memcmp(counters, &empty, sizeof(empty)) == 0;
}

static bool aggregated_stats_empty(struct aggregated_stats *stats)
{
	return trafficcounts_empty(&stats->rx_stats) &&
	       trafficcounts_empty(&stats->tx_stats);
}

static bool aggregated_stats_nortts(struct aggregated_stats *stats)
{
	return stats->rtt_max == 0;
}

static __u64 aggregated_stats_maxbins(struct aggregated_stats *stats,
				      __u64 bin_width, __u64 n_bins)
{
	return stats->rtt_max / bin_width < n_bins ?
		       stats->rtt_max / bin_width + 1 :
		       n_bins;
}

static void add_trafficcounts(struct traffic_counters *to,
			      const struct traffic_counters *from)
{
	to->tcp_ts_pkts += from->tcp_ts_pkts;
	to->tcp_ts_bytes += from->tcp_ts_bytes;
	to->tcp_nots_pkts += from->tcp_nots_pkts;
	to->tcp_nots_bytes += from->tcp_nots_bytes;
	to->other_pkts += from->other_pkts;
	to->other_bytes += from->other_bytes;
}

static void update_aggregated_stats(struct aggregated_stats *to_stats,
				    struct aggregated_stats *from_stats,
				    int n_bins)
{
	int bin;

	if (from_stats->last_updated > to_stats->last_updated)
		to_stats->last_updated = from_stats->last_updated;

	add_trafficcounts(&to_stats->rx_stats, &from_stats->rx_stats);
	add_trafficcounts(&to_stats->tx_stats, &from_stats->tx_stats);

	if (aggregated_stats_nortts(from_stats))
		return;

	if (from_stats->rtt_max > to_stats->rtt_max)
		to_stats->rtt_max = from_stats->rtt_max;
	if (to_stats->rtt_min == 0 || from_stats->rtt_min < to_stats->rtt_min)
		to_stats->rtt_min = from_stats->rtt_min;

	for (bin = 0; bin < n_bins; bin++)
		to_stats->rtt_bins[bin] += from_stats->rtt_bins[bin];
}

static void merge_percpu_aggreated_stats(struct aggregated_stats *percpu_stats,
					 struct aggregated_stats *merged_stats,
					 int n_cpus, int n_bins)
{
	int i;

	memset(merged_stats, 0, sizeof(*merged_stats));

	for (i = 0; i < n_cpus; i++)
		update_aggregated_stats(merged_stats, &percpu_stats[i], n_bins);
}

static void clear_aggregated_stats(struct aggregated_stats *stats)
{
	__u64 last_updated = stats->last_updated;
	memset(stats, 0, sizeof(*stats));
	stats->last_updated = last_updated;
}

static void print_aggmetadata_standard(FILE *stream,
				       struct aggregation_config *agg_conf)
{
	fprintf(stream,
		"Aggregating RTTs in histograms with %llu %.6g ms wide bins every %.9g seconds\n",
		agg_conf->n_bins, (double)agg_conf->bin_width / NS_PER_MS,
		(double)agg_conf->aggregation_interval / NS_PER_SECOND);
}

static void print_aggmetadata_json(json_writer_t *ctx,
				   struct aggregation_config *agg_conf)
{
	jsonw_start_object(ctx);

	jsonw_u64_field(ctx, "timestamp", get_time_ns(CLOCK_REALTIME));
	jsonw_u64_field(ctx, "bins", agg_conf->n_bins);
	jsonw_u64_field(ctx, "bin_width_ns", agg_conf->bin_width);
	jsonw_u64_field(ctx, "aggregation_interval_ns",
			agg_conf->aggregation_interval);
	jsonw_u64_field(ctx, "timeout_interval_ns", agg_conf->timeout_interval);
	jsonw_uint_field(ctx, "ipv4_prefix_len", agg_conf->ipv4_prefix_len);
	jsonw_uint_field(ctx, "ipv6_prefix_len", agg_conf->ipv6_prefix_len);

	jsonw_end_object(ctx);
}

static void print_aggmetadata(struct output_context *out_ctx,
			      struct aggregation_config *agg_conf)
{
	if (!out_ctx->stream)
		return;

	if (out_ctx->format == PPING_OUTPUT_STANDARD)
		print_aggmetadata_standard(out_ctx->stream, agg_conf);
	else if (out_ctx->jctx)
		print_aggmetadata_json(out_ctx->jctx, agg_conf);
}

static void print_aggstats_standard(FILE *stream, __u64 t,
				    const char *prefixstr,
				    struct aggregated_stats *stats,
				    struct aggregation_config *agg_conf)
{
	__u64 bw = agg_conf->bin_width;
	__u64 nb = aggregated_stats_maxbins(stats, bw, agg_conf->n_bins);

	print_ns_datetime(stream, t);
	fprintf(stream,
		": %s -> rxpkts=%llu, rxbytes=%llu, txpkts=%llu, txbytes=%llu",
		prefixstr, sum_trafficcounts_pkts(&stats->rx_stats),
		sum_trafficcounts_bytes(&stats->rx_stats),
		sum_trafficcounts_pkts(&stats->tx_stats),
		sum_trafficcounts_bytes(&stats->tx_stats));

	if (aggregated_stats_nortts(stats))
		goto exit;

	fprintf(stream,
		", rtt-count=%llu, min=%.6g ms, mean=%g ms, median=%g ms, p95=%g ms, max=%.6g ms",
		lhist_count(stats->rtt_bins, nb),
		(double)stats->rtt_min / NS_PER_MS,
		lhist_mean(stats->rtt_bins, nb, bw, 0) / NS_PER_MS,
		lhist_percentile(stats->rtt_bins, 50, nb, bw, 0) / NS_PER_MS,
		lhist_percentile(stats->rtt_bins, 95, nb, bw, 0) / NS_PER_MS,
		(double)stats->rtt_max / NS_PER_MS);

exit:
	fprintf(stream, "\n");
}

static void print_trafficcount_json(json_writer_t *jctx,
				    const struct traffic_counters *counters)
{
	jsonw_start_object(jctx);

	print_pktbytes_tuple_json(jctx, "TCP_TS", counters->tcp_ts_pkts,
				  counters->tcp_ts_bytes);
	print_pktbytes_tuple_json(jctx, "TCP_noTS", counters->tcp_nots_pkts,
				  counters->tcp_nots_bytes);
	print_pktbytes_tuple_json(jctx, "other", counters->other_pkts,
				  counters->other_bytes);
	jsonw_end_object(jctx);
}

static void print_aggstats_json(json_writer_t *ctx, __u64 t,
				const char *prefixstr,
				struct aggregated_stats *stats,
				struct aggregation_config *agg_conf)
{
	__u64 bw = agg_conf->bin_width;
	__u64 nb = aggregated_stats_maxbins(stats, bw, agg_conf->n_bins);
	int i;

	jsonw_start_object(ctx);
	jsonw_u64_field(ctx, "timestamp", convert_monotonic_to_realtime(t));
	jsonw_string_field(ctx, "ip_prefix", prefixstr);

	jsonw_name(ctx, "rx_stats");
	print_trafficcount_json(ctx, &stats->rx_stats);
	jsonw_name(ctx, "tx_stats");
	print_trafficcount_json(ctx, &stats->tx_stats);

	if (aggregated_stats_nortts(stats))
		goto exit;

	jsonw_u64_field(ctx, "count_rtt", lhist_count(stats->rtt_bins, nb));
	jsonw_u64_field(ctx, "min_rtt", stats->rtt_min);
	jsonw_float_field(ctx, "mean_rtt",
			  lhist_mean(stats->rtt_bins, nb, bw, 0));
	jsonw_float_field(ctx, "median_rtt",
			  lhist_percentile(stats->rtt_bins, 50, nb, bw, 0));
	jsonw_float_field(ctx, "p95_rtt",
			  lhist_percentile(stats->rtt_bins, 95, nb, bw, 0));
	jsonw_u64_field(ctx, "max_rtt", stats->rtt_max);

	jsonw_name(ctx, "histogram");
	jsonw_start_array(ctx);
	for (i = 0; i < nb; i++)
		jsonw_uint(ctx, stats->rtt_bins[i]);
	jsonw_end_array(ctx);

exit:
	jsonw_end_object(ctx);
}

static void print_aggregated_stats(struct output_context *out_ctx, __u64 t,
				   struct ipprefix_key *prefix, int af,
				   __u8 prefix_len,
				   struct aggregated_stats *stats,
				   struct aggregation_config *agg_conf)
{
	char prefixstr[INET6_PREFIXSTRLEN] = { 0 };

	if (!out_ctx->stream)
		return;

	format_ipprefix(prefixstr, sizeof(prefixstr), af, prefix, prefix_len);

	if (out_ctx->format == PPING_OUTPUT_STANDARD)
		print_aggstats_standard(out_ctx->stream, t, prefixstr, stats,
					agg_conf);
	else if (out_ctx->jctx)
		print_aggstats_json(out_ctx->jctx, t, prefixstr, stats,
				    agg_conf);
}

// Stolen from BPF selftests
int kern_sync_rcu(void)
{
	return syscall(__NR_membarrier, MEMBARRIER_CMD_SHARED, 0, 0);
}

/* Changes which map the BPF progs use to aggregate the RTTs in.
 * On success returns the map idx that the BPF progs used BEFORE the switch
 * (and thus the map filled with data up until the switch, but no longer
 * beeing activly used by the BPF progs).
 * On failure returns a negative error code */
static int switch_agg_map(int map_active_fd)
{
	__u32 prev_map, next_map, key = 0;
	int err;

	// Get current map being used by BPF progs
	err = bpf_map_lookup_elem(map_active_fd, &key, &prev_map);
	if (err)
		return err;

	// Swap map being used by BPF progs to agg RTTs in
	next_map = prev_map == 1 ? 0 : 1;
	err = bpf_map_update_elem(map_active_fd, &key, &next_map, BPF_EXIST);
	if (err)
		return err;

	// Wait for current BPF programs to finish
	// This should garantuee that after this call no BPF progs will attempt
	// to update the now inactive maps
	kern_sync_rcu();

	return prev_map;
}

static void report_aggregated_stats_mapentry(
	struct output_context *out_ctx, struct ipprefix_key *prefix,
	struct aggregated_stats *percpu_stats, int n_cpus, int af,
	__u8 prefix_len, __u64 t_monotonic, struct aggregation_config *agg_conf,
	bool *del_entry)
{
	struct aggregated_stats merged_stats;
	struct ipprefix_key backup_key = { 0 };
	int i;

	// Report the backup keys as 0.0.0.0/0 or ::/0
	if ((af == AF_INET && prefix->v4 == IPV4_BACKUP_KEY) ||
	    (af == AF_INET6 && prefix->v6 == IPV6_BACKUP_KEY)) {
		prefix = &backup_key;
		prefix_len = 0;
	}

	merge_percpu_aggreated_stats(percpu_stats, &merged_stats, n_cpus,
				     agg_conf->n_bins);

	if (prefix_len > 0 && // Pointless deleting /0 entry, and ensures backup keys are never deleted
	    agg_conf->timeout_interval > 0 &&
	    merged_stats.last_updated < t_monotonic &&
	    t_monotonic - merged_stats.last_updated >
		    agg_conf->timeout_interval)
		*del_entry = true;
	else
		*del_entry = false;

	// Only print and clear prefixes which have seen traffic
	if (!aggregated_stats_empty(&merged_stats)) {
		print_aggregated_stats(out_ctx, t_monotonic, prefix, af,
				       prefix_len, &merged_stats, agg_conf);

		// Clear out the reported stats
		if (!*del_entry)
			for (i = 0; i < n_cpus; i++) {
				clear_aggregated_stats(&percpu_stats[i]);
			}
	}
}

static int report_aggregated_stats_map(struct output_context *out_ctx,
				       int map_fd, int af, __u8 prefix_len,
				       __u64 t_monotonic,
				       struct aggregation_config *agg_conf)
{
	struct aggregated_stats *values = NULL;
	void *keys = NULL, *del_keys = NULL;
	int n_cpus = libbpf_num_possible_cpus();
	size_t keysize = af == AF_INET ? sizeof(__u32) : sizeof(__u64);
	__u64 batch, total = 0;
	__u32 count = AGG_BATCH_SIZE, del_idx = 0;
	bool remaining_entries = true;
	int err = 0, i;
	bool del_key;

	DECLARE_LIBBPF_OPTS(bpf_map_batch_opts, batch_opts, .flags = BPF_EXIST);

	values = calloc(n_cpus, sizeof(*values) * AGG_BATCH_SIZE);
	keys = calloc(AGG_BATCH_SIZE, keysize);
	del_keys = calloc(MAP_AGGREGATION_SIZE, keysize);
	if (!values || !keys || !del_keys) {
		err = -ENOMEM;
		goto exit;
	}

	while (remaining_entries) {
		err = bpf_map_lookup_batch(map_fd, total ? &batch : NULL,
					   &batch, keys, values, &count, NULL);
		if (err == -ENOENT) {
			remaining_entries = false;
			err = 0;
		} else if (err) {
			goto exit;
		}

		for (i = 0; i < count; i++) {
			report_aggregated_stats_mapentry(
				out_ctx, keys + i * keysize,
				values + i * n_cpus, n_cpus, af, prefix_len,
				t_monotonic, agg_conf, &del_key);

			if (del_key)
				memcpy(del_keys + del_idx++ * keysize,
				       keys + i * keysize, keysize);
		}

		// Update cleared stats
		err = bpf_map_update_batch(map_fd, keys, values, &count,
					   &batch_opts);
		if (err)
			goto exit;

		total += count;
		count = AGG_BATCH_SIZE; // Ensure we always try to fetch full batch
	}

	// Delete keys outside of fetch/update loop to avoid messing with key order
	if (del_idx > 0)
		err = bpf_map_delete_batch(map_fd, del_keys, &del_idx,
					   &batch_opts);

exit:
	free(values);
	free(keys);
	free(del_keys);
	return err;
}

static int report_aggregated_stats(struct output_context *out_ctx,
				   struct aggregation_context *agg_ctx,
				   struct aggregation_config *agg_conf)
{
	__u64 t = get_time_ns(CLOCK_MONOTONIC);
	int err, map_idx;

	map_idx = switch_agg_map(agg_ctx->maps.map_active_fd);
	if (map_idx < 0)
		return map_idx;

	err = report_aggregated_stats_map(out_ctx,
					  agg_ctx->maps.map_v4_fd[map_idx],
					  AF_INET, agg_conf->ipv4_prefix_len, t,
					  agg_conf);
	if (err)
		return err;

	err = report_aggregated_stats_map(out_ctx,
					  agg_ctx->maps.map_v6_fd[map_idx],
					  AF_INET6, agg_conf->ipv6_prefix_len,
					  t, agg_conf);
	if (err)
		return err;

	err = report_globalcounters(out_ctx, agg_ctx);
	return err;
}

/*
 * Sets only the necessary programs in the object file to autoload.
 *
 * Assumes all programs are set to autoload by default, so in practice
 * deactivates autoloading for the program that does not need to be loaded.
 */
static int set_programs_to_load(struct bpf_object *obj,
				struct pping_config *config)
{
	struct bpf_program *prog;
	char *unload_prog =
		strcmp(config->ingress_prog, PROG_INGRESS_XDP) != 0 ?
			PROG_INGRESS_XDP :
			PROG_INGRESS_TC;

	prog = bpf_object__find_program_by_name(obj, unload_prog);
	if (libbpf_get_error(prog))
		return libbpf_get_error(prog);

	return bpf_program__set_autoload(prog, false);
}

static int load_attach_bpfprogs(struct bpf_object **obj,
				struct pping_config *config)
{
	int err, detach_err;
	config->created_tc_hook = false;

	// Open and load ELF file
	*obj = bpf_object__open(config->object_path);
	err = libbpf_get_error(*obj);
	if (err) {
		fprintf(stderr, "Failed opening object file %s: %s\n",
			config->object_path, get_libbpf_strerror(err));
		return err;
	}

	err = init_rodata(*obj, &config->bpf_config,
			  sizeof(config->bpf_config));
	if (err) {
		fprintf(stderr, "Failed pushing user-configration to %s: %s\n",
			config->object_path, get_libbpf_strerror(err));
		return err;
	}

	set_programs_to_load(*obj, config);

	// Attach ingress prog
	if (strcmp(config->ingress_prog, PROG_INGRESS_XDP) == 0) {
		/* xdp_attach() loads 'obj' through libxdp */
		err = xdp_attach(*obj, config->ingress_prog, config->ifindex,
				 &config->xdp_prog, config->xdp_mode);
		if (err) {
			fprintf(stderr, "Failed attaching XDP program\n");
			if (config->xdp_mode == XDP_MODE_NATIVE)
				fprintf(stderr,
					"%s may not have driver support for XDP, try --xdp-mode generic instead\n",
					config->ifname);
			else
				fprintf(stderr,
					"Try updating kernel or use --ingress-hook tc instead\n");
		}
	} else {
		err = bpf_object__load(*obj);
		if (err) {
			fprintf(stderr, "Failed loading bpf programs in %s: %s\n",
				config->object_path, get_libbpf_strerror(err));
			return err;
		}
		err = tc_attach(*obj, config->ifindex, BPF_TC_INGRESS,
				config->ingress_prog, &config->tc_ingress_opts,
				&config->created_tc_hook);
		config->ingress_prog_id = err;
	}
	if (err < 0) {
		fprintf(stderr,
			"Failed attaching ingress BPF program on interface %s: %s\n",
			config->ifname, get_libbpf_strerror(err));
		goto ingress_err;
	}

	// Attach egress prog
	config->egress_prog_id = tc_attach(
		*obj, config->ifindex, BPF_TC_EGRESS, config->egress_prog,
		&config->tc_egress_opts,
		config->created_tc_hook ? NULL : &config->created_tc_hook);
	if (config->egress_prog_id < 0) {
		fprintf(stderr,
			"Failed attaching egress BPF program on interface %s: %s\n",
			config->ifname,
			get_libbpf_strerror(config->egress_prog_id));
		err = config->egress_prog_id;
		goto egress_err;
	}

	return 0;

egress_err:
	if (config->xdp_prog) {
		detach_err = xdp_detach(config->xdp_prog, config->ifindex,
					config->xdp_mode);
		config->xdp_prog = NULL;
	} else {
		detach_err = tc_detach(config->ifindex, BPF_TC_INGRESS,
				       &config->tc_ingress_opts,
				       config->created_tc_hook);
	}
	if (detach_err)
		fprintf(stderr,
			"Failed detaching ingress program from %s: %s\n",
			config->ifname, get_libbpf_strerror(detach_err));
ingress_err:
	bpf_object__close(*obj);
	return err;
}

static int setup_periodical_map_cleaning(struct bpf_object *obj,
					 struct pping_config *config)
{
	int pipefds[2];
	int err;
	config->clean_args.err = 0;

	if (config->clean_args.valid_thread) {
		fprintf(stderr,
			"There already exists a thread for the map cleanup\n");
		return -EINVAL;
	}

	err = pipe(pipefds);
	if (err) {
		err = -errno;
		fprintf(stderr, "Failed creating pipe: %s\n",
			get_libbpf_strerror(err));
		return err;
	}
	config->clean_args.pipe_rfd = pipefds[0];
	config->clean_args.pipe_wfd = pipefds[1];

	if (!config->clean_args.cleanup_interval) {
		fprintf(stderr, "Periodic map cleanup disabled\n");
		return 0;
	}

	err = iter_map_attach(obj, config->cleanup_ts_prog, config->packet_map,
			      &config->clean_args.tsclean_link);
	if (err) {
		fprintf(stderr,
			"Failed attaching cleanup program to timestamp map: %s\n",
			get_libbpf_strerror(err));
		return err;
	}

	err = iter_map_attach(obj, config->cleanup_flow_prog, config->flow_map,
			      &config->clean_args.flowclean_link);
	if (err) {
		fprintf(stderr,
			"Failed attaching cleanup program to flow map: %s\n",
			get_libbpf_strerror(err));
		goto destroy_ts_link;
	}

	err = pthread_create(&config->clean_args.tid, NULL,
			     periodic_map_cleanup, &config->clean_args);
	if (err) {
		fprintf(stderr,
			"Failed starting thread to perform periodic map cleanup: %s\n",
			get_libbpf_strerror(err));
		goto destroy_links;
	}

	config->clean_args.valid_thread = true;
	return 0;

destroy_links:
	bpf_link__destroy(config->clean_args.flowclean_link);
destroy_ts_link:
	bpf_link__destroy(config->clean_args.tsclean_link);
	return err;
}

static struct output_context *open_output(const char *filename,
					  enum pping_output_format format,
					  struct aggregation_config *agg_conf)
{
	struct output_context *out_ctx;

	out_ctx = calloc(1, sizeof(*out_ctx));
	if (!out_ctx)
		return NULL;

	out_ctx->format = format;

	if (filename) {
		out_ctx->stream = fopen(filename, "ax");
		if (!out_ctx->stream)
			goto err;
	} else {
		out_ctx->stream = stdout;
	}

	if (out_ctx->format == PPING_OUTPUT_JSON) {
		out_ctx->jctx = jsonw_new(out_ctx->stream);
		if (!out_ctx->jctx)
			goto err;
		jsonw_start_array(out_ctx->jctx);
	}

	if (agg_conf)
		print_aggmetadata(out_ctx, agg_conf);

	return out_ctx;
err:
	free(out_ctx);
	return NULL;
}

static int close_output(struct output_context *out_ctx)
{
	int err = 0;

	if (out_ctx->jctx) {
		jsonw_end_array(out_ctx->jctx);
		jsonw_destroy(&out_ctx->jctx);
	}

	if (out_ctx->stream && out_ctx->stream != stdout) {
		if (fclose(out_ctx->stream) != 0)
			err = -errno;
	}

	free(out_ctx);
	return err;
}

/* Will try to reopen *out_ctx
 * If it is able to open the new output it will return 0, replace *out_ctx with
 * the new output and close the old output_context. If it fails at opening a
 * new output_context it will return a negative error code and *out_ctx will
 * remain unchanged */
static int reopen_output(struct output_context **out_ctx, const char *filename,
			 struct aggregation_config *agg_conf)
{
	struct output_context *new_out;

	new_out = open_output(filename, (*out_ctx)->format, agg_conf);
	if (!new_out)
		return -errno;

	close_output(*out_ctx);

	*out_ctx = new_out;
	return 0;
}

static int init_signalfd(void)
{
	sigset_t mask;
	int fd, err;

	sigemptyset(&mask);
	sigaddset(&mask, SIGINT);
	sigaddset(&mask, SIGTERM);
	sigaddset(&mask, SIGHUP);

	fd = signalfd(-1, &mask, 0);
	if (fd < 0)
		return -errno;

	err = pthread_sigmask(SIG_BLOCK, &mask, NULL);
	if (err) {
		err = -errno;
		close(fd);
		return err;
	}

	return fd;
}

/* Returns 0 if signal was successfully handled, PPING_ABORT if signal
 * indicates program should be halted or a negative error code on failure. */
static int handle_signalfd(int sigfd, struct output_context **out_ctx,
			   const char *filename,
			   struct aggregation_config *agg_conf)
{
	struct signalfd_siginfo siginfo;
	int ret, err;

	ret = read(sigfd, &siginfo, sizeof(siginfo));
	if (ret != sizeof(siginfo)) {
		fprintf(stderr, "Failed reading signalfd\n");
		return -EBADFD;
	}

	if (siginfo.ssi_signo == SIGHUP) {
		if (filename) {
			err = reopen_output(out_ctx, filename, agg_conf);
			if (err)
				fprintf(stderr,
					"Warning: failed reopening %s: %s\n",
					filename, get_libbpf_strerror(err));
		} // If not writing to file, simply ignore the SIGHUP
	} else if (siginfo.ssi_signo == SIGINT ||
		   siginfo.ssi_signo == SIGTERM) {
		return PPING_ABORT;
	} else {
		fprintf(stderr, "Unexpected signal %d\n", siginfo.ssi_signo);
		return -EBADMSG;
	}

	return 0;
}

static int init_perfbuffer(struct bpf_object *obj, struct pping_config *config,
			   struct perf_buffer **_pb)
{
	struct perf_buffer *pb;
	int err;

	pb = perf_buffer__new(
		bpf_object__find_map_fd_by_name(obj, config->event_map),
		PERF_BUFFER_PAGES, handle_event, handle_missed_events,
		&config->out_ctx, NULL);
	err = libbpf_get_error(pb);
	if (err) {
		fprintf(stderr, "Failed to open perf buffer %s: %s\n",
			config->event_map, get_libbpf_strerror(err));
		return err;
	}

	*_pb = pb;
	return 0;
}

/* Returns PPING_ABORT to signal the program should be halted or a negative
 * error code. */
static int handle_pipefd(int pipe_rfd)
{
	int ret, remote_err;

	ret = read(pipe_rfd, &remote_err, sizeof(remote_err));
	if (ret != sizeof(remote_err)) {
		fprintf(stderr, "Failed reading remote error from pipe\n");
		return -EBADFD;
	}

	fprintf(stderr, "Program aborted - error: %s\n",
		get_libbpf_strerror(remote_err));
	return PPING_ABORT;
}

int fetch_aggregation_map_fds(struct bpf_object *obj,
			      struct aggregation_maps *maps)
{
	maps->map_active_fd =
		bpf_object__find_map_fd_by_name(obj, "map_active_agg_instance");
	maps->map_v4_fd[0] =
		bpf_object__find_map_fd_by_name(obj, "map_v4_agg1");
	maps->map_v4_fd[1] =
		bpf_object__find_map_fd_by_name(obj, "map_v4_agg2");
	maps->map_v6_fd[0] =
		bpf_object__find_map_fd_by_name(obj, "map_v6_agg1");
	maps->map_v6_fd[1] =
		bpf_object__find_map_fd_by_name(obj, "map_v6_agg2");
	maps->map_globcnt_fd =
		bpf_object__find_map_fd_by_name(obj, "map_global_counters");

	if (maps->map_active_fd < 0 || maps->map_v4_fd[0] < 0 ||
	    maps->map_v4_fd[1] < 0 || maps->map_v6_fd[0] < 0 ||
	    maps->map_v6_fd[1] < 0 || maps->map_globcnt_fd < 0) {
		fprintf(stderr,
			"Unable to find aggregation maps (%d/%d/%d/%d/%d/%d).\n",
			maps->map_active_fd, maps->map_v4_fd[0],
			maps->map_v4_fd[1], maps->map_v6_fd[0],
			maps->map_v6_fd[1], maps->map_globcnt_fd);
		return -ENOENT;
	}

	return 0;
}

static int init_agg_backup_entries(struct aggregation_maps *maps, bool ipv4,
				   bool ipv6)
{
	struct aggregated_stats *empty_stats;
	struct ipprefix_key key;
	int instance, err = 0;

	empty_stats = calloc(libbpf_num_possible_cpus(), sizeof(*empty_stats));
	if (!empty_stats)
		return -errno;

	if (ipv4) {
		key.v4 = IPV4_BACKUP_KEY;

		for (instance = 0; instance < 2; instance++) {
			err = bpf_map_update_elem(maps->map_v4_fd[instance],
						  &key, empty_stats,
						  BPF_NOEXIST);
			if (err)
				goto exit;
		}
	}

	if (ipv6) {
		key.v6 = IPV6_BACKUP_KEY;

		for (instance = 0; instance < 2; instance++) {
			err = bpf_map_update_elem(maps->map_v6_fd[instance],
						  &key, empty_stats,
						  BPF_NOEXIST);
			if (err)
				goto exit;
		}
	}

exit:
	free(empty_stats);
	return err;
}

static int setup_timer(__u64 init_delay_ns, __u64 interval_ns)
{
	struct itimerspec timercfg = {
		.it_value = { .tv_sec = init_delay_ns / NS_PER_SECOND,
			      .tv_nsec = init_delay_ns % NS_PER_SECOND },
		.it_interval = { .tv_sec = interval_ns / NS_PER_SECOND,
				 .tv_nsec = interval_ns % NS_PER_SECOND }
	};
	int fd, err;

	fd = timerfd_create(CLOCK_MONOTONIC, 0);
	if (fd < 0) {
		return -errno;
	}

	err = timerfd_settime(fd, 0, &timercfg, NULL);
	if (err) {
		err = -errno;
		close(fd);
		return err;
	}

	return fd;
}

static int init_aggregation_timer(struct bpf_object *obj,
				  struct pping_config *config)
{
	int err, fd;

	memset(&config->agg_ctx.prev_counters, 0,
	       sizeof(config->agg_ctx.prev_counters));

	err = fetch_aggregation_map_fds(obj, &config->agg_ctx.maps);
	if (err) {
		fprintf(stderr, "Failed fetching aggregation maps: %s\n",
			get_libbpf_strerror(err));
		return err;
	}

	err = init_agg_backup_entries(&config->agg_ctx.maps,
				      config->agg_conf.ipv4_prefix_len > 0,
				      config->agg_conf.ipv6_prefix_len > 0);
	if (err) {
		fprintf(stderr,
			"Failed initalized backup entries in aggregation maps: %s\n",
			get_libbpf_strerror(err));
		return err;
	}

	fd = setup_timer(config->agg_conf.aggregation_interval,
			 config->agg_conf.aggregation_interval);
	if (fd < 0) {
		fprintf(stderr,
			"Failed creating timer for periodic aggregation: %s\n",
			get_libbpf_strerror(fd));
		return fd;
	}

	return fd;
}

static int handle_aggregation_timer(int timer_fd,
				    struct output_context *out_ctx,
				    struct aggregation_context *agg_ctx,
				    struct aggregation_config *agg_conf)
{
	__u64 timer_exps;
	int ret, err;

	ret = read(timer_fd, &timer_exps, sizeof(timer_exps));
	if (ret != sizeof(timer_exps)) {
		fprintf(stderr, "Failed reading timerfd\n");
		return -EBADFD;
	}

	if (timer_exps > 1) {
		fprintf(stderr,
			"Warning - missed %llu aggregation timer expirations\n",
			timer_exps - 1);
	}

	err = report_aggregated_stats(out_ctx, agg_ctx, agg_conf);
	if (err) {
		fprintf(stderr, "Failed reporting aggregated RTTs: %s\n",
			get_libbpf_strerror(err));
		return err;
	}

	return 0;
}

static int epoll_add_event_type(int epfd, int fd, __u64 event_type, __u64 value)
{
	struct epoll_event ev = {
		.events = EPOLLIN,
		.data = { .u64 = event_type | value },
	};

	if (value & ~PPING_EPEVENT_MASK)
		return -EINVAL;

	return epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &ev) ? -errno : 0;
}

static int epoll_add_perf_buffer(int epfd, struct perf_buffer *pb)
{
	int fd, err;
	__u64 cpu;

	for (cpu = 0; cpu < perf_buffer__buffer_cnt(pb); cpu++) {
		fd = perf_buffer__buffer_fd(pb, cpu);
		if (fd < 0)
			return fd;

		err = epoll_add_event_type(epfd, fd, PPING_EPEVENT_TYPE_PERFBUF,
					   cpu);
		if (err)
			return err;
	}

	return 0;
}

static int epoll_add_events(int epfd, struct perf_buffer *pb, int sigfd,
			    int pipe_rfd, int aggfd)
{
	int err;

	err = epoll_add_event_type(epfd, sigfd, PPING_EPEVENT_TYPE_SIGNAL,
				   sigfd);
	if (err) {
		fprintf(stderr, "Failed adding signalfd to epoll instace: %s\n",
			get_libbpf_strerror(err));
		return err;
	}

	err = epoll_add_event_type(epfd, pipe_rfd, PPING_EPEVENT_TYPE_PIPE,
				   pipe_rfd);
	if (err) {
		fprintf(stderr, "Failed adding pipe fd to epoll instance: %s\n",
			get_libbpf_strerror(err));
		return err;
	}

	err = epoll_add_perf_buffer(epfd, pb);
	if (err) {
		fprintf(stderr,
			"Failed adding perf-buffer to epoll instance: %s\n",
			get_libbpf_strerror(err));
		return err;
	}

	if (aggfd >= 0) {
		err = epoll_add_event_type(epfd, aggfd,
					   PPING_EPEVENT_TYPE_AGGTIMER, aggfd);
		if (err) {
			fprintf(stderr,
				"Failed adding aggregation timerfd to epoll instance: %s\n",
				get_libbpf_strerror(err));
			return err;
		}
	}

	return 0;
}

static int epoll_poll_events(int epfd, struct pping_config *config,
			     struct perf_buffer *pb, int timeout_ms)
{
	struct epoll_event events[MAX_EPOLL_EVENTS];
	int err = 0, nfds, i;

	nfds = epoll_wait(epfd, events, MAX_EPOLL_EVENTS, timeout_ms);
	if (nfds < 0) {
		err = -errno;
		fprintf(stderr, "epoll error: %s\n", get_libbpf_strerror(err));
		return err;
	}

	for (i = 0; i < nfds; i++) {
		switch (events[i].data.u64 & ~PPING_EPEVENT_MASK) {
		case PPING_EPEVENT_TYPE_PERFBUF:
			err = perf_buffer__consume_buffer(
				pb, events[i].data.u64 & PPING_EPEVENT_MASK);
			break;
		case PPING_EPEVENT_TYPE_AGGTIMER:
			err = handle_aggregation_timer(
				events[i].data.u64 & PPING_EPEVENT_MASK,
				config->out_ctx, &config->agg_ctx,
				&config->agg_conf);
			break;
		case PPING_EPEVENT_TYPE_SIGNAL:
			err = handle_signalfd(
				events[i].data.u64 & PPING_EPEVENT_MASK,
				&config->out_ctx,
				config->write_to_file ? config->filename : NULL,
				config->bpf_config.agg_rtts ?
					&config->agg_conf :
					NULL);
			break;
		case PPING_EPEVENT_TYPE_PIPE:
			err = handle_pipefd(events[i].data.u64 &
					    PPING_EPEVENT_MASK);
			break;
		default:
			fprintf(stderr, "Warning: unexpected epoll data: %lu\n",
				events[i].data.u64);
			break;
		}
		if (err)
			break;
	}

	return err;
}

int main(int argc, char *argv[])
{
	int err = 0, detach_err = 0;
	void *thread_err;
	struct bpf_object *obj = NULL;
	struct perf_buffer *pb = NULL;
	int epfd, sigfd, aggfd;

	DECLARE_LIBBPF_OPTS(bpf_tc_opts, tc_ingress_opts);
	DECLARE_LIBBPF_OPTS(bpf_tc_opts, tc_egress_opts);

	struct pping_config config = {
		.bpf_config = { .rate_limit = 100 * NS_PER_MS,
				.rtt_rate = 0,
				.use_srtt = false },
		.clean_args = { .cleanup_interval = 1 * NS_PER_SECOND,
				.valid_thread = false },
		.agg_conf = { .aggregation_interval = 1 * NS_PER_SECOND,
			      .timeout_interval = 30 * NS_PER_SECOND,
			      .ipv4_prefix_len = 24,
			      .ipv6_prefix_len = 48,
			      .n_bins = RTT_AGG_NR_BINS,
			      .bin_width = RTT_AGG_BIN_WIDTH },
		.object_path = "pping_kern.o",
		.ingress_prog = PROG_INGRESS_TC,
		.egress_prog = PROG_EGRESS_TC,
		.cleanup_ts_prog = "tsmap_cleanup",
		.cleanup_flow_prog = "flowmap_cleanup",
		.packet_map = "packet_ts",
		.flow_map = "flow_state",
		.event_map = "events",
		.tc_ingress_opts = tc_ingress_opts,
		.tc_egress_opts = tc_egress_opts,
		.xdp_mode = XDP_MODE_NATIVE,
	};

	// Detect if running as root
	if (geteuid() != 0) {
		fprintf(stderr, "This program must be run as root.\n");
		return EXIT_FAILURE;
	}

	// Increase rlimit
	err = set_rlimit(RLIM_INFINITY);
	if (err) {
		fprintf(stderr, "Could not set rlimit to infinity: %s\n",
			get_libbpf_strerror(err));
		return EXIT_FAILURE;
	}

	err = parse_arguments(argc, argv, &config);
	if (err) {
		fprintf(stderr, "Failed parsing arguments:  %s\n",
			get_libbpf_strerror(err));
		print_usage(argv);
		return EXIT_FAILURE;
	}

	if (!config.bpf_config.track_tcp && !config.bpf_config.track_icmp)
		config.bpf_config.track_tcp = true;

	if (config.format == PPING_OUTPUT_PPVIZ) {
		if (config.bpf_config.agg_rtts) {
			fprintf(stderr,
				"The ppviz format does not support aggregated output\n");
			return EXIT_FAILURE;
		}
		if (config.bpf_config.track_icmp)
			fprintf(stderr,
				"Warning: ppviz format mainly intended for TCP traffic, but may now include ICMP traffic as well\n");
	}

	fprintf(stderr, "Starting ePPing in %s mode tracking %s on %s\n",
		output_format_to_str(config.format),
		tracked_protocols_to_str(&config), config.ifname);

	config.out_ctx = open_output(
		config.write_to_file ? config.filename : NULL, config.format,
		config.bpf_config.agg_rtts ? &config.agg_conf : NULL);
	if (!config.out_ctx) {
		err = -errno;
		fprintf(stderr, "Unable to open %s: %s\n",
			config.write_to_file ? config.filename : "output",
			get_libbpf_strerror(err));
		return EXIT_FAILURE;
	}

	// Setup signalhandling (allow graceful shutdown on SIGINT/SIGTERM, reopen on SIGHUP)
	sigfd = init_signalfd();
	if (sigfd < 0) {
		fprintf(stderr, "Failed creating signalfd: %s\n",
			get_libbpf_strerror(sigfd));
		goto cleanup_output;
	}

	err = load_attach_bpfprogs(&obj, &config);
	if (err) {
		fprintf(stderr,
			"Failed loading and attaching BPF programs in %s\n",
			config.object_path);
		goto cleanup_sigfd;
	}

	err = setup_periodical_map_cleaning(obj, &config);
	if (err) {
		fprintf(stderr, "Failed setting up map cleaning: %s\n",
			get_libbpf_strerror(err));
		goto cleanup_attached_progs;
	}

	err = init_perfbuffer(obj, &config, &pb);
	if (err) {
		fprintf(stderr, "Failed setting up perf-buffer: %s\n",
			get_libbpf_strerror(err));
		goto cleanup_mapcleaning;
	}

	if (config.bpf_config.agg_rtts) {
		aggfd = init_aggregation_timer(obj, &config);
		if (aggfd < 0) {
			fprintf(stderr,
				"Failed setting up aggregation timerfd: %s\n",
				get_libbpf_strerror(aggfd));
			goto cleanup_perf_buffer;
		}
	} else {
		aggfd = -1;
	}

	epfd = epoll_create1(EPOLL_CLOEXEC);
	if (epfd < 0) {
		fprintf(stderr, "Failed creating epoll instance: %s\n",
			get_libbpf_strerror(err));
		goto cleanup_aggfd;
	}

	err = epoll_add_events(epfd, pb, sigfd, config.clean_args.pipe_rfd, aggfd);
	if (err) {
		fprintf(stderr, "Failed adding events to epoll instace: %s\n",
			get_libbpf_strerror(err));
		goto cleanup_epfd;
	}

	// Main loop
	while (true) {
		err = epoll_poll_events(epfd, &config, pb, -1);
		if (err) {
			if (err == PPING_ABORT)
				err = 0;
			else
				fprintf(stderr, "Error polling events: %s\n",
					get_libbpf_strerror(err));
			break;
		}
	}

	// Cleanup
cleanup_epfd:
	close(epfd);

cleanup_aggfd:
	if (aggfd >= 0)
		close(aggfd);

cleanup_perf_buffer:
	perf_buffer__free(pb);

cleanup_mapcleaning:
	if (config.clean_args.valid_thread) {
		pthread_cancel(config.clean_args.tid);
		pthread_join(config.clean_args.tid, &thread_err);
		if (thread_err != PTHREAD_CANCELED)
			err = err ? err : config.clean_args.err;

		bpf_link__destroy(config.clean_args.tsclean_link);
		bpf_link__destroy(config.clean_args.flowclean_link);
	}
	close(config.clean_args.pipe_rfd);
	close(config.clean_args.pipe_wfd);

cleanup_attached_progs:
	if (config.xdp_prog)
		detach_err = xdp_detach(config.xdp_prog, config.ifindex,
					config.xdp_mode);
	else
		detach_err = tc_detach(config.ifindex, BPF_TC_INGRESS,
				       &config.tc_ingress_opts, false);
	if (detach_err)
		fprintf(stderr,
			"Failed removing ingress program from interface %s: %s\n",
			config.ifname, get_libbpf_strerror(detach_err));

	detach_err =
		tc_detach(config.ifindex, BPF_TC_EGRESS, &config.tc_egress_opts,
			  config.force && config.created_tc_hook);
	if (detach_err)
		fprintf(stderr,
			"Failed removing egress program from interface %s: %s\n",
			config.ifname, get_libbpf_strerror(detach_err));

	bpf_object__close(obj);

cleanup_sigfd:
	close(sigfd);

cleanup_output:
	close_output(config.out_ctx);

	return err != 0 || detach_err != 0;
}
