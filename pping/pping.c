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
#include <signal.h> // For detecting Ctrl-C
#include <sys/resource.h> // For setting rlmit
#include <time.h>
#include <pthread.h>

#include "json_writer.h"
#include "pping.h" //common structs for user-space and BPF parts

#define PERF_BUFFER_PAGES 64 // Related to the perf-buffer size?
#define PERF_POLL_TIMEOUT_MS 100

#define MAX_PATH_LEN 1024

#define MON_TO_REAL_UPDATE_FREQ                                                \
	(1 * NS_PER_SECOND) // Update offset between CLOCK_MONOTONIC and CLOCK_REALTIME once per second

enum PPING_OUTPUT_FORMAT {
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
	bool valid_thread;
};

// Store configuration values in struct to easily pass around
struct pping_config {
	struct bpf_config bpf_config;
	struct bpf_tc_opts tc_ingress_opts;
	struct bpf_tc_opts tc_egress_opts;
	struct map_cleanup_args clean_args;
	char *object_path;
	char *ingress_prog;
	char *egress_prog;
	char *cleanup_ts_prog;
	char *cleanup_flow_prog;
	char *packet_map;
	char *flow_map;
	char *event_map;
	int xdp_flags;
	int ifindex;
	int ingress_prog_id;
	int egress_prog_id;
	char ifname[IF_NAMESIZE];
	enum PPING_OUTPUT_FORMAT output_format;
	bool force;
	bool created_tc_hook;
};

static volatile sig_atomic_t keep_running = 1;
static json_writer_t *json_ctx = NULL;
static void (*print_event_func)(const union pping_event *) = NULL;

static const struct option long_options[] = {
	{ "help",             no_argument,       NULL, 'h' },
	{ "interface",        required_argument, NULL, 'i' }, // Name of interface to run on
	{ "rate-limit",       required_argument, NULL, 'r' }, // Sampling rate-limit in ms
	{ "rtt-rate",         required_argument, NULL, 'R' }, // Sampling rate in terms of flow-RTT (ex 1 sample per RTT-interval)
	{ "rtt-type",         required_argument, NULL, 't' }, // What type of RTT the RTT-rate should be applied to ("min" or "smoothed"), only relevant if rtt-rate is provided
	{ "force",            no_argument,       NULL, 'f' }, // Overwrite any existing XDP program on interface, remove qdisc on cleanup
	{ "cleanup-interval", required_argument, NULL, 'c' }, // Map cleaning interval in s, 0 to disable
	{ "format",           required_argument, NULL, 'F' }, // Which format to output in (standard/json/ppviz)
	{ "ingress-hook",     required_argument, NULL, 'I' }, // Use tc or XDP as ingress hook
	{ "tcp",              no_argument,       NULL, 'T' }, // Calculate and report RTTs for TCP traffic (with TCP timestamps)
	{ "icmp",             no_argument,       NULL, 'C' }, // Calculate and report RTTs for ICMP echo-reply traffic
	{ "include-local",    no_argument,       NULL, 'l' }, // Also report "internal" RTTs
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
		else
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
	*res = strtod(str, &endptr);
	if (strlen(str) != endptr - str) {
		fprintf(stderr, "%s %s is not a valid number\n", name, str);
		return -EINVAL;
	}
	if (*res < low || *res > high) {
		fprintf(stderr, "%s must in range [%g, %g]\n", name, low, high);
		return -EINVAL;
	}

	return 0;
}

static int parse_arguments(int argc, char *argv[], struct pping_config *config)
{
	int err, opt;
	double rate_limit_ms, cleanup_interval_s, rtt_rate;

	config->ifindex = 0;
	config->bpf_config.localfilt = true;
	config->force = false;
	config->bpf_config.track_tcp = false;
	config->bpf_config.track_icmp = false;

	while ((opt = getopt_long(argc, argv, "hflTCi:r:R:t:c:F:I:",
				  long_options, NULL)) != -1) {
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
					config->ifname,
					get_libbpf_strerror(err));
				return err;
			}
			break;
		case 'r':
			err = parse_bounded_double(&rate_limit_ms, optarg, 0,
						   7 * S_PER_DAY * MS_PER_S,
						   "rate-limit");
			if (err)
				return -EINVAL;

			config->bpf_config.rate_limit =
				rate_limit_ms * NS_PER_MS;
			break;
		case 'R':
			err = parse_bounded_double(&rtt_rate, optarg, 0, 10000,
						   "rtt-rate");
			if (err)
				return -EINVAL;
			config->bpf_config.rtt_rate =
				DOUBLE_TO_FIXPOINT(rtt_rate);
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
			err = parse_bounded_double(&cleanup_interval_s, optarg,
						   0, 7 * S_PER_DAY,
						   "cleanup-interval");
			if (err)
				return -EINVAL;

			config->clean_args.cleanup_interval =
				cleanup_interval_s * NS_PER_SECOND;
			break;
		case 'F':
			if (strcmp(optarg, "standard") == 0) {
				config->output_format = PPING_OUTPUT_STANDARD;
			} else if (strcmp(optarg, "json") == 0) {
				config->output_format = PPING_OUTPUT_JSON;
			} else if (strcmp(optarg, "ppviz") == 0) {
				config->output_format = PPING_OUTPUT_PPVIZ;
			} else {
				fprintf(stderr,
					"format must be \"standard\", \"json\" or \"ppviz\"\n");
				return -EINVAL;
			}
			break;
		case 'I':
			if (strcmp(optarg, "xdp") == 0) {
				config->ingress_prog = "pping_xdp_ingress";
			} else if (strcmp(optarg, "tc") == 0) {
				config->ingress_prog = "pping_tc_ingress";
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
			config->xdp_flags &= ~XDP_FLAGS_UPDATE_IF_NOEXIST;
			break;
		case 'T':
			config->bpf_config.track_tcp = true;
			break;
		case 'C':
			config->bpf_config.track_icmp = true;
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

	return 0;
}

const char *tracked_protocols_to_str(struct pping_config *config)
{
	bool tcp = config->bpf_config.track_tcp;
	bool icmp = config->bpf_config.track_icmp;
	return tcp && icmp ? "TCP, ICMP" : tcp ? "TCP" : "ICMP";
}

const char *output_format_to_str(enum PPING_OUTPUT_FORMAT format)
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

void abort_program(int sig)
{
	keep_running = 0;
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
		      int ifindex, __u32 xdp_flags)
{
	struct bpf_program *prog;
	int prog_fd, err;
	__u32 prog_id;

	if (prog_name)
		prog = bpf_object__find_program_by_name(obj, prog_name);
	else
		prog = bpf_object__next_program(obj, NULL);

	prog_fd = bpf_program__fd(prog);
	if (prog_fd < 0)
		return prog_fd;

	err = bpf_set_link_xdp_fd(ifindex, prog_fd, xdp_flags);
	if (err)
		return err;

	err = bpf_get_link_xdp_id(ifindex, &prog_id, xdp_flags);
	if (err) {
		bpf_set_link_xdp_fd(ifindex, -1, xdp_flags);
		return err;
	}

	return prog_id;
}

static int xdp_detach(int ifindex, __u32 xdp_flags, __u32 expected_prog_id)
{
	__u32 curr_prog_id;
	int err;

	err = bpf_get_link_xdp_id(ifindex, &curr_prog_id, xdp_flags);
	if (err)
		return err;

	if (!curr_prog_id) {
		return 0; // No current prog on interface
	}

	if (expected_prog_id && curr_prog_id != expected_prog_id)
		return -ENOENT;

	return bpf_set_link_xdp_fd(ifindex, -1, xdp_flags);
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

static void *periodic_map_cleanup(void *args)
{
	struct map_cleanup_args *argp = args;
	struct timespec interval;
	interval.tv_sec = argp->cleanup_interval / NS_PER_SECOND;
	interval.tv_nsec = argp->cleanup_interval % NS_PER_SECOND;
	char buf[256];
	int err;

	while (keep_running) {
		err = iter_map_execute(argp->tsclean_link);
		if (err) {
			// Running in separate thread so can't use get_libbpf_strerror
			libbpf_strerror(err, buf, sizeof(buf));
			fprintf(stderr,
				"Error while cleaning timestamp map: %s\n",
				buf);
		}

		err = iter_map_execute(argp->flowclean_link);
		if (err) {
			libbpf_strerror(err, buf, sizeof(buf));
			fprintf(stderr, "Error while cleaning flow map: %s\n",
				buf);
		}

		nanosleep(&interval, NULL);
	}
	pthread_exit(NULL);
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

/*
 * Wrapper around inet_ntop designed to handle the "bug" that mapped IPv4
 * addresses are formated as IPv6 addresses for AF_INET6
 */
static int format_ip_address(char *buf, size_t size, int af,
			     const struct in6_addr *addr)
{
	if (af == AF_INET)
		return inet_ntop(af, &addr->s6_addr[12], buf, size) ? -errno :
									    0;
	else if (af == AF_INET6)
		return inet_ntop(af, addr, buf, size) ? -errno : 0;
	return -EINVAL;
}

static const char *proto_to_str(__u16 proto)
{
	static char buf[8];

	switch (proto) {
	case IPPROTO_TCP:
		return "TCP";
	case IPPROTO_ICMP:
		return "ICMP";
	case IPPROTO_ICMPV6:
		return "ICMPv6";
	default:
		snprintf(buf, sizeof(buf), "%d", proto);
		return buf;
	}
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

static void print_event_standard(const union pping_event *e)
{
	if (e->event_type == EVENT_TYPE_RTT) {
		print_ns_datetime(stdout, e->rtt_event.timestamp);
		printf(" %llu.%06llu ms %llu.%06llu ms %s ",
		       e->rtt_event.rtt / NS_PER_MS,
		       e->rtt_event.rtt % NS_PER_MS,
		       e->rtt_event.min_rtt / NS_PER_MS,
		       e->rtt_event.min_rtt % NS_PER_MS,
		       proto_to_str(e->rtt_event.flow.proto));
		print_flow_ppvizformat(stdout, &e->rtt_event.flow);
		printf("\n");
	} else if (e->event_type == EVENT_TYPE_FLOW) {
		print_ns_datetime(stdout, e->flow_event.timestamp);
		printf(" %s ", proto_to_str(e->rtt_event.flow.proto));
		print_flow_ppvizformat(stdout, &e->flow_event.flow);
		printf(" %s due to %s from %s\n",
		       flowevent_to_str(e->flow_event.flow_event_type),
		       eventreason_to_str(e->flow_event.reason),
		       eventsource_to_str(e->flow_event.source));
	}
}

static void print_event_ppviz(const union pping_event *e)
{
	// ppviz format does not support flow events
	if (e->event_type != EVENT_TYPE_RTT)
		return;

	const struct rtt_event *re = &e->rtt_event;
	__u64 time = convert_monotonic_to_realtime(re->timestamp);

	printf("%llu.%09llu %llu.%09llu %llu.%09llu ", time / NS_PER_SECOND,
	       time % NS_PER_SECOND, re->rtt / NS_PER_SECOND,
	       re->rtt % NS_PER_SECOND, re->min_rtt / NS_PER_SECOND,
	       re->min_rtt);
	print_flow_ppvizformat(stdout, &re->flow);
	printf("\n");
}

static void print_common_fields_json(json_writer_t *ctx,
				     const union pping_event *e)
{
	const struct network_tuple *flow = &e->rtt_event.flow;
	char saddr[INET6_ADDRSTRLEN];
	char daddr[INET6_ADDRSTRLEN];

	format_ip_address(saddr, sizeof(saddr), flow->ipv, &flow->saddr.ip);
	format_ip_address(daddr, sizeof(daddr), flow->ipv, &flow->daddr.ip);

	jsonw_u64_field(ctx, "timestamp",
			convert_monotonic_to_realtime(e->rtt_event.timestamp));
	jsonw_string_field(ctx, "src_ip", saddr);
	jsonw_hu_field(ctx, "src_port", ntohs(flow->saddr.port));
	jsonw_string_field(ctx, "dest_ip", daddr);
	jsonw_hu_field(ctx, "dest_port", ntohs(flow->daddr.port));
	jsonw_string_field(ctx, "protocol", proto_to_str(flow->proto));
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

static void print_event_json(const union pping_event *e)
{
	if (e->event_type != EVENT_TYPE_RTT && e->event_type != EVENT_TYPE_FLOW)
		return;

	if (!json_ctx) {
		json_ctx = jsonw_new(stdout);
		jsonw_start_array(json_ctx);
	}

	jsonw_start_object(json_ctx);
	print_common_fields_json(json_ctx, e);
	if (e->event_type == EVENT_TYPE_RTT)
		print_rttevent_fields_json(json_ctx, &e->rtt_event);
	else // flow-event
		print_flowevent_fields_json(json_ctx, &e->flow_event);
	jsonw_end_object(json_ctx);
}

static void warn_map_full(const struct map_full_event *e)
{
	print_ns_datetime(stderr, e->timestamp);
	fprintf(stderr, " Warning: Unable to create %s entry for flow ",
		e->map == PPING_MAP_FLOWSTATE ? "flow" : "timestamp");
	print_flow_ppvizformat(stderr, &e->flow);
	fprintf(stderr, "\n");
}

static void print_map_clean_info(const struct map_clean_event *e)
{
	fprintf(stderr,
		"%s: cycle: %u, entries: %u, time: %llu, timeout: %u, tot timeout: %llu, selfdel: %u, tot selfdel: %llu\n",
		e->map == PPING_MAP_PACKETTS ? "packet_ts" : "flow_state",
		e->clean_cycles, e->last_processed_entries, e->last_runtime,
		e->last_timeout_del, e->tot_timeout_del, e->last_auto_del,
		e->tot_auto_del);
}

static void handle_event(void *ctx, int cpu, void *data, __u32 data_size)
{
	const union pping_event *e = data;

	if (data_size < sizeof(e->event_type))
		return;

	switch (e->event_type) {
	case EVENT_TYPE_MAP_FULL:
		warn_map_full(&e->map_event);
		break;
	case EVENT_TYPE_MAP_CLEAN:
		print_map_clean_info(&e->map_clean_event);
		break;
	case EVENT_TYPE_RTT:
	case EVENT_TYPE_FLOW:
		print_event_func(e);
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
		strcmp(config->ingress_prog, "pping_xdp_ingress") != 0 ?
			"pping_xdp_ingress" :
			      "pping_tc_ingress";

	prog = bpf_object__find_program_by_name(obj, unload_prog);
	if (libbpf_get_error(prog))
		return libbpf_get_error(prog);

	return bpf_program__set_autoload(prog, false);
}

/*
 * Print out some hints for what might have caused an error while attempting
 * to attach an XDP program. Based on xdp_link_attach() in
 * xdp-tutorial/common/common_user_bpf_xdp.c
 */
static void print_xdp_error_hints(FILE *stream, int err)
{
	err = err > 0 ? err : -err;
	switch (err) {
	case EBUSY:
	case EEXIST:
		fprintf(stream, "Hint: XDP already loaded on device"
				" use --force to swap/replace\n");
		break;
	case EOPNOTSUPP:
		fprintf(stream, "Hint: Native-XDP not supported\n");
		break;
	}
}

static int load_attach_bpfprogs(struct bpf_object **obj,
				struct pping_config *config)
{
	int err, detach_err;

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
	err = bpf_object__load(*obj);
	if (err) {
		fprintf(stderr, "Failed loading bpf programs in %s: %s\n",
			config->object_path, get_libbpf_strerror(err));
		return err;
	}

	// Attach egress prog
	config->egress_prog_id =
		tc_attach(*obj, config->ifindex, BPF_TC_EGRESS,
			  config->egress_prog, &config->tc_egress_opts,
			  &config->created_tc_hook);
	if (config->egress_prog_id < 0) {
		fprintf(stderr,
			"Failed attaching egress BPF program on interface %s: %s\n",
			config->ifname,
			get_libbpf_strerror(config->egress_prog_id));
		return config->egress_prog_id;
	}

	// Attach ingress prog
	if (strcmp(config->ingress_prog, "pping_xdp_ingress") == 0)
		config->ingress_prog_id =
			xdp_attach(*obj, config->ingress_prog, config->ifindex,
				   config->xdp_flags);
	else
		config->ingress_prog_id =
			tc_attach(*obj, config->ifindex, BPF_TC_INGRESS,
				  config->ingress_prog,
				  &config->tc_ingress_opts, NULL);
	if (config->ingress_prog_id < 0) {
		fprintf(stderr,
			"Failed attaching ingress BPF program on interface %s: %s\n",
			config->ifname, get_libbpf_strerror(err));
		err = config->ingress_prog_id;
		if (strcmp(config->ingress_prog, "pping_xdp_ingress") == 0)
			print_xdp_error_hints(stderr, err);
		goto ingress_err;
	}

	return 0;

ingress_err:
	detach_err =
		tc_detach(config->ifindex, BPF_TC_EGRESS,
			  &config->tc_egress_opts, config->created_tc_hook);
	if (detach_err)
		fprintf(stderr, "Failed detaching tc program from %s: %s\n",
			config->ifname, get_libbpf_strerror(detach_err));
	return err;
}

static int setup_periodical_map_cleaning(struct bpf_object *obj,
					 struct pping_config *config)
{
	int err;

	if (config->clean_args.valid_thread) {
		fprintf(stderr,
			"There already exists a thread for the map cleanup\n");
		return -EINVAL;
	}

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

int main(int argc, char *argv[])
{
	int err = 0, detach_err;
	struct bpf_object *obj = NULL;
	struct perf_buffer *pb = NULL;

	DECLARE_LIBBPF_OPTS(bpf_tc_opts, tc_ingress_opts);
	DECLARE_LIBBPF_OPTS(bpf_tc_opts, tc_egress_opts);

	struct pping_config config = {
		.bpf_config = { .rate_limit = 100 * NS_PER_MS,
				.rtt_rate = 0,
				.use_srtt = false },
		.clean_args = { .cleanup_interval = 1 * NS_PER_SECOND,
				.valid_thread = false },
		.object_path = "pping_kern.o",
		.ingress_prog = "pping_xdp_ingress",
		.egress_prog = "pping_tc_egress",
		.cleanup_ts_prog = "tsmap_cleanup",
		.cleanup_flow_prog = "flowmap_cleanup",
		.packet_map = "packet_ts",
		.flow_map = "flow_state",
		.event_map = "events",
		.xdp_flags = XDP_FLAGS_UPDATE_IF_NOEXIST,
		.tc_ingress_opts = tc_ingress_opts,
		.tc_egress_opts = tc_egress_opts,
		.output_format = PPING_OUTPUT_STANDARD,
	};

	// Detect if running as root
	if (geteuid() != 0) {
		printf("This program must be run as root.\n");
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

	if (config.bpf_config.track_icmp &&
	    config.output_format == PPING_OUTPUT_PPVIZ)
		fprintf(stderr,
			"Warning: ppviz format mainly intended for TCP traffic, but may now include ICMP traffic as well\n");

	switch (config.output_format) {
	case PPING_OUTPUT_STANDARD:
		print_event_func = print_event_standard;
		break;
	case PPING_OUTPUT_JSON:
		print_event_func = print_event_json;
		break;
	case PPING_OUTPUT_PPVIZ:
		print_event_func = print_event_ppviz;
		break;
	}

	fprintf(stderr, "Starting ePPing in %s mode tracking %s on %s\n",
		output_format_to_str(config.output_format),
		tracked_protocols_to_str(&config), config.ifname);

	// Allow program to perform cleanup on Ctrl-C
	signal(SIGINT, abort_program);
	signal(SIGTERM, abort_program);

	err = load_attach_bpfprogs(&obj, &config);
	if (err) {
		fprintf(stderr,
			"Failed loading and attaching BPF programs in %s\n",
			config.object_path);
		return EXIT_FAILURE;
	}

	// Set up perf buffer
	pb = perf_buffer__new(bpf_object__find_map_fd_by_name(obj,
							      config.event_map),
			      PERF_BUFFER_PAGES, handle_event,
			      handle_missed_events, NULL, NULL);
	err = libbpf_get_error(pb);
	if (err) {
		fprintf(stderr, "Failed to open perf buffer %s: %s\n",
			config.event_map, get_libbpf_strerror(err));
		goto cleanup_attached_progs;
	}

	err = setup_periodical_map_cleaning(obj, &config);
	if (err) {
		fprintf(stderr, "Failed setting up map cleaning: %s\n",
			get_libbpf_strerror(err));
		goto cleanup_perf_buffer;
	}

	// Main loop
	while (keep_running) {
		if ((err = perf_buffer__poll(pb, PERF_POLL_TIMEOUT_MS)) < 0) {
			if (keep_running) // Only print polling error if it wasn't caused by program termination
				fprintf(stderr,
					"Error polling perf buffer: %s\n",
					get_libbpf_strerror(-err));
			break;
		}
	}

	// Cleanup
	if (config.output_format == PPING_OUTPUT_JSON && json_ctx) {
		jsonw_end_array(json_ctx);
		jsonw_destroy(&json_ctx);
	}

	if (config.clean_args.valid_thread) {
		pthread_cancel(config.clean_args.tid);
		pthread_join(config.clean_args.tid, NULL);

		bpf_link__destroy(config.clean_args.tsclean_link);
		bpf_link__destroy(config.clean_args.flowclean_link);
	}

cleanup_perf_buffer:
	perf_buffer__free(pb);

cleanup_attached_progs:
	if (strcmp(config.ingress_prog, "pping_xdp_ingress") == 0)
		detach_err = xdp_detach(config.ifindex, config.xdp_flags,
					config.ingress_prog_id);
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

	return (err != 0 && keep_running) || detach_err != 0;
}
