/* SPDX-License-Identifier: GPL-2.0-or-later */
static const char *__doc__ =
	"Passive Ping - monitor flow RTT based on TCP timestamps";

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
#include <limits.h>
#include <signal.h> // For detecting Ctrl-C
#include <sys/resource.h> // For setting rlmit
#include <sys/wait.h>
#include <sys/stat.h>
#include <time.h>
#include <pthread.h>

#include "json_writer.h"
#include "pping.h" //common structs for user-space and BPF parts

#define NS_PER_SECOND 1000000000UL
#define NS_PER_MS 1000000UL

#define TIMESTAMP_LIFETIME                                                     \
	(10 * NS_PER_SECOND) // Clear out packet timestamps if they're over 10 seconds
#define FLOW_LIFETIME                                                          \
	(300 * NS_PER_SECOND) // Clear out flows if they're inactive over 300 seconds

#define PERF_BUFFER_PAGES 64 // Related to the perf-buffer size?
#define PERF_POLL_TIMEOUT_MS 100

#define MAX_PATH_LEN 1024

#define MON_TO_REAL_UPDATE_FREQ                                                \
	(1 * NS_PER_SECOND) // Update offset between CLOCK_MONOTONIC and CLOCK_REALTIME once per second

/* 
 * BPF implementation of pping using libbpf
 * Uses TC-BPF for egress and XDP for ingress
 * - On egrees, packets are parsed for TCP TSval, 
 *   if found added to hashmap using flow+TSval as key, 
 *   and current time as value
 * - On ingress, packets are parsed for TCP TSecr, 
 *   if found looksup hashmap using reverse-flow+TSecr as key, 
 *   and calculates RTT as different between now map value
 * - Calculated RTTs are pushed to userspace 
 *   (together with the related flow) and printed out 
 */

// Structure to contain arguments for clean_map (for passing to pthread_create)
struct map_cleanup_args {
	__u64 cleanup_interval;
	int packet_map_fd;
	int flow_map_fd;
};

// Store configuration values in struct to easily pass around
struct pping_config {
	struct bpf_config bpf_config;
	struct bpf_tc_opts tc_ingress_opts;
	struct bpf_tc_opts tc_egress_opts;
	__u64 cleanup_interval;
	char *object_path;
	char *ingress_sec;
	char *egress_sec;
	char *packet_map;
	char *flow_map;
	char *event_map;
	int xdp_flags;
	int ifindex;
	char ifname[IF_NAMESIZE];
	bool json_format;
	bool ppviz_format;
	bool force;
};

static volatile int keep_running = 1;
static json_writer_t *json_ctx = NULL;
static void (*print_event_func)(void *, int, void *, __u32) = NULL;

static const struct option long_options[] = {
	{ "help",             no_argument,       NULL, 'h' },
	{ "interface",        required_argument, NULL, 'i' }, // Name of interface to run on
	{ "rate-limit",       required_argument, NULL, 'r' }, // Sampling rate-limit in ms
	{ "force",            no_argument,       NULL, 'f' }, // Detach any existing XDP program on interface
	{ "cleanup-interval", required_argument, NULL, 'c' }, // Map cleaning interval in s
	{ "format",           required_argument, NULL, 'F' }, // Which format to output in (standard/json/ppviz)
	{ "ingress-hook",     required_argument, NULL, 'I' }, // Use tc or XDP as ingress hook
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

static double parse_positive_double_argument(const char *str,
					     const char *parname)
{
	char *endptr;
	double val;
	val = strtod(str, &endptr);
	if (strlen(str) != endptr - str) {
		fprintf(stderr, "%s %s is not a valid number\n", parname, str);
		return -EINVAL;
	}
	if (val < 0) {
		fprintf(stderr, "%s must be positive\n", parname);
		return -EINVAL;
	}

	return val;
}

static int parse_arguments(int argc, char *argv[], struct pping_config *config)
{
	int err, opt;
	double rate_limit_ms, cleanup_interval_s;

	config->ifindex = 0;
	config->force = false;
	config->json_format = false;
	config->ppviz_format = false;

	while ((opt = getopt_long(argc, argv, "hfi:r:c:F:I:", long_options,
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
		case 'r':
			rate_limit_ms = parse_positive_double_argument(
				optarg, "rate-limit");
			if (rate_limit_ms < 0)
				return -EINVAL;

			config->bpf_config.rate_limit =
				rate_limit_ms * NS_PER_MS;
			break;
		case 'c':
			cleanup_interval_s = parse_positive_double_argument(
				optarg, "cleanup-interval");
			if (cleanup_interval_s < 0)
				return -EINVAL;

			config->cleanup_interval =
				cleanup_interval_s * NS_PER_SECOND;
			break;
		case 'F':
			if (strcmp(optarg, "json") == 0) {
				config->json_format = true;
			} else if (strcmp(optarg, "ppviz") == 0) {
				config->ppviz_format = true;
			} else if (strcmp(optarg, "standard") != 0) {
				fprintf(stderr, "format must be \"standard\", \"json\" or \"ppviz\"\n");
				return -EINVAL;
			}
			break;
		case 'I':
			if (strcmp(optarg, "xdp") == 0) {
				config->ingress_sec = SEC_INGRESS_XDP;
			} else if (strcmp(optarg, "tc") == 0) {
				config->ingress_sec = SEC_INGRESS_TC;
			} else {
				fprintf(stderr, "ingress-hook must be \"xdp\" or \"tc\"\n");
				return -EINVAL;
			}
			break;
		case 'f':
			config->force = true;
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

static int xdp_detach(int ifindex, __u32 xdp_flags)
{
	return bpf_set_link_xdp_fd(ifindex, -1, xdp_flags);
}

static int xdp_attach(struct bpf_object *obj, const char *sec, int ifindex,
		      __u32 xdp_flags, bool force)
{
	struct bpf_program *prog;
	int prog_fd;

	if (sec)
		prog = bpf_object__find_program_by_title(obj, sec);
	else
		prog = bpf_program__next(NULL, obj);

	prog_fd = bpf_program__fd(prog);
	if (prog_fd < 0)
		return prog_fd;

	if (force) // detach current (if any) xdp-program first
		xdp_detach(ifindex, xdp_flags);

	return bpf_set_link_xdp_fd(ifindex, prog_fd, xdp_flags);
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

static int tc_attach(struct bpf_object *obj, int ifindex,
		     enum bpf_tc_attach_point attach_point,
		     const char *prog_title, struct bpf_tc_opts *opts)
{
	int err;
	int prog_fd;
	DECLARE_LIBBPF_OPTS(bpf_tc_hook, hook, .ifindex = ifindex,
			    .attach_point = attach_point);

	err = bpf_tc_hook_create(&hook);
	if (err && err != -EEXIST)
		return err;

	prog_fd = bpf_program__fd(
		bpf_object__find_program_by_title(obj, prog_title));
	if (prog_fd < 0)
		return prog_fd;

	opts->prog_fd = prog_fd;
	opts->prog_id = 0;
	return bpf_tc_attach(&hook, opts);
}

static int tc_detach(int ifindex, enum bpf_tc_attach_point attach_point,
		     struct bpf_tc_opts *opts)
{
	DECLARE_LIBBPF_OPTS(bpf_tc_hook, hook, .ifindex = ifindex,
			    .attach_point = attach_point);
	opts->prog_fd = 0;
	opts->prog_id = 0;
	opts->flags = 0;

	return bpf_tc_detach(&hook, opts);
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

static bool packet_ts_timeout(void *key_ptr, void *val_ptr, __u64 now)
{
	__u64 ts = *(__u64 *)val_ptr;
	if (now > ts && now - ts > TIMESTAMP_LIFETIME)
		return true;
	return false;
}

static bool flow_timeout(void *key_ptr, void *val_ptr, __u64 now)
{
	struct flow_event fe;
	__u64 ts = ((struct flow_state *)val_ptr)->last_timestamp;

	if (now > ts && now - ts > FLOW_LIFETIME) {
		if (print_event_func) {
			fe.event_type = EVENT_TYPE_FLOW;
			fe.timestamp = now;
			memcpy(&fe.flow, key_ptr, sizeof(struct network_tuple));
			fe.event_info.event = FLOW_EVENT_CLOSING;
			fe.event_info.reason = EVENT_REASON_FLOW_TIMEOUT;
			fe.source = EVENT_SOURCE_USERSPACE;
			print_event_func(NULL, 0, &fe, sizeof(fe));
		}
		return true;
	}
	return false;
}

/*
 * Loops through all entries in a map, running del_decision_func(value, time)
 * on every entry, and deleting those for which it returns true.
 * On sucess, returns the number of entries deleted, otherwise returns the
 * (negative) error code.
 */
//TODO - maybe add some pointer to arguments for del_decision_func?
static int clean_map(int map_fd, size_t key_size, size_t value_size,
		     bool (*del_decision_func)(void *, void *, __u64))
{
	int removed = 0;
	void *key, *prev_key, *value;
	bool delete_prev = false;
	__u64 now_nsec = get_time_ns(CLOCK_MONOTONIC);

#ifdef DEBUG
	int entries = 0;
	__u64 duration;
#endif

	if (now_nsec == 0)
		return -errno;

	key = malloc(key_size);
	prev_key = malloc(key_size);
	value = malloc(value_size);
	if (!key || !prev_key || !value) {
		removed = -ENOMEM;
		goto cleanup;
	}

	// Cannot delete current key because then loop will reset, see https://www.bouncybouncy.net/blog/bpf_map_get_next_key-pitfalls/
	while (bpf_map_get_next_key(map_fd, prev_key, key) == 0) {
		if (delete_prev) {
			bpf_map_delete_elem(map_fd, prev_key);
			removed++;
			delete_prev = false;
		}

		if (bpf_map_lookup_elem(map_fd, key, value) == 0)
			delete_prev = del_decision_func(key, value, now_nsec);
#ifdef DEBUG
		entries++;
#endif
		memcpy(prev_key, key, key_size);
	}
	if (delete_prev) {
		bpf_map_delete_elem(map_fd, prev_key);
		removed++;
	}
#ifdef DEBUG
	duration = get_time_ns(CLOCK_MONOTONIC) - now_nsec;
	fprintf(stderr,
		"%d: Gone through %d entries and removed %d of them in %llu.%09llu s\n",
		map_fd, entries, removed, duration / NS_PER_SECOND,
		duration % NS_PER_SECOND);
#endif
cleanup:
	free(key);
	free(prev_key);
	free(value);
	return removed;
}

static void *periodic_map_cleanup(void *args)
{
	struct map_cleanup_args *argp = args;
	struct timespec interval;
	interval.tv_sec = argp->cleanup_interval / NS_PER_SECOND;
	interval.tv_nsec = argp->cleanup_interval % NS_PER_SECOND;

	while (keep_running) {
		clean_map(argp->packet_map_fd, sizeof(struct packet_id),
			  sizeof(__u64), packet_ts_timeout);
		clean_map(argp->flow_map_fd, sizeof(struct network_tuple),
			  sizeof(struct flow_state), flow_timeout);
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
		return inet_ntop(af, &addr->s6_addr[12],
				 buf, size) ? -errno : 0;
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
		return "closing";
	default:
		return "unknown";
	}
}

static const char *eventreason_to_str(enum flow_event_reason er)
{
	switch (er) {
	case EVENT_REASON_SYN:
		return "SYN";
	case EVENT_REASON_SYN_ACK:
		return "SYN-ACK";
	case EVENT_REASON_FIRST_OBS_PCKT:
		return "first observed packet";
	case EVENT_REASON_FIN:
		return "FIN";
	case EVENT_REASON_FIN_ACK:
		return "FIN-ACK";
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
	case EVENT_SOURCE_EGRESS:
		return "src";
	case EVENT_SOURCE_INGRESS:
		return "dest";
	case EVENT_SOURCE_USERSPACE:
		return "userspace-cleanup";
	default:
		return "unknown";
	}
}

static void print_flow_ppvizformat(FILE *stream, const struct network_tuple *flow)
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

static void print_event_standard(void *ctx, int cpu, void *data,
				 __u32 data_size)
{
	const union pping_event *e = data;

	if (e->event_type == EVENT_TYPE_RTT) {
		print_ns_datetime(stdout, e->rtt_event.timestamp);
		printf(" %llu.%06llu ms %llu.%06llu ms ",
		       e->rtt_event.rtt / NS_PER_MS,
		       e->rtt_event.rtt % NS_PER_MS,
		       e->rtt_event.min_rtt / NS_PER_MS,
		       e->rtt_event.min_rtt % NS_PER_MS);
		print_flow_ppvizformat(stdout, &e->rtt_event.flow);
		printf("\n");
	} else if (e->event_type == EVENT_TYPE_FLOW) {
		print_ns_datetime(stdout, e->flow_event.timestamp);
		printf(" ");
		print_flow_ppvizformat(stdout, &e->flow_event.flow);
		printf(" %s due to %s from %s\n",
		       flowevent_to_str(e->flow_event.event_info.event),
		       eventreason_to_str(e->flow_event.event_info.reason),
		       eventsource_to_str(e->flow_event.source));
	}
}

static void print_event_ppviz(void *ctx, int cpu, void *data, __u32 data_size)
{
	const struct rtt_event *e = data;
	__u64 time = convert_monotonic_to_realtime(e->timestamp);

	if (e->event_type != EVENT_TYPE_RTT)
		return;

	printf("%llu.%09llu %llu.%09llu %llu.%09llu ", time / NS_PER_SECOND,
	       time % NS_PER_SECOND, e->rtt / NS_PER_SECOND,
	       e->rtt % NS_PER_SECOND, e->min_rtt / NS_PER_SECOND, e->min_rtt);
	print_flow_ppvizformat(stdout, &e->flow);
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
}

static void print_flowevent_fields_json(json_writer_t *ctx,
					const struct flow_event *fe)
{
	jsonw_string_field(ctx, "flow_event",
			   flowevent_to_str(fe->event_info.event));
	jsonw_string_field(ctx, "reason",
			   eventreason_to_str(fe->event_info.reason));
	jsonw_string_field(ctx, "triggered_by", eventsource_to_str(fe->source));
}

static void print_event_json(void *ctx, int cpu, void *data, __u32 data_size)
{
	const union pping_event *e = data;

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

static void handle_missed_rtt_event(void *ctx, int cpu, __u64 lost_cnt)
{
	fprintf(stderr, "Lost %llu RTT events on CPU %d\n", lost_cnt, cpu);
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
	char *unload_sec = strcmp(SEC_INGRESS_XDP, config->ingress_sec) == 0 ?
				   SEC_INGRESS_TC :
					 SEC_INGRESS_XDP;

	prog = bpf_object__find_program_by_title(obj, unload_sec);
	if (libbpf_get_error(prog))
		return libbpf_get_error(prog);

	return bpf_program__set_autoload(prog, false);
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
			config->object_path, strerror(-err));
		return err;
	}

	err = init_rodata(*obj, &config->bpf_config,
			  sizeof(config->bpf_config));
	if (err) {
		fprintf(stderr, "Failed pushing user-configration to %s: %s\n",
			config->object_path, strerror(-err));
		return err;
	}

	set_programs_to_load(*obj, config);
	err = bpf_object__load(*obj);
	if (err) {
		fprintf(stderr, "Failed loading bpf programs in %s: %s\n",
			config->object_path, strerror(-err));
		return err;
	}

	// Attach egress prog
	err = tc_attach(*obj, config->ifindex, BPF_TC_EGRESS,
			config->egress_sec, &config->tc_egress_opts);
	if (err) {
		fprintf(stderr,
			"Failed attaching egress BPF program on interface %s: %s\n",
			config->ifname, strerror(-err));
		return err;
	}

	// Attach ingress prog
	if (strcmp(config->ingress_sec, SEC_INGRESS_XDP) == 0)
		err = xdp_attach(*obj, config->ingress_sec, config->ifindex,
				 config->xdp_flags, config->force);
	else
		err = tc_attach(*obj, config->ifindex, BPF_TC_INGRESS,
				config->ingress_sec, &config->tc_ingress_opts);
	if (err) {
		fprintf(stderr,
			"Failed attaching ingress BPF program on interface %s: %s\n",
			config->ifname, strerror(-err));
		goto ingress_err;
	}

	return 0;

ingress_err:
	detach_err = tc_detach(config->ifindex, BPF_TC_EGRESS,
			       &config->tc_egress_opts);
	if (detach_err)
		fprintf(stderr, "Failed detaching tc program from %s: %s\n",
			config->ifname, strerror(-detach_err));
	return err;
}

static int setup_periodical_map_cleaning(struct bpf_object *obj,
					 struct pping_config *config)
{
	pthread_t tid;
	struct map_cleanup_args clean_args = {
		.cleanup_interval = config->cleanup_interval
	};
	int err;

	clean_args.packet_map_fd =
		bpf_object__find_map_fd_by_name(obj, config->packet_map);
	if (clean_args.packet_map_fd < 0) {
		fprintf(stderr, "Could not get file descriptor of map %s: %s\n",
			config->packet_map,
			strerror(-clean_args.packet_map_fd));
		return clean_args.packet_map_fd;
	}

	clean_args.flow_map_fd =
		bpf_object__find_map_fd_by_name(obj, config->flow_map);
	if (clean_args.flow_map_fd < 0) {
		fprintf(stderr, "Could not get file descriptor of map %s: %s\n",
			config->flow_map, strerror(-clean_args.flow_map_fd));
		return clean_args.packet_map_fd;
	}

	err = pthread_create(&tid, NULL, periodic_map_cleanup, &clean_args);
	if (err) {
		fprintf(stderr,
			"Failed starting thread to perform periodic map cleanup: %s\n",
			strerror(-err));
		return err;
	}

	return 0;
}

int main(int argc, char *argv[])
{
	int err = 0, detach_err;
	struct bpf_object *obj = NULL;
	struct perf_buffer *pb = NULL;
	struct perf_buffer_opts pb_opts = {
		.sample_cb = print_event_standard,
		.lost_cb = handle_missed_rtt_event,
	};

	DECLARE_LIBBPF_OPTS(bpf_tc_opts, tc_ingress_opts);
	DECLARE_LIBBPF_OPTS(bpf_tc_opts, tc_egress_opts);

	struct pping_config config = {
		.bpf_config = { .rate_limit = 100 * NS_PER_MS },
		.cleanup_interval = 1 * NS_PER_SECOND,
		.object_path = "pping_kern.o",
		.ingress_sec = SEC_INGRESS_XDP,
		.egress_sec = SEC_EGRESS_TC,
		.packet_map = "packet_ts",
		.flow_map = "flow_state",
		.event_map = "events",
		.xdp_flags = XDP_FLAGS_UPDATE_IF_NOEXIST,
		.tc_ingress_opts = tc_ingress_opts,
		.tc_egress_opts = tc_egress_opts,
	};

	print_event_func = print_event_standard;

	// Detect if running as root
	if (geteuid() != 0) {
		printf("This program must be run as root.\n");
		return EXIT_FAILURE;
	}

	// Increase rlimit
	err = set_rlimit(RLIM_INFINITY);
	if (err) {
		fprintf(stderr, "Could not set rlimit to infinity: %s\n",
			strerror(-err));
		return EXIT_FAILURE;
	}

	err = parse_arguments(argc, argv, &config);
	if (err) {
		fprintf(stderr, "Failed parsing arguments:  %s\n",
			strerror(-err));
		print_usage(argv);
		return EXIT_FAILURE;
	}

	if (config.json_format) {
		pb_opts.sample_cb = print_event_json;
		print_event_func = print_event_json;
	} else if (config.ppviz_format) {
		pb_opts.sample_cb = print_event_ppviz;
		print_event_func = print_event_ppviz;
	}

	err = load_attach_bpfprogs(&obj, &config);
	if (err) {
		fprintf(stderr,
			"Failed loading and attaching BPF programs in %s\n",
			config.object_path);
		return EXIT_FAILURE;
	}

	err = setup_periodical_map_cleaning(obj, &config);
	if (err) {
		fprintf(stderr, "Failed setting up map cleaning: %s\n",
			strerror(-err));
		goto cleanup_attached_progs;
	}

	// Set up perf buffer
	pb = perf_buffer__new(bpf_object__find_map_fd_by_name(obj,
							      config.event_map),
			      PERF_BUFFER_PAGES, &pb_opts);
	err = libbpf_get_error(pb);
	if (err) {
		fprintf(stderr, "Failed to open perf buffer %s: %s\n",
			config.event_map, strerror(err));
		goto cleanup_attached_progs;
	}

	// Allow program to perform cleanup on Ctrl-C
	signal(SIGINT, abort_program);

	// Main loop
	while (keep_running) {
		if ((err = perf_buffer__poll(pb, PERF_POLL_TIMEOUT_MS)) < 0) {
			if (keep_running) // Only print polling error if it wasn't caused by program termination
				fprintf(stderr,
					"Error polling perf buffer: %s\n",
					strerror(-err));
			break;
		}
	}

	// Cleanup
	if (config.json_format && json_ctx) {
		jsonw_end_array(json_ctx);
		jsonw_destroy(&json_ctx);
	}

	perf_buffer__free(pb);

cleanup_attached_progs:
	detach_err = tc_detach(config.ifindex, BPF_TC_EGRESS,
			       &config.tc_egress_opts);
	if (detach_err)
		fprintf(stderr,
			"Failed removing egress program from interface %s: %s\n",
			config.ifname, strerror(-detach_err));

	if (strcmp(config.ingress_sec, SEC_INGRESS_XDP) == 0)
		detach_err = xdp_detach(config.ifindex, config.xdp_flags);
	else
		detach_err = tc_detach(config.ifindex, BPF_TC_INGRESS,
				       &config.tc_ingress_opts);
	if (detach_err)
		fprintf(stderr,
			"Failed removing ingress program from interface %s: %s\n",
			config.ifname, strerror(-detach_err));

	return (err != 0 && keep_running) || detach_err != 0;
}
