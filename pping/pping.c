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

#include "pping.h" //common structs for user-space and BPF parts

#define NS_PER_SECOND 1000000000UL
#define NS_PER_MS 1000000UL

#define TCBPF_LOADER_SCRIPT "./bpf_egress_loader.sh"

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
	__u64 cleanup_interval;
	char *object_path;
	char *ingress_sec;
	char *egress_sec;
	char *pin_dir;
	char *packet_map;
	char *flow_map;
	char *rtt_map;
	int xdp_flags;
	int ifindex;
	char ifname[IF_NAMESIZE];
	bool json_format;
	bool ppviz_format;
	bool force;
};

static volatile int keep_running = 1;
static bool json_started = false;

static const struct option long_options[] = {
	{ "help",             no_argument,       NULL, 'h' },
	{ "interface",        required_argument, NULL, 'i' }, // Name of interface to run on
	{ "rate-limit",       required_argument, NULL, 'r' }, // Sampling rate-limit in ms
	{ "force",            no_argument,       NULL, 'f' }, // Detach any existing XDP program on interface
	{ "cleanup-interval", required_argument, NULL, 'c' }, // Map cleaning interval in s
	{ "format",           required_argument, NULL, 'F' }, // Which format to output in (standard/json/ppviz)
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

	while ((opt = getopt_long(argc, argv, "hfi:r:c:F:", long_options,
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

static int
bpf_obj_run_prog_pindir_func(struct bpf_object *obj, const char *prog_title,
			     const char *pin_dir,
			     int (*func)(struct bpf_program *, const char *))
{
	int len;
	struct bpf_program *prog;
	char path[MAX_PATH_LEN];

	len = snprintf(path, MAX_PATH_LEN, "%s/%s", pin_dir, prog_title);
	if (len < 0)
		return len;
	if (len > MAX_PATH_LEN)
		return -ENAMETOOLONG;

	prog = bpf_object__find_program_by_title(obj, prog_title);
	if (!prog || libbpf_get_error(prog))
		return prog ? libbpf_get_error(prog) : -EINVAL;

	return func(prog, path);
}

/*
 * Similar to bpf_object__pin_programs, but only attemps to pin a
 * single program prog_title at path pin_dir/prog_title
 */
static int bpf_obj_pin_program(struct bpf_object *obj, const char *prog_title,
			       const char *pin_dir)
{
	return bpf_obj_run_prog_pindir_func(obj, prog_title, pin_dir,
					    bpf_program__pin);
}

/*
 * Similar to bpf_object__unpin_programs, but only attempts to unpin a
 * single program prog_title at path pin_dir/prog_title.
 */
static int bpf_obj_unpin_program(struct bpf_object *obj, const char *prog_title,
				 const char *pin_dir)
{
	return bpf_obj_run_prog_pindir_func(obj, prog_title, pin_dir,
					    bpf_program__unpin);
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

static int run_external_program(const char *path, char *const argv[])
{
	int status;
	int ret = -1;

	pid_t pid = fork();

	if (pid < 0)
		return -errno;
	if (pid == 0) {
		execv(path, argv);
		return -errno;
	} else { //pid > 0
		waitpid(pid, &status, 0);
		if (WIFEXITED(status))
			ret = WEXITSTATUS(status);
		return ret;
	}
}

static int tc_bpf_attach(const char *pin_dir, const char *section,
			 char *interface)
{
	char prog_path[MAX_PATH_LEN];
	char *const argv[] = { TCBPF_LOADER_SCRIPT, "--dev",   interface,
			       "--pinned",	    prog_path, NULL };

	if (snprintf(prog_path, sizeof(prog_path), "%s/%s", pin_dir, section) < 0)
		return -EINVAL;

	return run_external_program(TCBPF_LOADER_SCRIPT, argv);
}

static int tc_bpf_clear(char *interface)
{
	char *const argv[] = { TCBPF_LOADER_SCRIPT, "--dev", interface,
			       "--remove", NULL };
	return run_external_program(TCBPF_LOADER_SCRIPT, argv);
}

/*
 * Returns time of CLOCK_MONOTONIC as nanoseconds in a single __u64.
 * On failure, the value 0 is returned (and errno will be set).
 */
static __u64 get_time_ns(clockid_t clockid)
{
	struct timespec t;
	if (clock_gettime(clockid, &t) != 0)
		return 0;

	return (__u64)t.tv_sec * NS_PER_SECOND + (__u64)t.tv_nsec;
}

static bool packet_ts_timeout(void *val_ptr, __u64 now)
{
	__u64 ts = *(__u64 *)val_ptr;
	if (now > ts && now - ts > TIMESTAMP_LIFETIME)
		return true;
	return false;
}

static bool flow_timeout(void *val_ptr, __u64 now)
{
	__u64 ts = ((struct flow_state *)val_ptr)->last_timestamp;
	if (now > ts && now - ts > FLOW_LIFETIME)
		return true;
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
		     bool (*del_decision_func)(void *, __u64))
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
			delete_prev = del_decision_func(value, now_nsec);
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
	__u64 now_mon, now_rt;
	static __u64 offset = 0;
	static __u64 offset_updated = 0;

	now_mon = get_time_ns(CLOCK_MONOTONIC);
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
static int format_ip_address(int af, const struct in6_addr *addr, char *buf,
			     size_t size)
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

static void print_rtt_event_standard(void *ctx, int cpu, void *data,
				     __u32 data_size)
{
	const struct rtt_event *e = data;
	char saddr[INET6_ADDRSTRLEN];
	char daddr[INET6_ADDRSTRLEN];
	char timestr[9];
	__u64 ts = convert_monotonic_to_realtime(e->timestamp);
	time_t ts_s = ts / NS_PER_SECOND;

	format_ip_address(e->flow.ipv, &e->flow.saddr.ip, saddr, sizeof(saddr));
	format_ip_address(e->flow.ipv, &e->flow.daddr.ip, daddr, sizeof(daddr));
	strftime(timestr, sizeof(timestr), "%H:%M:%S", localtime(&ts_s));

	printf("%s.%09llu %llu.%06llu ms %llu.%06llu ms %s:%d+%s:%d\n", timestr,
	       ts % NS_PER_SECOND, e->rtt / NS_PER_MS, e->rtt % NS_PER_MS,
	       e->min_rtt / NS_PER_MS, e->min_rtt % NS_PER_MS, saddr,
	       ntohs(e->flow.saddr.port), daddr, ntohs(e->flow.daddr.port));
}

static void print_rtt_event_ppviz(void *ctx, int cpu, void *data,
				  __u32 data_size)
{
	const struct rtt_event *e = data;
	char saddr[INET6_ADDRSTRLEN];
	char daddr[INET6_ADDRSTRLEN];
	__u64 time = convert_monotonic_to_realtime(e->timestamp);

	format_ip_address(e->flow.ipv, &e->flow.saddr.ip, saddr, sizeof(saddr));
	format_ip_address(e->flow.ipv, &e->flow.daddr.ip, daddr, sizeof(daddr));

	printf("%llu.%09llu %llu.%09llu %llu.%09llu %s:%d+%s:%d\n",
	       time / NS_PER_SECOND, time % NS_PER_SECOND,
	       e->rtt / NS_PER_SECOND, e->rtt % NS_PER_SECOND,
	       e->min_rtt / NS_PER_SECOND, e->min_rtt, saddr,
	       ntohs(e->flow.saddr.port), daddr, ntohs(e->flow.daddr.port));
}

static void print_rtt_event_json(void *ctx, int cpu, void *data,
				 __u32 data_size)
{
	const struct rtt_event *e = data;
	char saddr[INET6_ADDRSTRLEN];
	char daddr[INET6_ADDRSTRLEN];
	__u64 time = convert_monotonic_to_realtime(e->timestamp);

	format_ip_address(e->flow.ipv, &e->flow.saddr.ip, saddr, sizeof(saddr));
	format_ip_address(e->flow.ipv, &e->flow.daddr.ip, daddr, sizeof(daddr));

	if (json_started) {
		printf(",");
	} else {
		printf("[");
		json_started = true;
	}

	printf("\n{\"timestamp\":%llu.%09llu, \"rtt\":%llu.%09llu, "
	       "\"min_rtt\":%llu.%09llu, \"src_ip\":\"%s\", \"src_port\":%d, "
	       "\"dest_ip\":\"%s\", \"dest_port\":%d, \"protocol\":\"%s\", "
	       "\"sent_pkts\":%llu, \"sent_bytes\":%llu, \"rec_pkts\":%llu, "
	       "\"rec_bytes\":%llu }",
	       time / NS_PER_SECOND, time % NS_PER_SECOND,
	       e->rtt / NS_PER_SECOND, e->rtt % NS_PER_SECOND,
	       e->min_rtt / NS_PER_SECOND, e->min_rtt % NS_PER_SECOND, saddr,
	       ntohs(e->flow.saddr.port), daddr, ntohs(e->flow.daddr.port),
	       proto_to_str(e->flow.proto), e->sent_pkts, e->sent_bytes,
	       e->rec_pkts, e->rec_bytes);
}

static void end_json_output(void)
{
	if (json_started)
		printf("\n]\n");
	else
		printf("[]\n");
}

static void handle_missed_rtt_event(void *ctx, int cpu, __u64 lost_cnt)
{
	fprintf(stderr, "Lost %llu RTT events on CPU %d\n", lost_cnt, cpu);
}

static int load_attach_bpfprogs(struct bpf_object **obj,
				struct pping_config *config, bool *tc_attached,
				bool *xdp_attached)
{
	int err;

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

	err = bpf_object__load(*obj);
	if (err) {
		fprintf(stderr, "Failed loading bpf program in %s: %s\n",
			config->object_path, strerror(-err));
		return err;
	}

	// Attach tc program
	err = bpf_obj_pin_program(*obj, config->egress_sec, config->pin_dir);
	if (err) {
		fprintf(stderr, "Failed pinning tc program to %s/%s: %s\n",
			config->pin_dir, config->egress_sec, strerror(-err));
		return err;
	}

	err = tc_bpf_attach(config->pin_dir, config->egress_sec,
			    config->ifname);
	if (err) {
		fprintf(stderr,
			"Failed attaching tc program on interface %s: %s\n",
			config->ifname, strerror(-err));
		return err;
	}
	*tc_attached = true;

	// Attach XDP program
	err = xdp_attach(*obj, config->ingress_sec, config->ifindex,
			 config->xdp_flags, config->force);
	if (err) {
		fprintf(stderr, "Failed attaching XDP program to %s%s: %s\n",
			config->ifname,
			config->force ? "" : ", ensure no other XDP program is already running on interface",
			strerror(-err));
		return err;
	}
	*xdp_attached = true;

	return 0;
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
	int err = 0;

	bool tc_attached = false;
	bool xdp_attached = false;

	struct bpf_object *obj = NULL;

	struct pping_config config = {
		.bpf_config = { .rate_limit = 100 * NS_PER_MS },
		.cleanup_interval = 1 * NS_PER_SECOND,
		.object_path = "pping_kern.o",
		.ingress_sec = INGRESS_PROG_SEC,
		.egress_sec = EGRESS_PROG_SEC,
		.pin_dir = "/sys/fs/bpf/pping",
		.packet_map = "packet_ts",
		.flow_map = "flow_state",
		.rtt_map = "rtt_events",
		.xdp_flags = XDP_FLAGS_UPDATE_IF_NOEXIST,
	};

	struct perf_buffer *pb = NULL;
	struct perf_buffer_opts pb_opts = {
		.sample_cb = print_rtt_event_standard,
		.lost_cb = handle_missed_rtt_event,
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

	if (config.json_format)
		pb_opts.sample_cb = print_rtt_event_json;
	else if (config.ppviz_format)
		pb_opts.sample_cb = print_rtt_event_ppviz;

	err = load_attach_bpfprogs(&obj, &config, &tc_attached, &xdp_attached);
	if (err) {
		fprintf(stderr,
			"Failed loading and attaching BPF programs in %s\n",
			config.object_path);
		goto cleanup;
	}

	err = setup_periodical_map_cleaning(obj, &config);
	if (err) {
		fprintf(stderr, "Failed setting up map cleaning: %s\n",
			strerror(-err));
		goto cleanup;
	}

	// Set up perf buffer
	pb = perf_buffer__new(bpf_object__find_map_fd_by_name(obj,
							      config.rtt_map),
			      PERF_BUFFER_PAGES, &pb_opts);
	err = libbpf_get_error(pb);
	if (err) {
		pb = NULL;
		fprintf(stderr, "Failed to open perf buffer %s: %s\n",
			config.rtt_map, strerror(err));
		goto cleanup;
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

cleanup:
	perf_buffer__free(pb);

	if (config.json_format)
		end_json_output();

	if (xdp_attached) {
		err = xdp_detach(config.ifindex, config.xdp_flags);
		if (err)
			fprintf(stderr,
				"Failed deatching program from ifindex %s: %s\n",
				config.ifname, strerror(-err));
	}

	if (tc_attached) {
		err = tc_bpf_clear(config.ifname);
		if (err)
			fprintf(stderr,
				"Failed removing tc-bpf program from interface %s: %s\n",
				config.ifname, strerror(-err));
	}

	if (obj && !libbpf_get_error(obj)) {
		err = bpf_obj_unpin_program(obj, config.egress_sec,
					    config.pin_dir);
		if (err)
			fprintf(stderr,
				"Failed unpinning tc program from %s: %s\n",
				config.pin_dir, strerror(-err));
	}

	return err != 0;
}
