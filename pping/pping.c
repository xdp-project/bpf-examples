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

#include "pping.h" //key and value structs for the ts_start map

#define NS_PER_SECOND 1000000000UL
#define NS_PER_MS 1000000UL

#define TCBPF_LOADER_SCRIPT "./bpf_egress_loader.sh"
#define PINNED_DIR "/sys/fs/bpf/pping"
#define PPING_XDP_OBJ "pping_kern_xdp.o"
#define PPING_TCBPF_OBJ "pping_kern_tc.o"

#define XDP_FLAGS XDP_FLAGS_UPDATE_IF_NOEXIST

#define TS_MAP "ts_start"
#define FLOW_MAP "flow_state"
#define MAP_CLEANUP_INTERVAL                                                   \
	(1 * NS_PER_SECOND) // Clean timestamp map once per second
#define TIMESTAMP_LIFETIME                                                     \
	(10 * NS_PER_SECOND) // Clear out packet timestamps if they're over 10 seconds
#define FLOW_LIFETIME                                                     \
	(300 * NS_PER_SECOND) // Clear out flows if they're inactive over 300 seconds

#define DEFAULT_RATE_LIMIT                                                     \
	(100 * NS_PER_MS) // Allow one timestamp entry per flow every 100 ms

#define PERF_BUFFER "rtt_events"
#define PERF_BUFFER_PAGES 64 // Related to the perf-buffer size?
#define PERF_POLL_TIMEOUT_MS 100

#define MAX_PATH_LEN 1024

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
	int packet_map_fd;
	int flow_map_fd;
};

static volatile int keep_running = 1;

static const struct option long_options[] = {
	{ "help",       no_argument,       NULL, 'h' },
	{ "interface",  required_argument, NULL, 'i' },
	{ "rate-limit", required_argument, NULL, 'r' },
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
			printf(" short-option: -%c",
				long_options[i].val);
		printf("\n");
	}
	printf("\n");
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

static int bpf_obj_open(struct bpf_object **obj, const char *obj_path,
			char *map_path)
{
	DECLARE_LIBBPF_OPTS(bpf_object_open_opts, opts,
			    .pin_root_path = map_path);
	*obj = bpf_object__open_file(obj_path, map_path ? &opts : NULL);
	return libbpf_get_error(*obj);
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
	int err;

	if (sec)
		prog = bpf_object__find_program_by_title(obj, sec);
	else
		prog = bpf_program__next(NULL, obj);

	prog_fd = bpf_program__fd(prog);
	if (prog_fd < 0) {
		fprintf(stderr, "Could not find program to attach\n");
		return prog_fd;
	}

	if (force) // detach current (if any) xdp-program first
		xdp_detach(ifindex, xdp_flags);

	err = bpf_set_link_xdp_fd(ifindex, prog_fd, xdp_flags);
	if (err < 0) {
		fprintf(stderr, "Failed loading xdp-program on interface %d\n",
			ifindex);
		return err;
	}
	return 0;
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

static int run_program(const char *path, char *const argv[])
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

static int tc_bpf_attach(char *pin_dir, char *section, char *interface)
{
	char prog_path[MAX_PATH_LEN];
	char *const argv[] = { TCBPF_LOADER_SCRIPT, "--dev", interface, "--pinned", prog_path, NULL };

	if(snprintf(prog_path, sizeof(prog_path), "%s/%s", pin_dir, section) < 0)
		return -EINVAL;

	return run_program(TCBPF_LOADER_SCRIPT, argv);
}

static int tc_bpf_clear(char *interface)
{
	char *const argv[] = { TCBPF_LOADER_SCRIPT, "--dev", interface,
			       "--remove", NULL };
	return run_program(TCBPF_LOADER_SCRIPT, argv);
}

/*
 * Returns time of CLOCK_MONOTONIC as nanoseconds in a single __u64.
 * On failure, the value 0 is returned (and errno will be set).
 */
static __u64 get_time_ns(void)
{
	struct timespec t;
	if (clock_gettime(CLOCK_MONOTONIC, &t) != 0)
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
	__u64 now_nsec = get_time_ns();

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
	duration = get_time_ns() - now_nsec;
	printf("%d: Gone through %d entries and removed %d of them in %llu.%09llu s\n",
	       map_fd, entries, removed, duration / NS_PER_SECOND,
	       duration % NS_PER_SECOND);
#endif
cleanup:
	if (key)
		free(key);
	if (prev_key)
		free(prev_key);
	if (value)
		free(value);
	return removed;
}

/*
 * Periodically cleans out entries from both the packet timestamp map and the
 * flow state map. Maybe better to split up the cleaning of the maps into two
 * separate threads instead, to better utilize multi-threading and allow for
 * maps to be cleaned up at different intervals?
 */
static void *periodic_map_cleanup(void *args)
{
	struct map_cleanup_args *argp = args;
	struct timespec interval;
	interval.tv_sec = MAP_CLEANUP_INTERVAL / NS_PER_SECOND;
	interval.tv_nsec = MAP_CLEANUP_INTERVAL % NS_PER_SECOND;

	while (keep_running) {
		clean_map(argp->packet_map_fd, sizeof(struct packet_id),
			  sizeof(__u64), packet_ts_timeout);
		clean_map(argp->flow_map_fd, sizeof(struct network_tuple),
			  sizeof(struct flow_state), flow_timeout);
		nanosleep(&interval, NULL);
	}
	pthread_exit(NULL);
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

static void handle_rtt_event(void *ctx, int cpu, void *data, __u32 data_size)
{
	const struct rtt_event *e = data;
	char saddr[INET6_ADDRSTRLEN];
	char daddr[INET6_ADDRSTRLEN];

	format_ip_address(e->flow.ipv, &e->flow.saddr.ip, saddr, sizeof(saddr));
	format_ip_address(e->flow.ipv, &e->flow.daddr.ip, daddr, sizeof(daddr));

	printf("%llu.%06llu ms %s:%d+%s:%d\n", e->rtt / NS_PER_MS,
	       e->rtt % NS_PER_MS, saddr, ntohs(e->flow.saddr.port), daddr,
	       ntohs(e->flow.daddr.port));
}

static void handle_missed_rtt_event(void *ctx, int cpu, __u64 lost_cnt)
{
	fprintf(stderr, "Lost %llu RTT events on CPU %d\n", lost_cnt, cpu);
}

int main(int argc, char *argv[])
{
	int err = 0;
	int ifindex = 0;
	int opt, longindex = 0;
	char ifname[IF_NAMESIZE];
	unsigned long rate_limit_ms = -1;
	bool xdp_attached = false;
	bool tc_attached = false;

	struct bpf_object *xdp_obj = NULL;
	struct bpf_object *tc_obj = NULL;

	struct user_config config = { .rate_limit = DEFAULT_RATE_LIMIT };

	pthread_t tid;
	struct map_cleanup_args clean_args;

	struct perf_buffer *pb = NULL;
	struct perf_buffer_opts pb_opts = {
		.sample_cb = handle_rtt_event,
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

	while ((opt = getopt_long(argc, argv, "hi:r:", long_options,
				  &longindex)) != -1) {
		switch (opt) {
		case 'i':
			if (strlen(optarg) > IF_NAMESIZE) {
				fprintf(stderr, "interface name too long\n");
				return EXIT_FAILURE;
			}

			strncpy(ifname, optarg, IF_NAMESIZE);
			ifindex = if_nametoindex(ifname);
			if (ifindex == 0) {
				err = -errno;
				fprintf(stderr,
					"Could not get index of interface %s: %s\n",
					ifname, strerror(-err));
				return EXIT_FAILURE;
			}

			break;
		case 'r':
			rate_limit_ms = strtoul(optarg, NULL, 10);
			if (rate_limit_ms == ULONG_MAX) {
				fprintf(stderr,
					"rate-limit \"%s\" ms is invalid\n",
					optarg);
				return EXIT_FAILURE;
			}
			config.rate_limit = rate_limit_ms * NS_PER_MS;
			break;
		case 'h':
			print_usage(argv);
			return 0;
		default:
			print_usage(argv);
			return EXIT_FAILURE;
		}
	}

	if (ifindex == 0) {
		fprintf(stderr,
			"An interface (-i or --interface) must be provided\n");
		return EXIT_FAILURE;
	}

	// Load and attach the XDP program
	err = bpf_obj_open(&xdp_obj, PPING_XDP_OBJ, PINNED_DIR);
	if (err) {
		fprintf(stderr, "Failed opening object file %s: %s\n",
			PPING_XDP_OBJ, strerror(-err));
		goto cleanup;
	}

	err = bpf_object__load(xdp_obj);
	if (err) {
		fprintf(stderr, "Failed loading XDP program: %s\n",
			strerror(-err));
		goto cleanup;
	}

	err = xdp_attach(xdp_obj, XDP_PROG_SEC, ifindex, XDP_FLAGS, false);
	if (err) {
		fprintf(stderr, "Failed attaching XDP program to %s: %s\n",
			ifname, strerror(-err));
		goto cleanup;
	}
	xdp_attached = true;

	// Load, pin and attach tc program on egress
	err = bpf_obj_open(&tc_obj, PPING_TCBPF_OBJ, PINNED_DIR);
	if (err) {
		fprintf(stderr, "Failed opening object file %s: %s\n",
			PPING_TCBPF_OBJ, strerror(-err));
		goto cleanup;
	}

	err = init_rodata(tc_obj, &config, sizeof(config));
	if (err) {
		fprintf(stderr, "Failed pushing user-configration to %s: %s\n",
			PPING_TCBPF_OBJ, strerror(-err));
		goto cleanup;
	}

	err = bpf_object__load(tc_obj);
	if (err) {
		fprintf(stderr, "Failed loading tc program: %s\n",
			strerror(-err));
		goto cleanup;
	}

	err = bpf_object__pin_programs(tc_obj, PINNED_DIR);
	if (err) {
		fprintf(stderr, "Failed pinning tc program to %s: %s\n",
			PINNED_DIR, strerror(-err));
		goto cleanup;
	}

	err = tc_bpf_attach(PINNED_DIR, TCBPF_PROG_SEC, ifname);
	if (err) {
		fprintf(stderr,
			"Failed attaching tc program on interface %s: %s\n",
			ifname, strerror(-err));
		goto cleanup;
	}
	tc_attached = true;

	// Set up the periodical map cleaning
	clean_args.packet_map_fd =
		bpf_object__find_map_fd_by_name(xdp_obj, TS_MAP);
	if (clean_args.packet_map_fd < 0) {
		fprintf(stderr,
			"Could not get file descriptor of map  %s in object %s: %s\n",
			TS_MAP, PPING_XDP_OBJ,
			strerror(-clean_args.packet_map_fd));
		goto cleanup;
	}

	clean_args.flow_map_fd =
		bpf_object__find_map_fd_by_name(tc_obj, FLOW_MAP);
	if (clean_args.flow_map_fd < 0) {
		fprintf(stderr,
			"Could not get file descriptor of map  %s in object %s: %s\n",
			FLOW_MAP, PPING_TCBPF_OBJ,
			strerror(-clean_args.flow_map_fd));
		goto cleanup;
	}

	err = pthread_create(&tid, NULL, periodic_map_cleanup, &clean_args);
	if (err) {
		fprintf(stderr,
			"Failed starting thread to perform periodic map cleanup: %s\n",
			strerror(err));
		goto cleanup;
	}

	// Set up perf buffer
	pb = perf_buffer__new(bpf_object__find_map_fd_by_name(xdp_obj,
							      PERF_BUFFER),
			      PERF_BUFFER_PAGES, &pb_opts);
	err = libbpf_get_error(pb);
	if (err) {
		pb = NULL;
		fprintf(stderr, "Failed to open perf buffer %s: %s\n",
			PERF_BUFFER, strerror(err));
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

	if (xdp_attached) {
		err = xdp_detach(ifindex, XDP_FLAGS);
		if (err)
			fprintf(stderr,
				"Failed deatching program from ifindex %d: %s\n",
				ifindex, strerror(-err));
	}

	if (tc_attached) {
		err = tc_bpf_clear(ifname);
		if (err)
			fprintf(stderr,
				"Failed removing tc-bpf program from interface %s: %s\n",
				argv[1], strerror(-err));
	}

	if (tc_obj) {
		err = bpf_object__unpin_programs(tc_obj, PINNED_DIR);
		if (err)
			fprintf(stderr,
				"Failed unpinning tc program from %s: %s\n",
				PINNED_DIR, strerror(-err));
	}

	if (xdp_obj) {
		err = bpf_object__unpin_maps(xdp_obj, NULL);
		if (err)
			fprintf(stderr, "Failed unpinning maps: %s\n",
				strerror(-err));
	}

	return err != 0;
}
