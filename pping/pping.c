/* SPDX-License-Identifier: GPL-2.0-or-later */
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
#include <stdbool.h>
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
#define MAP_CLEANUP_INTERVAL                                                   \
	(1 * NS_PER_SECOND) // Clean timestamp map once per second
#define TIMESTAMP_LIFETIME                                                     \
	(10 * NS_PER_SECOND) // Clear out entries from ts_start if they're over 10 seconds

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
	int map_fd;
	__u64 max_age_ns;
};

static volatile int keep_running = 1;

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

/* static int mkdir_if_noexist(const char *path) */
/* { */
/* 	int ret; */
/* 	struct stat st = { 0 }; */

/* 	ret = stat(path, &st); */
/* 	if (ret) { */
/* 		if (errno != ENOENT) */
/* 			return -errno; */

/* 		return mkdir(path, 0700) ? -errno : 0; */
/* 	} */
/* 	return S_ISDIR(st.st_mode) ? 0 : -EEXIST; */
/* } */

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

// TODO - generalize mechanic so it can be used for cleaning both ts_start and flow_state maps
static int clean_map(int map_fd, __u64 max_age)
{
	int removed = 0;
	struct packet_id key, prev_key = { 0 };
	__u64 value;
	bool delete_prev = false;
	__u64 now_nsec = get_time_ns();

	int entries = 0; // Just for debug
	__u64 duration; // Just for debug

	if (now_nsec == 0)
		return -errno;

	// Cannot delete current key because then loop will reset, see https://www.bouncybouncy.net/blog/bpf_map_get_next_key-pitfalls/
	while (bpf_map_get_next_key(map_fd, &prev_key, &key) == 0) {
		if (delete_prev) {
			bpf_map_delete_elem(map_fd, &prev_key);
			removed++;
			delete_prev = false;
		}

		if (bpf_map_lookup_elem(map_fd, &key, &value) == 0) {
			if (now_nsec > value &&
			    now_nsec - value > max_age) {
				delete_prev = true;
			}
		}
		entries++;
		prev_key = key;
	}
	if (delete_prev) {
		bpf_map_delete_elem(map_fd, &prev_key);
		removed++;
	}
	duration = get_time_ns() - now_nsec;
	printf("Gone through %d entries and removed %d of them in %llu.%09llu s\n",
	       entries, removed, duration / NS_PER_SECOND,
	       duration % NS_PER_SECOND);
	return removed;
}

static void *periodic_map_cleanup(void *args)
{
	struct map_cleanup_args *argp = args;
	struct timespec interval;
	interval.tv_sec = MAP_CLEANUP_INTERVAL / NS_PER_SECOND;
	interval.tv_nsec = MAP_CLEANUP_INTERVAL % NS_PER_SECOND;

	while (keep_running) {
		clean_map(argp->map_fd, argp->max_age_ns);
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
	bool xdp_attached = false;
	bool tc_attached = false;
	char path_buffer[MAX_PATH_LEN];

	struct bpf_object *xdp_obj = NULL;
	struct bpf_object *tc_obj = NULL;
	struct bpf_map *map = NULL;

	pthread_t tid;
	struct map_cleanup_args clean_args;

	struct perf_buffer *pb = NULL;
	struct perf_buffer_opts pb_opts;

	// TODO - better argument parsing (more relevant as featureas are added)
	if (argc < 2) {
		printf("Usage: ./pping_user <dev>\n");
		return EXIT_FAILURE;
	}

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
		goto cleanup;
	}

	// Get index of interface
	ifindex = if_nametoindex(argv[1]);
	if (ifindex == 0) {
		err = -errno;
		fprintf(stderr, "Could not get index of interface %s: %s\n",
			argv[1], strerror(-err));
		goto cleanup;
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
			argv[1], strerror(-err));
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

	err = tc_bpf_attach(PINNED_DIR, TCBPF_PROG_SEC, argv[1]);
	if (err) {
		fprintf(stderr,
			"Failed attaching tc program on interface %s: %s\n",
			argv[1], strerror(-err));
		goto cleanup;
	}
	tc_attached = true;

	// Set up the periodical map cleaning
	clean_args.max_age_ns = TIMESTAMP_LIFETIME;
	clean_args.map_fd = bpf_object__find_map_fd_by_name(xdp_obj, TS_MAP);
	if (clean_args.map_fd < 0) {
		fprintf(stderr,
			"Could not get file descriptor of map  %s in object %s: %s\n",
			TS_MAP, PPING_XDP_OBJ, strerror(-clean_args.map_fd));
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
	pb_opts.sample_cb = handle_rtt_event;
	pb_opts.lost_cb = handle_missed_rtt_event;

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
		err = tc_bpf_clear(argv[1]);
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

	/* 
	 * Could use bpf_obj__unpin_maps(obj, PINNED_DIR) if it only tried
	 * unpinning pinned maps. But as it also attempts (and fails) to unpin
	 * maps that aren't pinned, will instead manually unpin the one pinned
	 * map for now.
	 */
	if (xdp_obj) {
		if ((map = bpf_object__find_map_by_name(xdp_obj, TS_MAP)) &&
		    bpf_map__is_pinned(map)) {
			snprintf(path_buffer, sizeof(path_buffer), "%s/%s",
				 PINNED_DIR, TS_MAP);
			err = bpf_map__unpin(map, path_buffer);
			if (err)
				fprintf(stderr,
					"Failed unpinning map from %s: %s\n",
					path_buffer, strerror(-err));
		}
	}

	return err != 0;
}
