//#include <linux/bpf.h>
#include <linux/if_link.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <net/if.h> // For if_nametoindex
//#include <linux/err.h> // For IS_ERR_OR_NULL macro // use libbpf_get_error instead
#include <arpa/inet.h> // For inet_ntoa and ntohs

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <stdbool.h>
#include <signal.h> // For detecting Ctrl-C
#include <sys/resource.h> // For setting rlmit
#include <time.h>
#include <pthread.h>
#include "pping.h" //key and value structs for the ts_start map

#define BILLION 1000000000UL
#define TCBPF_LOADER_SCRIPT "./bpf_egress_loader.sh"
#define PPING_XDP_OBJ "pping_kern_xdp.o"
#define XDP_PROG_SEC "pping_ingress"
#define PPING_TCBPF_OBJ "pping_kern_tc.o"
#define TCBPF_PROG_SEC "pping_egress"
#define XDP_FLAGS XDP_FLAGS_UPDATE_IF_NOEXIST
#define MAP_NAME "ts_start"
#define MAP_CLEANUP_INTERVAL 1*BILLION // Clean timestamp map once per second 
#define PERF_BUFFER_NAME "rtt_events"
#define PERF_BUFFER_PAGES 64 // Related to the perf-buffer size?
#define PERF_POLL_TIMEOUT_MS 100
#define RMEMLIM 512UL << 20 /* 512 MBs */
#define MAX_COMMAND_LEN 1024
#define ERROR_MSG_MAX 1024
#define TIMESTAMP_LIFETIME 10*BILLION // 10 seconds

struct map_cleanup_args {
  int map_fd;
  __u64 max_age_ns;
};

/* static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args) */
/* { */
/* 	return vfprintf(stderr, format, args); */
/* } */

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
 
static int xdp_load_and_attach(int ifindex, char *obj_path, char *sec, __u32 xdp_flags, struct bpf_object **obj, int *prog_fd, char *error_buf)
{
  // Load and attach XDP program to interface
  struct bpf_program *prog = NULL;
  int err;
  *prog_fd = -1;
  
  struct bpf_prog_load_attr attr = {
    .prog_type = BPF_PROG_TYPE_XDP,
    //.ifindex = ifindex,
    .file = obj_path,
  };

  err = bpf_prog_load_xattr(&attr, obj, prog_fd);
  if (err) {
    if (error_buf) { snprintf(error_buf, ERROR_MSG_MAX, "Could not open %s", obj_path); }
    return err;
  }

  prog = bpf_object__find_program_by_title(*obj, sec);
  if (!prog) {
    if (error_buf) { snprintf(error_buf, ERROR_MSG_MAX, "Could not find section %s in object %s", sec, obj_path); }
    return -1;
  }

  *prog_fd = bpf_program__fd(prog);
  err = bpf_set_link_xdp_fd(ifindex, *prog_fd, xdp_flags);
  if (err < 0) {
    if (error_buf) { snprintf(error_buf, ERROR_MSG_MAX, "Failed attaching XDP program %s in %s to ifindex %d", sec, obj_path, ifindex); }
    return err;
  }
  return 0;
}

static int xdp_deatach(int ifindex, __u32 xdp_flags) {
  return bpf_set_link_xdp_fd(ifindex, -1, xdp_flags);
}

static __u64 get_time_ns(clockid_t clockid)
{
  struct timespec t;
  if (clock_gettime(clockid, &t) != 0) // CLOCK_BOOTTIME if using bpf_get_ktime_boot_ns
    return 0;
  return (__u64)t.tv_sec * BILLION + (__u64)t.tv_nsec;
}

static int remove_old_entries_from_map(int map_fd, __u64 max_age)
{
  int removed = 0, entries = 0;
  struct ts_key key, prev_key = {0};
  struct ts_timestamp value;
  bool delete_prev = false;
  __u64 now_nsec = get_time_ns(CLOCK_MONOTONIC);
  if (now_nsec == 0)
    return -errno;

  // Cannot delete current key because then loop will reset, see https://www.bouncybouncy.net/blog/bpf_map_get_next_key-pitfalls/
  while(bpf_map_get_next_key(map_fd, &prev_key, &key) == 0) {
    if (delete_prev) {
      bpf_map_delete_elem(map_fd, &prev_key);
      removed++;
      delete_prev = false;
    }

    if (bpf_map_lookup_elem(map_fd, &key, &value) == 0) {
      if (now_nsec > value.timestamp && now_nsec - value.timestamp > max_age) {
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
  __u64 duration = get_time_ns(CLOCK_MONOTONIC) - now_nsec;
  printf("Gone through %d entries and removed %d of them in %llu.%09llu\n", entries, removed, duration / BILLION, duration % BILLION);
  return removed;
}

static void *periodic_map_cleanup(void *args)
{
  struct map_cleanup_args *argp = args;
  struct timespec interval;
  interval.tv_sec = MAP_CLEANUP_INTERVAL / BILLION;
  interval.tv_nsec = MAP_CLEANUP_INTERVAL % BILLION;
  while (keep_running) {
    remove_old_entries_from_map(argp->map_fd, argp->max_age_ns);
    nanosleep(&interval, NULL);
  }
  pthread_exit(NULL);
}

static void handle_rtt_event(void *ctx, int cpu, void *data, __u32 data_size)
{
  const struct rtt_event *e = data;
  struct in_addr saddr, daddr;
  saddr.s_addr = e->flow.saddr;
  daddr.s_addr = e->flow.daddr;
  printf("%llu.%09llu ms %s:%d+%s:%d\n", e->rtt / BILLION, e->rtt % BILLION,
	 inet_ntoa(saddr), ntohs(e->flow.sport),
	 inet_ntoa(daddr), ntohs(e->flow.dport));	 
}

static void handle_missed_rtt_event(void *ctx, int cpu, __u64 lost_cnt)
{
  fprintf(stderr, "Lost %llu RTT events on CPU %d\n", lost_cnt, cpu);
}

int main(int argc, char *argv[])
{
  if (argc < 2) {
    printf("Usage: ./pping_user <dev>\n");
    return EXIT_FAILURE;
  }

  int err = 0, ifindex = 0;
  bool xdp_attached = false;
  char error_msg[ERROR_MSG_MAX];
  struct perf_buffer *pb = NULL;

  // Setup libbpf errors and debug info on callback
  //libbpf_set_print(libbpf_print_fn);

  // Increase rlimit
  err = set_rlimit(RMEMLIM);
  if (err) {
    fprintf(stderr, "Could not set rlimit to %ld bytes: %s\n", RMEMLIM, strerror(-err));
    goto cleanup;
  }

  // Get index of interface
  ifindex = if_nametoindex(argv[1]);
  if (ifindex == 0) {
    err = -errno;
    fprintf(stderr, "Could not get index of interface %s: %s\n", argv[1], strerror(-err));
    goto cleanup;
  }

  //Load tc-bpf section on egress
  char tc_bpf_load[MAX_COMMAND_LEN];
  snprintf(tc_bpf_load, MAX_COMMAND_LEN, "%s --dev %s --obj %s --sec %s",
	   TCBPF_LOADER_SCRIPT, argv[1], PPING_TCBPF_OBJ, TCBPF_PROG_SEC);
  err = system(tc_bpf_load);
  if (err) {
    fprintf(stderr, "Could not load section %s of %s on interface %s: %s\n",
	    TCBPF_PROG_SEC, PPING_TCBPF_OBJ, argv[1], strerror(err));
    goto cleanup;
  }
  
  // Load and attach XDP program to interface
  struct bpf_object *obj = NULL;
  int prog_fd = -1;

  err = xdp_load_and_attach(ifindex, PPING_XDP_OBJ, XDP_PROG_SEC, XDP_FLAGS, &obj, &prog_fd, error_msg);
  if (err) {
    fprintf(stderr, "%s: %s\n", error_msg, strerror(-err));
    goto cleanup;
  }
  xdp_attached = true;

  // Find map fd (to perform periodic cleanup)
  int map_fd = bpf_object__find_map_fd_by_name(obj, MAP_NAME);
  if (map_fd < 0) {
    fprintf(stderr, "Failed finding map %s in %s: %s\n", MAP_NAME, PPING_XDP_OBJ, strerror(-map_fd));
    goto cleanup;
  }
  pthread_t tid;
  struct map_cleanup_args args = {.map_fd = map_fd, .max_age_ns = TIMESTAMP_LIFETIME};
  err = pthread_create(&tid, NULL, periodic_map_cleanup, &args);
  if (err) {
    fprintf(stderr, "Failed starting thread to perform periodic map cleanup: %s\n", strerror(err));
    goto cleanup;
  }

  // Set up perf buffer
  struct perf_buffer_opts pb_opts;
  pb_opts.sample_cb = handle_rtt_event;
  pb_opts.lost_cb = handle_missed_rtt_event;
  
  pb = perf_buffer__new(bpf_object__find_map_fd_by_name(obj, PERF_BUFFER_NAME), PERF_BUFFER_PAGES, &pb_opts);
  err = libbpf_get_error(pb);
  if (err) {
    pb = NULL;
    fprintf(stderr, "Failed to open perf buffer %s: %s\n", PERF_BUFFER_NAME, strerror(err));
    goto cleanup;
  }

  // Main loop
  signal(SIGINT, abort_program);
  while(keep_running) {
    if ((err = perf_buffer__poll(pb, PERF_POLL_TIMEOUT_MS)) < 0) {
      if (keep_running) // Only print polling error if it wasn't caused by program termination
	fprintf(stderr, "Error polling perf buffer: %s\n", strerror(-err));
      break;
    }
  }
    
 cleanup:
  perf_buffer__free(pb);
  if (xdp_attached) {
    err = xdp_deatach(ifindex, XDP_FLAGS);
    if (err) {
      fprintf(stderr, "Failed deatching program from ifindex %d: %s\n", ifindex, strerror(-err));
    }
  }
  // TODO: Unload TC-BPF program
  
  return err != 0;
}

