//#include <linux/bpf.h>
#include <linux/if_link.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <net/if.h>
#include <linux/err.h> // For IS_ERR_OR_NULL macro
#include <arpa/inet.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <stdbool.h>
#include <signal.h> // For detecting Ctrl-C
#include <sys/resource.h> // For setting rlmit
#include <time.h>
#include "timestamp_map.h" //key and value structs for the ts_start map

#define PPING_ELF_OBJ "pping_kern.o"
#define XDP_PROG_SEC "pping_ingress"
#define XDP_FLAGS XDP_FLAGS_UPDATE_IF_NOEXIST
#define MAP_NAME "ts_start"
#define RMEMLIM 512UL << 20 /* 512 MBs */
#define ERROR_MSG_MAX 1024
#define BILLION 1000000000UL
#define TIMESTAMP_LIFETIME 10*BILLION // 10 seconds

/* static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args) */
/* { */
/* 	return vfprintf(stderr, format, args); */
/* } */

static volatile int keep_running = 1;

void abort_main_loop(int sig)
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
  //attr.file = obj_path;

  err = bpf_prog_load_xattr(&attr, obj, prog_fd);
  if (err) {
    if (error_buf) { snprintf(error_buf, ERROR_MSG_MAX, "Could not open %s", obj_path); }
    return err;
  }

  prog = bpf_object__find_program_by_title(*obj, sec);
  if (!prog) {
    if (error_buf) { snprintf(error_buf, ERROR_MSG_MAX, "Could not find section %s in ELF object %s", sec, obj_path); }
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
  printf("Gone through %d entries and removed %d of them\n", entries, removed);
  return removed;
}

int main(int argc, char *argv[])
{
  if (argc < 2) {
    printf("Usage: ./pping_user <dev>\n");
    return EXIT_FAILURE;
  }

  int err;
  char error_msg[ERROR_MSG_MAX];

  // Setup libbpf errors and debug info on callback
  //libbpf_set_print(libbpf_print_fn);

  // Increase rlimit
  err = set_rlimit(RMEMLIM);
  if (err) {
    fprintf(stderr, "Could not set rlimit to %ld bytes: %s\n", RMEMLIM, strerror(-err));
    return EXIT_FAILURE;
  }

  // Get index of interface
  int ifindex = if_nametoindex(argv[1]);
  if (ifindex == 0) {
    err = -errno;
    fprintf(stderr, "Could not get index of interface %s: %s\n", argv[1], strerror(-err));
    return EXIT_FAILURE;
  }
  
  // Load and attach XDP program to interface
  struct bpf_object *obj = NULL;
  int prog_fd = -1;

  err = xdp_load_and_attach(ifindex, PPING_ELF_OBJ, XDP_PROG_SEC, XDP_FLAGS, &obj, &prog_fd, error_msg);
  if (err) {
    fprintf(stderr, "%s: %s\n", error_msg, strerror(-err));
    return EXIT_FAILURE;
  }
  int map_fd = bpf_object__find_map_fd_by_name(obj, MAP_NAME);
  if (map_fd < 0) {
    fprintf(stderr, "Failed finding map %s in %s: %s\n", MAP_NAME, PPING_ELF_OBJ, strerror(-map_fd));
    xdp_deatach(ifindex, XDP_FLAGS);
    return EXIT_FAILURE;
  }

  // Main loop
  signal(SIGINT, abort_main_loop);
  while(keep_running) {
    sleep(1);
    // TODO - print out 
    remove_old_entries_from_map(map_fd, TIMESTAMP_LIFETIME);
  }

  err = xdp_deatach(ifindex, XDP_FLAGS);
  if (err) {
    fprintf(stderr, "Failed deatching program from ifindex %d: %s\n", ifindex, strerror(-err));
    return EXIT_FAILURE;
  }
  
  return EXIT_SUCCESS;
}

