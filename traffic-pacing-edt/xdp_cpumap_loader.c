// SPDX-License-Identifier: GPL-2.0+
static const char *__doc__ =
	" XDP load-balancing with CPU-map";

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <locale.h>
#include <sys/resource.h>
#include <sys/sysinfo.h>
#include <getopt.h>
#include <net/if.h>
#include <time.h>
#include <linux/limits.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include <linux/if_link.h> /* XDP defines */

static int ifindex = -1;
static char ifname_buf[IF_NAMESIZE];
static char *ifname;

static __u32 xdp_flags = XDP_FLAGS_UPDATE_IF_NOEXIST;

/* Exit return codes */
#define EXIT_OK 		0
#define EXIT_FAIL		1
#define EXIT_FAIL_OPTION	2
#define EXIT_FAIL_XDP		3
#define EXIT_FAIL_BPF		4
#define EXIT_FAIL_MEM		5
#define EXIT_FAIL_FILE		6

static const struct option long_options[] = {
	{"help",	no_argument,		NULL, 'h' },
	{"dev",		required_argument,	NULL, 'd' },
	{"qsize",	required_argument,	NULL, 'q' },
	{"force",	no_argument,		NULL, 'F' },
	{"remove",	no_argument,		NULL, 'r' },
	{0, 0, NULL,  0 }
};

static void usage(char *argv[])
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

static int create_cpu_entry(int cpumap_fd, __u32 cpu,
			    struct bpf_cpumap_val *value)
{
	int err;

	/* Add a CPU entry to cpumap, as this allocate a cpu entry in
	 * the kernel for the cpu.
	 */
	err = bpf_map_update_elem(cpumap_fd, &cpu, value, 0);
	if (err) {
		fprintf(stderr, "Create CPU entry failed (err:%d)\n", err);
		exit(EXIT_FAIL_BPF);
	}

	return 0;
}

/* Userspace MUST create/populate CPUMAP entries for redirect to work
 */
static void enable_all_cpus(int cpumap_fd, __u32 qsize)
{
	struct bpf_cpumap_val value = { 0 };
        int n_cpus = get_nprocs_conf();
	int i;

	value.qsize = qsize;

	for (i = 0; i < n_cpus; i++) {
		printf("Enable CPU:%d\n", i);
		create_cpu_entry(cpumap_fd, i, &value);
	}
}

struct bpf_object *do_load_bpf_obj(struct bpf_object *obj)
{
	char buf[200];
	int err;

	err = bpf_object__load(obj);
	if (err) {
		libbpf_strerror(err, buf, sizeof(buf));
		printf("Error loading: %s\n", buf);
		return NULL;
	}
	return obj;
}

int do_xdp_attach(int ifindex, struct bpf_program *prog, __u32 xdp_flags)
{
	int prog_fd = bpf_program__fd(prog);
	int err;

	if (prog_fd < 0) {
		fprintf(stderr, "bpf_program__fd failed\n");
		return EXIT_FAIL_BPF;
	}

	err = bpf_set_link_xdp_fd(ifindex, prog_fd, xdp_flags);
	if (err) {
		fprintf(stderr, "%s(): link set xdp fd failed (err:%d)\n",
			__func__, err);
		return EXIT_FAIL_XDP;
	}
	return EXIT_OK;
}

int do_xdp_detach(int ifindex, __u32 xdp_flags)
{
	int err;

	err = bpf_set_link_xdp_fd(ifindex, -1, xdp_flags);
	if (err) {
		fprintf(stderr, "%s(): link set xdp fd failed (err:%d)\n",
			__func__, err);
		return EXIT_FAIL_XDP;
	}
	return EXIT_OK;
}

int main(int argc, char **argv)
{
	struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};
	bool do_detach = false;
	int opt, longindex = 0;
	__u32 cfg_qsize = 512;
	char buf[100];
	int err;

	struct bpf_object *obj = NULL;
	struct bpf_program *prog;
	int cpumap_fd = -1;

	int n_cpus = get_nprocs_conf();

	/* Always use XDP native driver mode */
	xdp_flags |= XDP_FLAGS_DRV_MODE;

        obj = bpf_object__open_file("xdp_cpumap_qinq.o", NULL);
	err = libbpf_get_error(obj);
	if (err) {
		libbpf_strerror(err, buf, sizeof(buf));
		printf("Error opening file: %s\n", buf);
		return EXIT_FAIL_FILE;
	}
	err = EXIT_OK;

	/* Parse commands line args */
	while ((opt = getopt_long(argc, argv, "hSd:s:p:q:c:xzFf:e:r:m:",
				  long_options, &longindex)) != -1) {
		switch (opt) {
		case 'd':
			if (strlen(optarg) >= IF_NAMESIZE) {
				fprintf(stderr, "ERR: --dev name too long\n");
				goto error;
			}
			ifname = (char *)&ifname_buf;
			strncpy(ifname, optarg, IF_NAMESIZE);
			ifindex = if_nametoindex(ifname);
			if (ifindex == 0) {
				fprintf(stderr,
					"ERR: --dev name unknown err(%d):%s\n",
					errno, strerror(errno));
				goto error;
			}
			break;
		case 'q':
			cfg_qsize = strtol(optarg, NULL, 10);
			break;
		case 'F':
			xdp_flags &= ~XDP_FLAGS_UPDATE_IF_NOEXIST;
			break;
		case 'r':
			do_detach = true;
			break;
		case 'h':
		error:
		default:
			usage(argv);
			return EXIT_FAIL_OPTION;
		}
	}
	/* Required option */
	if (ifindex == -1) {
		fprintf(stderr, "ERR: required option --dev missing\n");
		usage(argv);
		return EXIT_FAIL_OPTION;
	}

	if (do_detach)
		return do_xdp_detach(ifindex, xdp_flags);

	if (setrlimit(RLIMIT_MEMLOCK, &r)) {
		perror("setrlimit(RLIMIT_MEMLOCK)");
		return EXIT_FAIL_MEM;
	}


	obj = do_load_bpf_obj(obj);
	if (!obj)
		return EXIT_FAIL_BPF;

	/* Pickup first BPF-program */
	prog = bpf_program__next(NULL, obj);
	if (!prog) {
		printf("No program!\n");
		err = EXIT_FAIL_BPF;
		goto out;
	}

	/* Get file descriptor to BPF-map */
	cpumap_fd = bpf_object__find_map_fd_by_name(obj, "cpumap");
	if (cpumap_fd < 0) {
		printf("No cpumap found!\n");
		err = EXIT_FAIL_BPF;
		goto out;
	}
	/* Configure cpumap */
	enable_all_cpus(cpumap_fd, cfg_qsize);

	/* Attach XDP program */
	err = do_xdp_attach(ifindex, prog, xdp_flags);
	if (err)
		goto out;

	printf("Attached XDP program:\"%s\" on netdev:%s (ifindex:%d)\n",
	       bpf_program__name(prog), ifname, ifindex);
	printf("CPUs: %d\n", n_cpus);

out:
	if (obj)
		bpf_object__close(obj);

	return err;
}
