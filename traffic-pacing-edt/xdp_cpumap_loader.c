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
	{"non-cpu",	required_argument,	NULL, 'x' },
	{"exclude-cpu",	required_argument,	NULL, 'x' },
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

struct cpumap_config {
	int fd_cpumap;
	int fd_cpus_enabled;
	int fd_cpus_count;
	int *cpu_exclude;
	int max_cpus;
	__u32 qsize;
};

static int cpumap_config_init(struct cpumap_config *cfg)
{
        int n_cpus = get_nprocs_conf();
	int *cpu_exclude;

	memset(cfg, 0, sizeof(*cfg));

	cpu_exclude = malloc(n_cpus * sizeof(int));
	if (!cpu_exclude) {
		fprintf(stderr, "failed to allocate array\n");
		return EXIT_FAIL_MEM;
	}
	memset(cpu_exclude, 0, n_cpus * sizeof(int));

	cfg->cpu_exclude = cpu_exclude;
	cfg->max_cpus = n_cpus;
	return 0;
}

int __find_map_fd_by_name(struct bpf_object *obj, char *name)
{
	int fd;

	fd = bpf_object__find_map_fd_by_name(obj, name);
	if (fd < 0) {
		printf("No map found! - named: %s\n", name);
		exit(EXIT_FAIL_BPF);
	}
	return fd;
}

/* Get file descriptors to BPF-maps */
static int cpumap_config_find_maps(struct bpf_object *obj,
				   struct cpumap_config *cfg)
{
	cfg->fd_cpumap       = __find_map_fd_by_name(obj, "cpumap");
	cfg->fd_cpus_enabled = __find_map_fd_by_name(obj, "cpus_enabled");
	cfg->fd_cpus_count   = __find_map_fd_by_name(obj, "cpus_count");
	return 0;
}

static int create_cpu_entry(struct cpumap_config *cfg, __u32 cpu,
			    struct bpf_cpumap_val *value,
			    __u32 enabled_idx, bool new)
{
	__u32 curr_cpus_count = 0;
	__u32 key = 0;
	int err, fd;

	/* Add a CPU entry to cpumap, as this allocate a cpu entry in
	 * the kernel for the cpu.
	 */
	fd = cfg->fd_cpumap;
	err = bpf_map_update_elem(fd, &cpu, value, 0);
	if (err) {
		fprintf(stderr, "Create(fd:%d) CPU(%d) entry failed (err:%d)\n",
			fd, cpu, err);
		return EXIT_FAIL_BPF;
	}

	/* Inform bpf_prog's that a new CPU is enabled and available
	 * to be select from the map, that maps index to actual CPU.
	 */
	fd = cfg->fd_cpus_enabled;
	err = bpf_map_update_elem(fd, &enabled_idx, &cpu, 0);
	if (err) {
		fprintf(stderr, "Add to enabled avail CPUs failed\n");
		return EXIT_FAIL_BPF;
	}

	/* When not replacing/updating existing entry, bump the count */
	fd = cfg->fd_cpus_count;
	err = bpf_map_lookup_elem(fd, &key, &curr_cpus_count);
	if (err) {
		fprintf(stderr, "Failed reading curr cpus_count\n");
		return EXIT_FAIL_BPF;
	}
	if (new) {
		curr_cpus_count++;
		err = bpf_map_update_elem(fd, &key, &curr_cpus_count, 0);
		if (err) {
			fprintf(stderr, "Failed write curr cpus_count\n");
			return EXIT_FAIL_BPF;
		}
	}

	return 0;
}

/* Userspace MUST create/populate CPUMAP entries for redirect to work
 */
static int configure_cpus(struct cpumap_config *cfg)
{
	struct bpf_cpumap_val value = { 0 };
        int n_cpus = cfg->max_cpus;
	int *exclude = cfg->cpu_exclude;
	int enabled_idx = 0;
	bool new = true;
	int cpu, err;

	value.qsize = cfg->qsize;

	for (cpu = 0; cpu < n_cpus; cpu++) {

		if (exclude[cpu] == -1) {
			printf("Excluding CPU:%d\n", cpu);
			continue;
		}
		printf("Enable CPU:%d\n", cpu);
		err = create_cpu_entry(cfg, cpu, &value, enabled_idx, new);
		if (err)
			return err;
		enabled_idx++;
	}
	return 0;
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

	err = bpf_xdp_attach(ifindex, prog_fd, xdp_flags, NULL);
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

	err = bpf_xdp_detach(ifindex, xdp_flags, NULL);
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
	char buf[100];
	int err;

	struct bpf_object *obj = NULL;
	struct bpf_program *prog;

	/* System to setup and exclude some CPUs */
	struct cpumap_config cfg;
	int n_cpus = get_nprocs_conf();
	int non_cpu = -1;
	int *cpu_exclude;

	cpumap_config_init(&cfg);
	cpu_exclude = cfg.cpu_exclude;
	cfg.qsize = 512; /* Default queue size */

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
	while ((opt = getopt_long(argc, argv, "hd:q:Frx:",
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
			cfg.qsize = strtol(optarg, NULL, 10);
			break;
		case 'F':
			xdp_flags &= ~XDP_FLAGS_UPDATE_IF_NOEXIST;
			break;
		case 'r':
			do_detach = true;
			break;
		case 'x': /* --exclude-cpu or --non-cpu */
			/* Possible to exclude multiple CPUs on cmdline */
			non_cpu = strtoul(optarg, NULL, 0);
			if (non_cpu >= n_cpus) {
				fprintf(stderr,
				"--cpu nr too large for cpumap err(%d):%s\n",
					errno, strerror(errno));
				goto error;
			}
			cpu_exclude[non_cpu] = -1;
			break;

		case 'h':
		error:
		default:
			usage(argv);
			free(cpu_exclude);
			return EXIT_FAIL_OPTION;
		}
	}
	/* Required option */
	if (ifindex == -1) {
		fprintf(stderr, "ERR: required option --dev missing\n");
		usage(argv);
		err = EXIT_FAIL_OPTION;
		goto out;
	}

	if (do_detach)
		return do_xdp_detach(ifindex, xdp_flags);

	if (setrlimit(RLIMIT_MEMLOCK, &r)) {
		perror("setrlimit(RLIMIT_MEMLOCK)");
		err = EXIT_FAIL_MEM;
		goto out;
	}

	obj = do_load_bpf_obj(obj);
	if (!obj) {
		err = EXIT_FAIL_BPF;
		goto out;
	}

	/* Pickup first BPF-program */
	prog = bpf_object__next_program(obj, NULL);
	if (!prog) {
		printf("No program!\n");
		err = EXIT_FAIL_BPF;
		goto out;
	}

	/* Find maps maps */
	if (cpumap_config_find_maps(obj, &cfg)) {
		err = EXIT_FAIL_BPF;
		goto out;
	}

	/* Configure cpumap */
	if (configure_cpus(&cfg)) {
		err = EXIT_FAIL_BPF;
		goto out;
	}

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

	free(cpu_exclude);
	return err;
}
