/* SPDX-License-Identifier: GPL-2.0-or-later */
static const char *__doc__ =
	"Test program making use of global function - simply print ping sequence number";

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <linux/if_link.h>
#include <net/if.h> // For if_nametoindex

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <getopt.h>
#include <stdbool.h>
#include <signal.h> // For detecting Ctrl-C
#include <sys/resource.h> // For setting rlmit
#include <xdp/libxdp.h>

#define VERIFIER_LOG_SIZE (1UL << 20)


// Store configuration values in struct to easily pass around
struct myconfig {
	char *object_path;
	char *prog_name;
	int ifindex;
	int loglevel;
	struct xdp_program *xdp_prog;
	char ifname[IF_NAMESIZE];
};

static volatile sig_atomic_t keep_running = 1;

static const struct option long_options[] = {
	{"help",      no_argument,       NULL, 'h'},
	{"interface", required_argument, NULL, 'i'}, // Name of interface to run on
	{"log-level", required_argument, NULL, 'l'},
	{0, 0, NULL, 0}};

static const char *get_libbpf_strerror(int err)
{
	static char buf[200];
	libbpf_strerror(err, buf, sizeof(buf));
	return buf;
}

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

static int parse_arguments(int argc, char *argv[], struct myconfig *conf)
{
	int err, opt;

	conf->ifindex = 0;

	while ((opt = getopt_long(argc, argv, "hi:l:", long_options, NULL)) !=
	       -1) {
		switch (opt) {
		case 'i':
			if (strlen(optarg) > IF_NAMESIZE) {
				fprintf(stderr, "interface name too long\n");
				return -EINVAL;
			}
			strncpy(conf->ifname, optarg, IF_NAMESIZE);

			conf->ifindex = if_nametoindex(conf->ifname);
			if (conf->ifindex == 0) {
				err = -errno;
				fprintf(stderr,
					"Could not get index of interface %s: %s\n",
					conf->ifname, get_libbpf_strerror(err));
				return err;
			}
			break;
		case 'l':
			conf->loglevel = atoi(optarg);
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

	if (conf->ifindex == 0) {
		fprintf(stderr,
			"An interface (-i or --interface) must be provided\n");
		return -EINVAL;
	}

	return 0;
}

static int set_rlimit(long int lim)
{
	struct rlimit rlim = {
		.rlim_cur = lim,
		.rlim_max = lim,
	};

	return !setrlimit(RLIMIT_MEMLOCK, &rlim) ? 0 : -errno;
}

/*
 * Attempt to attach program in section sec of obj to ifindex.
 * If sucessful, will return the positive program id of the attached.
 * On failure, will return a negative error code.
 */
static int xdp_attach(struct bpf_object *obj, const char *prog_name,
		      int ifindex, struct xdp_program **xdp_prog)
{
	struct xdp_program *prog;
	int err;
	DECLARE_LIBXDP_OPTS(xdp_program_opts, opts,
			    .prog_name = prog_name,
			    .obj = obj);

	prog = xdp_program__create(&opts);
	if (!prog)
		return -errno;

	err = xdp_program__attach(prog, ifindex, XDP_MODE_UNSPEC, 0);
	if (err) {
		xdp_program__close(prog);
		return err;
	}

	*xdp_prog = prog;
	return 0;
}

static int xdp_detach(struct xdp_program *prog, int ifindex)
{
	int err;

	err = xdp_program__detach(prog, ifindex, XDP_MODE_UNSPEC, 0);
	xdp_program__close(prog);
	return err;
}

void abort_program(int sig)
{
	keep_running = 0;
}

static int load_attach_bpfprog(struct bpf_object **obj, struct myconfig *conf,
			       char *log_buf, size_t log_buf_size)
{
	int err;
	struct bpf_program *prog;

	// Open ELF file
	*obj = bpf_object__open(conf->object_path);
	err = libbpf_get_error(*obj);
	if (err) {
		fprintf(stderr, "Failed opening object file %s: %s\n",
			conf->object_path, get_libbpf_strerror(err));
		return err;
	}

	bpf_object__for_each_program(prog, *obj) {
		if (prog) {
			bpf_program__set_log_level(prog, conf->loglevel);
			if (log_buf)
				bpf_program__set_log_buf(prog, log_buf,
							 log_buf_size);
		}
	}

	// Attach ingress prog
	err = xdp_attach(*obj, conf->prog_name, conf->ifindex, &conf->xdp_prog);
	if (err < 0) {
		fprintf(stderr,
			"Failed attaching BPF program on interface %s: %s\n",
			conf->ifname, get_libbpf_strerror(err));
		return err;
	}

	return 0;
}

int main(int argc, char *argv[])
{
	struct myconfig config = {
		.object_path = "glob_func_test_kern.o",
		.prog_name = "xdp_glob_func_test",
		.xdp_prog = NULL,
		.loglevel = 0,
	};
	struct bpf_object *obj = NULL;
	int err;

	// Detect if running as root
	if (geteuid() != 0) {
		fprintf(stderr, "This program must be run as root.\n");
		return EXIT_FAILURE;
	}

	if (set_rlimit(RLIM_INFINITY)) {
		fprintf(stderr, "Failed increasing rlimit\n");
		return EXIT_FAILURE;
	}

	char *log_buf = malloc(VERIFIER_LOG_SIZE);

	err = parse_arguments(argc, argv, &config);
	if (err) {
		fprintf(stderr, "Invalid arguments: %s\n",
			get_libbpf_strerror(err));
		goto out;
	}

	err = load_attach_bpfprog(&obj, &config, log_buf, VERIFIER_LOG_SIZE);
	if (err) {
		fprintf(stderr, "Failed loading BPF program: %s\n",
			get_libbpf_strerror(err));
		fprintf(stderr, "Verifier log:\n%s", log_buf);
		goto out;
	}

	if (config.loglevel > 0) {
		fprintf(stderr,
			"Verifier log:\n%s\n\nVerification successful!\n",
			log_buf);
	}

	signal(SIGINT, abort_program);
	signal(SIGTERM, abort_program);

	// Keep userspace component alive until Ctrl-C
	while (keep_running) {
		sleep(1);
	}

out:
	if (config.xdp_prog)
		xdp_detach(config.xdp_prog, config.ifindex);
	if (obj)
		bpf_object__close(obj);
	free(log_buf);
	return err;
}
