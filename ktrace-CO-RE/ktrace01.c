// SPDX-License-Identifier: GPL-2.0+
// static const char *__doc__ = " Trivial ktrace example";

#include <bpf/libbpf.h>
#include <stdlib.h>
#include <errno.h>

#include <stdio.h>

#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <getopt.h>

#define pr_err(fmt, ...) \
	fprintf(stderr, "%s:%d - " fmt, __FILE__, __LINE__, ##__VA_ARGS__)

#define DEBUGFS "/sys/kernel/debug/tracing/"

void read_trace_pipe(void)
{
	int trace_fd;

	trace_fd = open(DEBUGFS "trace_pipe", O_RDONLY, 0);
	if (trace_fd < 0)
		return;

	while (1) {
		static char buf[4096];
		ssize_t sz;

		sz = read(trace_fd, buf, sizeof(buf) - 1);
		if (sz > 0) {
			buf[sz] = 0;
			puts(buf);
		}
	}
}

int print_all_levels(enum libbpf_print_level level,
		     const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

static const struct option long_options[] = {
	{ "debug",	no_argument,	NULL,	'd' },
	{ 0, 0, NULL, 0 }
};

int main(int argc, char **argv)
{
	struct bpf_object *obj = NULL;
	struct bpf_link *link = NULL;
	struct bpf_program *prog;
	int opt, longindex = 0;
	char filename[256];
	char buf[100];
	int err;

	snprintf(filename, sizeof(filename), "%s_kern.o", argv[0]);

	/* Parse commands line args */
	while ((opt = getopt_long(argc, argv, "d",
				  long_options, &longindex)) != -1) {
		switch (opt) {
		case 'd':
			libbpf_set_print(print_all_levels);
			// verifier_logs = true;
			break;
		default:
			pr_err("Unrecognized option '%s'\n", argv[optind - 1]);
			return EXIT_FAILURE;
		}
	}
	argc -= optind;
	argv += optind;

	obj = bpf_object__open_file(filename, NULL);
	err = libbpf_get_error(obj);
	if (err) {
		libbpf_strerror(err, buf, sizeof(buf));
		pr_err("Error(%d) opening file: %s\n", err, buf);
		goto out;
	}

	err = bpf_object__load(obj);
	if (err) {
		libbpf_strerror(err, buf, sizeof(buf));
		pr_err("Error(%d) loading: %s\n", err, buf);
		goto out;
	}

	prog = bpf_object__next_program(obj, NULL);
	if (!prog) {
		pr_err("No program!\n");
		err = -ENOENT;
		goto out;
	}
	printf("Loaded BPF file %s\n", filename);

	link = bpf_program__attach(prog);
	err = libbpf_get_error(link);
	if (err) {
		libbpf_strerror(err, buf, sizeof(buf));
		pr_err("Error(%d) attaching: %s\n", err, buf);
		goto out;
	}

	printf("Attached and reading trace_pipe\n");
	printf(" - Press Ctrl-C to unload program again\n");
	read_trace_pipe();

out:
	bpf_link__destroy(link);
	bpf_object__close(obj);
	if (err)
		return EXIT_FAILURE;
	return EXIT_SUCCESS;
}
