// SPDX-License-Identifier: GPL-2.0+

#include <stdlib.h>
#include <errno.h>
#include <stdio.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <getopt.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <bpf/btf.h> /* Notice libbpf BTF include */

#include <linux/err.h>

static const struct option long_options[] = {
	{ "debug",	no_argument,	NULL,	'd' },
	{ 0, 0, NULL, 0 }
};

int print_all_levels(enum libbpf_print_level level,
		     const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

#define pr_err(fmt, ...) \
	fprintf(stderr, "%s:%d - " fmt, __FILE__, __LINE__, ##__VA_ARGS__)

int __btf_obj_id_via_fd(int fd)
{
	struct bpf_btf_info info;
	__u32 len = sizeof(info);
	int err;

	memset(&info, 0, sizeof(info));

	err = bpf_obj_get_info_by_fd(fd, &info, &len); /* Privileged op */
	if (err) {
		pr_err("ERR(%d): Can't get BTF object info on FD(%d): %s\n",
		       errno, fd, strerror(errno));
		return 0;
	}

	return info.id;
}

struct btf *open_vmlinux_btf(void)
{
	struct btf* btf_obj;
	int fd;

	//btf_obj = btf_load_vmlinux_from_kernel();
	btf_obj = btf__load_vmlinux_btf();

	fd = btf__fd(btf_obj);
	if (fd < 0)
		pr_err("WARN: BTF-obj miss FD(%d)\n", fd);

	return btf_obj;
}

int main(int argc, char **argv)
{
	struct btf *vmlinux_btf;
	int opt, longindex = 0;
        int err = 0;

	/* Parse commands line args */
	while ((opt = getopt_long(argc, argv, "d",
				  long_options, &longindex)) != -1) {
		switch (opt) {
		case 'd':
			libbpf_set_print(print_all_levels);
			break;
		default:
			pr_err("Unrecognized option '%s'\n", argv[optind - 1]);
			return EXIT_FAILURE;
		}
	}
	argc -= optind;
	argv += optind;

        vmlinux_btf = open_vmlinux_btf();

	if (err)
		return EXIT_FAILURE;
	return EXIT_SUCCESS;
}
