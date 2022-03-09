// SPDX-License-Identifier: GPL-2.0+

#include <bpf/libbpf.h>
#include <stdlib.h>
#include <errno.h>

#include <stdio.h>

#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <getopt.h>

#include <bpf/btf.h> /* Notice libbpf BTF include */

#include <linux/err.h>

static const char *module_name = "tun";
static const char *symbol_name = "tun_struct";

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


int main(int argc, char **argv)
{
	struct btf *vmlinux_btf, *module_btf = NULL;
	int opt, longindex = 0;
	__s32 type_id;
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

	vmlinux_btf = btf__load_vmlinux_btf();
	err = libbpf_get_error(vmlinux_btf);
	if (err) {
		pr_err("ERROR(%d): btf__load_vmlinux_btf()\n", err);
		goto out;
	}

	module_btf = btf__load_module_btf(module_name, vmlinux_btf);
	err = libbpf_get_error(module_btf);
	if (err) {
		pr_err("ERROR(%d): btf__load_module_btf() module_name: %s\n",
		       err, module_name);
		goto out;
	}

	type_id = btf__find_by_name(module_btf, symbol_name);
	if (type_id < 0) {
		err = type_id;
		pr_err("ERROR(%d): btf__find_by_name() symbol_name: %s\n",
		       err, symbol_name);
		goto out;
	}

	printf("Module:%s Symbol:%s have BTF id:%d\n",
	       module_name, symbol_name, type_id);

out:
	btf__free(module_btf);
	btf__free(vmlinux_btf);
	if (err)
		return EXIT_FAILURE;
	return EXIT_SUCCESS;
}
