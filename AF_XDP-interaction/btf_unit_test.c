/* Code exercising BTF userspace decoding */

#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>

#include <errno.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include <bpf/btf.h> /* provided by libbpf */

#include "lib_xsk_extend.h"

/* Exit return codes - can be used by scripts looking at exit code */
#define EXIT_OK             0 /* == EXIT_SUCCESS (stdlib.h) man exit(3) */
#define EXIT_FAIL           1 /* == EXIT_FAILURE (stdlib.h) man exit(3) */
#define EXIT_FAIL_OPTION    2
#define EXIT_FAIL_XDP       3
#define EXIT_FAIL_BPF       4
#define EXIT_FAIL_BTF       5

struct bpf_object *load_bpf_object() {
	struct bpf_object *obj;
	char buf[100];
	int err;

	obj = bpf_object__open_file("af_xdp_kern.o", NULL);
	err = libbpf_get_error(obj);
	if (err) {
		libbpf_strerror(err, buf, sizeof(buf));
		printf("Error opening file: %s\n", buf);
		return NULL;
	}
	return obj;
}

int main(int argc, char **argv)
{
	struct bpf_object *bpf_obj;
	// int err = 0;

	bpf_obj = load_bpf_object();
	if (!bpf_obj)
		return EXIT_FAIL_BPF;

	return EXIT_OK;
}


