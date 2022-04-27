/* Code exercising BTF userspace decoding */

#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>

#include <errno.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include <bpf/btf.h> /* provided by libbpf */

#include "lib_xsk_extend.h"

static int verbose = 1;

/* Exit return codes - can be used by scripts looking at exit code */
#define EXIT_OK             0 /* == EXIT_SUCCESS (stdlib.h) man exit(3) */
#define EXIT_FAIL           1 /* == EXIT_FAILURE (stdlib.h) man exit(3) */
#define EXIT_FAIL_OPTION    2
#define EXIT_FAIL_XDP       3
#define EXIT_FAIL_BPF       4
#define EXIT_FAIL_BTF       5

struct bpf_object *load_bpf_object(const char *filename) {
	struct bpf_object *obj;
	char buf[100];
	int err;

	obj = bpf_object__open_file(filename, NULL);
	err = libbpf_get_error(obj);
	if (err) {
		libbpf_strerror(err, buf, sizeof(buf));
		printf("Error opening file: %s\n", buf);
		return NULL;
	}
	return obj;
}

/**
 * BTF setup XDP-hints
 * -------------------
 * Setup the data structures for accessing the XDP-hints provided by
 * kernel side BPF-prog via decoding BTF-info provided in BPF
 * ELF-object file.
 */

/* This struct BTF mirrors kernel-side struct xdp_hints_rx_time */
struct xdp_hints_rx_time {
	__u32 btf_type_id; /* cached xsk_btf__btf_type_id(xbi) */
	struct xsk_btf_info *xbi;
	struct xsk_btf_member rx_ktime;
	struct xsk_btf_member xdp_rx_cpu;
} xdp_hints_rx_time = { 0 };

/* This struct BTF mirrors kernel-side struct xdp_hints_mark */
struct xdp_hints_mark {
	__u32 btf_type_id; /* cached xsk_btf__btf_type_id(xbi) */
	struct xsk_btf_info *xbi;
	struct xsk_btf_member mark;
} xdp_hints_mark = { 0 };

struct xsk_btf_info *setup_btf_info(struct btf *btf,
				    const char *struct_name,
				    int *errval)
{
	struct xsk_btf_info *xbi = NULL;
	int err;

	err = xsk_btf__init_xdp_hint(btf, struct_name, &xbi);
	if (err) {
		if (errval) {
			/* Expect caller to handle err detection */
			*errval = err;
		} else {
			fprintf(stderr,
				"WARN(%d): Cannot BTF locate valid struct:%s\n",
				err, struct_name);
		}
		return NULL;
	}

	if (verbose) {
		int btf_id = xsk_btf__btf_type_id(xbi);
		printf("Setup BTF based XDP hints for (btf_id:%d) struct: %s\n",
		       btf_id, struct_name);
	}

	return xbi;
}

int init_btf_info_via_bpf_object(struct bpf_object *bpf_obj)
{
	struct btf *btf = bpf_object__btf(bpf_obj);
	struct xsk_btf_info *xbi;

	xbi = setup_btf_info(btf, "xdp_hints_rx_time", NULL);
	if (xbi) {
		/* Lookup info on required member "rx_ktime" */
		if (!xsk_btf__field_member("rx_ktime", xbi,
					   &xdp_hints_rx_time.rx_ktime))
			return -EBADSLT;
		if (!xsk_btf__field_member("xdp_rx_cpu", xbi,
					   &xdp_hints_rx_time.xdp_rx_cpu))
			return -EBADSLT;
		xdp_hints_rx_time.btf_type_id = xsk_btf__btf_type_id(xbi);
		xdp_hints_rx_time.xbi = xbi;
	}
	/* Remember to cleanup later: xsk_btf__free_xdp_hint(xbi); */

	xbi = setup_btf_info(btf, "xdp_hints_mark", NULL);
	if (xbi) {
		if (!xsk_btf__field_member("mark", xbi, &xdp_hints_mark.mark))
			return -EBADSLT;
		xdp_hints_mark.btf_type_id = xsk_btf__btf_type_id(xbi);
		xdp_hints_mark.xbi = xbi;
	}

	return 0;
}

int test01_normal()
{
	struct bpf_object *bpf_obj;
	int err = 0;

	bpf_obj = load_bpf_object("af_xdp_kern.o");
	if (!bpf_obj)
		return EXIT_FAIL_BPF;

	err = init_btf_info_via_bpf_object(bpf_obj);
	if (err) {
		if (verbose)
			printf("ERR(%d): Failed loading BTF info", err);
		bpf_object__close(bpf_obj);
		return EXIT_FAIL_BTF;
	}
	/* Teardown structs and memory again */
	xsk_btf__free_xdp_hint(xdp_hints_rx_time.xbi);
	xsk_btf__free_xdp_hint(xdp_hints_mark.xbi);
	bpf_object__close(bpf_obj);

	return EXIT_OK;
}

int helper_expect_invalid_btf_id(struct btf *btf,
				 const char *xdp_hint_name)
{
	struct xsk_btf_info *xbi;
	int ret = EXIT_OK;
	int errval = 0;

	xbi = setup_btf_info(btf, xdp_hint_name, &errval);
	if (xbi) {
		/* Unexpected success - as hints layout should be invalid */
		printf(" - Unexpected success in test that should fail\n");
		xsk_btf__free_xdp_hint(xbi);
		ret = EXIT_FAIL_BPF;
		goto out;
	}
	if (errval != -EOVERFLOW) {
		/* Expecting failure with EOVERFLOW as btf_id not last member */
		printf("Unexpect FAIL - with errno:%d\n", errval);
		ret = EXIT_FAIL_BTF;
		goto out;
	}
	if (verbose) {
		printf("SUCCESS - "
		       "detect btf_id not last member in struct %s\n",
		       xdp_hint_name);
	}

out:
	return ret;
}

int test02_should_fail()
{
	const char *xdp_hint01 = "xdp_hints_fail001";
	const char *xdp_hint02 = "xdp_hints_fail002";
	struct bpf_object *bpf_obj;
	int ret = EXIT_OK;
	struct btf *btf;

	bpf_obj = load_bpf_object("btf_unit_test_bpf.o");
	if (!bpf_obj)
		return EXIT_FAIL_BPF;

	btf = bpf_object__btf(bpf_obj);

	ret = helper_expect_invalid_btf_id(btf, xdp_hint01);
	if (ret)
		goto out;

	ret = helper_expect_invalid_btf_id(btf, xdp_hint02);
	if (ret)
		goto out;

out:
	bpf_object__close(bpf_obj);
	return ret;
}

int main(int argc, char **argv)
{
	int err;

	err = test01_normal();
	if (err)
		return err;

	err = test02_should_fail();
	if (err)
		return err;

	return EXIT_OK;
}
