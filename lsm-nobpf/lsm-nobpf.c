#include <bpf/libbpf.h>
#include <unistd.h>
#include <errno.h>

int main(int argc, char **argv)
{
	struct bpf_link *link = NULL;
	struct bpf_program *prog;
	struct bpf_object *obj;
	char buf[100];
	int err = 0;

	obj = bpf_object__open_file("lsm-nobpf-kern.o", NULL);
	err = libbpf_get_error(obj);
	if (err) {
		libbpf_strerror(err, buf, sizeof(buf));
		printf("Error opening file: %s\n", buf);
		goto out;
	}

	err = bpf_object__load(obj);
	if (err) {
		libbpf_strerror(err, buf, sizeof(buf));
		printf("Error loading: %s\n", buf);
		goto out;
	}

	prog = bpf_program__next(NULL, obj);
	if (!prog) {
		printf("No program!\n");
		err = -ENOENT;
		goto out;
	}

	link = bpf_program__attach(prog);
	err = libbpf_get_error(link);
	if (err) {
		libbpf_strerror(err, buf, sizeof(buf));
		printf("Error attaching: %s\n", buf);
		goto out;
	}

	err = bpf_link__pin(link, "/sys/fs/bpf/lsm-nobpf");
	if (err) {
		libbpf_strerror(err, buf, sizeof(buf));
		printf("Error pinning: %s\n", buf);
		goto out;
	}

	printf("The bpf() syscall is now disabled - delete /sys/fs/bpf/lsm-nobpf to re-enable\n");

out:
	bpf_link__destroy(link);
	bpf_object__close(obj);
	if (err)
		return 1;
	return 0;
}
