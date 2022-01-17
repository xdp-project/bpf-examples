#include <bpf/libbpf.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>

int main(int argc, char **argv)
{
	struct bpf_object *obj = NULL;
	struct bpf_link *link = NULL;
	struct bpf_program *prog;
	int err = 0, fd;
	char buf[100];
	ssize_t len;
	char *c;

	fd = open("/sys/kernel/security/lsm", O_RDONLY);
        if (fd < 0) {
		err = -errno;
		printf("Error opening /sys/kernel/security/lsm ('%s') - securityfs "
		       "not mounted?\n",
		       strerror(-err));
		goto out;
        }

	len = read(fd, buf, sizeof(buf));
	if (len == -1) {
		err = -errno;
		printf("Error reading /sys/kernel/security/lsm: %s\n",
		       strerror(-err));
		close(fd);
		goto out;
	}
	close(fd);
	buf[sizeof(buf)-1] = '\0';
	c = strstr(buf, "bpf");
	if (!c) {
		printf("BPF LSM not loaded - make sure CONFIG_LSM or lsm kernel "
		       "param includes 'bpf'!\n");
		err = -EINVAL;
		goto out;
	}

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

	prog = bpf_object__next_program(obj, NULL);
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
