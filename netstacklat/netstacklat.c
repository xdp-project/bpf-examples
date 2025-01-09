/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <sys/signalfd.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "netstacklat.h"
#include "netstacklat.bpf.skel.h"

static int init_signalfd(void)
{
	sigset_t mask;
	int fd, err;

	sigemptyset(&mask);
	sigaddset(&mask, SIGINT);
	sigaddset(&mask, SIGTERM);

	fd = signalfd(-1, &mask, 0);
	if (fd < 0)
		return -errno;

	err = pthread_sigmask(SIG_BLOCK, &mask, NULL);
	if (err) {
		err = -errno;
		close(fd);
		return err;
	}

	return fd;
}

int main(int argc, char *argv[])
{
	struct signalfd_siginfo sig_info;
	struct netstacklat_bpf *obj;
	ssize_t read_bytes;
	int sig_fd, err = 0;
	char errmsg[128];

	obj = netstacklat_bpf__open_and_load();
	if (!obj) {
		err = libbpf_get_error(obj);
		libbpf_strerror(err, errmsg, sizeof(errmsg));
		fprintf(stderr, "Failed loading eBPF programs: %s\n", errmsg);
		return EXIT_FAILURE;
	}

	err = netstacklat_bpf__attach(obj);
	if (err) {
		libbpf_strerror(err, errmsg, sizeof(errmsg));
		fprintf(stderr, "Failed to attach eBPF programs: %s\n", errmsg);
		goto exit_destroy;
	}

	sig_fd = init_signalfd();
	if (sig_fd < 0) {
		err = sig_fd;
		fprintf(stderr, "Failed setting up signal handling: %s\n",
			strerror(-err));
		goto exit_detach;
	}

	printf("eBPF programs are now attached\n");
	printf("eBPF program will stay attached as long as this user space program is running\n");
	printf("Hit CTRL-C to quit\n");

	read_bytes = read(sig_fd, &sig_info, sizeof(sig_info));
	if (read_bytes != sizeof(sig_info)) {
		err = EINVAL;
		goto exit_sigfd;
	}

exit_sigfd:
	close(sig_fd);
exit_detach:
	netstacklat_bpf__detach(obj);
exit_destroy:
	netstacklat_bpf__destroy(obj);
	return err ? EXIT_FAILURE : EXIT_SUCCESS;
}
