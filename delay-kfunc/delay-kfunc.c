/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <net/if.h>
#include <signal.h>
#include <sys/signalfd.h>
#include <sys/epoll.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "delay-kfunc.h"
#include "delay-kfunc.bpf.skel.h"

#define MAX_EVENTS 2
/* cap delay to 10 minutes to avoid breaking systems indefinitely */
#define MAX_DELAY 600000000

static int wait_for_interrupt(struct ring_buffer *rb)
{
	int sigfd, err, i, cnt, epoll_fd = ring_buffer__epoll_fd(rb);
	struct epoll_event events[MAX_EVENTS] = {};
	struct signalfd_siginfo fdsi;
	sigset_t mask;
	ssize_t s;

	sigemptyset(&mask);
	sigaddset(&mask, SIGINT);
	sigaddset(&mask, SIGTERM);

	err = sigprocmask(SIG_BLOCK, &mask, NULL);
	if (err)
		return -errno;

	sigfd = signalfd(-1, &mask, 0);
	if (sigfd < 0)
		return -errno;

	events[0].events = EPOLLIN;
	events[0].data.fd = sigfd;
	if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, sigfd, &events[0])) {
		err = -errno;
		goto out;
	}

	for (;;) {
		cnt = epoll_wait(epoll_fd, events, MAX_EVENTS, 0);
		if (cnt < 0) {
			err = -errno;
			goto out;
		}

		for (i = 0; i < cnt; i++) {
			if (events[i].data.fd == sigfd) {

				s = read(sigfd, &fdsi, sizeof(fdsi));
				if (s != sizeof(fdsi))
					err = -errno;
				else
					err = 0;
				goto out;

			} else if (ring_buffer__consume(rb) < 0) {
				err = -errno;
				goto out;
			}
		}
	}

out:
	close(sigfd);
	return err;
}

static int do_timing(struct bpf_program *prog)
{
	int prog_fd;
	__u64 ctx = 0;
	LIBBPF_OPTS(bpf_test_run_opts, tattr, .ctx_in = &ctx,
		    .ctx_size_in = sizeof(ctx), );

	prog_fd = bpf_program__fd(prog);
	return bpf_prog_test_run_opts(prog_fd, &tattr);
}

static int process_stats_entry(void *ctx, void *data, size_t len)
{
	struct delay_stats *s = data;
	char *fname = ctx;

	if (s->ret < 0)
		printf("Delay loop failed with error %d!\n", s->ret);
	else
		printf("Delayed %s() %llu us for PID %d(%s)\n",
		       fname,
		       s->delay_ns / 1000,
		       s->pid,
		       s->comm);
	return 0;
}

int main(int argc, char *argv[])
{
	unsigned long loop_outer, loop_inner;
	struct ring_buffer *rb = NULL;
	struct delay_kfunc_bpf *skel;
	long target_delay;
	char *func_name;
	int err = -1;

	if (argc < 3) {
		fprintf(stderr, "Usage: %s <kfunc> <usec>\n", argv[0]);
		return 1;
	}
	func_name = argv[1];
	target_delay = atol(argv[2]);

	if (target_delay > MAX_DELAY) {
		fprintf(stderr,
			"Target delay capped to %u seconds to avoid breaking the system!\n",
			MAX_DELAY / 1000000);
		return 1;
	}

	skel = delay_kfunc_bpf__open();
	if (!skel)
		goto out;

	loop_outer = skel->data->iterations_outer;
	loop_inner = skel->data->iterations_inner;

	err = bpf_program__set_attach_target(skel->progs.delay_function, 0,
					     func_name);
	if (err) {
		fprintf(stderr, "Could not attach to function '%s': %s\n",
			func_name, strerror(errno));
		goto out;
	}

	err = delay_kfunc_bpf__load(skel);
	if (err)
		goto out;

	printf("Loop calibration: ");
	fflush(stdout);
	err = do_timing(skel->progs.time_call);
	if (err)
		goto out;

	printf("average loop duration %llu ns / %lu iterations ",
	       skel->data->avg_delay,
	       loop_inner);

	loop_outer = 1 + target_delay * 1000 / skel->data->avg_delay;
	while (loop_outer > 1 << 23) {
		loop_inner *= 10;
		loop_outer /= 10;
	}
	printf("- looping %lu * %lu times to hit target\n", loop_outer, loop_inner);
	skel->data->iterations_outer = loop_outer;
	skel->data->iterations_inner = loop_inner;

	rb = ring_buffer__new(bpf_map__fd(skel->maps.delay_ringbuf),
			      process_stats_entry,
			      func_name, NULL);
	if (!rb) {
		err = -errno;
		goto out;
	}

	err = delay_kfunc_bpf__attach(skel);
	if (err)
		goto out;

	printf("Delay function attached to %s(). Press Ctrl-C to interrupt...\n",
		func_name);
	err = wait_for_interrupt(rb);

out:
	ring_buffer__free(rb);
	delay_kfunc_bpf__destroy(skel);
	return err;
}
