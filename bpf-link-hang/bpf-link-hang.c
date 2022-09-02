#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
#include <time.h>
#include <net/if.h>
#include <linux/if_link.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

static inline int64_t timespec_ns(struct timespec* a)
{
    return ((int64_t) a->tv_sec * 1000000000) + a->tv_nsec;
}

int main()
{
        struct bpf_object *obj_target, *obj_prog;
        struct bpf_program *target, *prog;
        struct timespec start_time, end_time;
	int err = EXIT_FAILURE, lfd;

	obj_target = bpf_object__open_file("xdp-pass.o", NULL);
	obj_prog = bpf_object__open_file("xdp-pass.o", NULL);
        if (libbpf_get_error(obj_target) || libbpf_get_error(obj_prog))
                goto out;

        if (bpf_object__load(obj_target))
            goto out;

        target = bpf_object__find_program_by_name(obj_target, "xdp_pass");
        prog = bpf_object__find_program_by_name(obj_prog, "xdp_pass");

        if (!target || !prog)
                goto out;

	bpf_program__set_type(prog, BPF_PROG_TYPE_EXT);
	bpf_program__set_expected_attach_type(prog, 0);

        if (bpf_program__set_attach_target(prog, bpf_program__fd(target), "xdp_pass"))
                goto out;

        if (bpf_object__load(obj_prog))
                goto out;

        lfd = bpf_raw_tracepoint_open(NULL, bpf_program__fd(prog));
        if (lfd < 0)
                goto out;

        printf("\nClosing link fd (%d) - this should hang if the system is loaded...\n", lfd);
        clock_gettime(CLOCK_REALTIME, &start_time);
        close(lfd);
        clock_gettime(CLOCK_REALTIME, &end_time);

        printf("Link fd closed in %lu ms!\n", (timespec_ns(&end_time) - timespec_ns(&start_time)) / 1000000);
        err = 0;
out:
        if (obj_target && !libbpf_get_error(obj_target))
                bpf_object__close(obj_target);
        if (obj_prog && !libbpf_get_error(obj_prog))
                bpf_object__close(obj_prog);
        printf(err ? "An error occurred!\n" : "Exited successfully\n");
        return err;
}
