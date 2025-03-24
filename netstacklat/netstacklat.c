/* SPDX-License-Identifier: GPL-2.0-or-later */
static const char *__doc__ =
	"Netstacklat - Monitor latency to various points in the ingress network stack";

#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <time.h>
#include <math.h>
#include <getopt.h>
#include <ctype.h>
#include <sys/signalfd.h>
#include <sys/timerfd.h>
#include <sys/epoll.h>
#include <sys/socket.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <linux/types.h>
#include <linux/net_tstamp.h>

#include "netstacklat.h"
#include "netstacklat.bpf.skel.h"

#define MAX_EPOLL_EVENTS 8

/*
 * Used to pack both a "type" and a value into the epoll_event.data.u64 member.
 * The topmost bits indicates the type (SIG, TIMER, etc) while the remaining
 * bits can be used for the value. The MASK can be used to filter out the
 * type/value.
 */
#define NETSTACKLAT_EPOLL_SIG (1ULL << 63)
#define NETSTACKLAT_EPOLL_TIMER (1ULL << 62)
#define NETSTACKLAT_EPOLL_TYPE_MASK \
	(NETSTACKLAT_EPOLL_SIG | NETSTACKLAT_EPOLL_TIMER)

// Magical value used to indicate that the program should be aborted
#define NETSTACKLAT_ABORT 424242

#define MAX_BUCKETSPAN_STRLEN 16
#define MAX_BUCKETCOUNT_STRLEN 10
#define MAX_BAR_STRLEN (80 - 6 - MAX_BUCKETSPAN_STRLEN - MAX_BUCKETCOUNT_STRLEN)

struct netstacklat_config {
	double report_interval_s;
};

static const struct option long_options[] = {
	{ "help",            no_argument,       NULL, 'h' },
	{ "report-interval", required_argument, NULL, 'r' },
	{ 0, 0, 0, 0 }
};

static const struct option *optval_to_longopt(int val)
{
	int i;

	for (i = 0; long_options[i].name != 0; i++) {
		if (long_options[i].val == val)
			return &long_options[i];
	}

	return NULL;
}

static int generate_optstr(char *buf, size_t size)
{
	char *end = buf + size - 1, *p = buf;
	int i, ret = -E2BIG;

	if (size <= 0)
		return -E2BIG;

	for (i = 0; long_options[i].name; i++) {
		if (long_options[i].flag || !isalnum(long_options[i].val))
			continue;

		if (p >= end)
			goto out;
		*p++ = (unsigned char)long_options[i].val;

		if (long_options[i].has_arg) {
			if (p >= end)
				goto out;
			*p++ = ':';
		}

		if (long_options[i].has_arg == optional_argument) {
			if (p >= end)
				goto out;
			*p++ = ':';
		}
	}

	ret = (p - buf) + 1;
out:
	*p = '\0';
	return ret;
}

static void print_usage(FILE *stream, const char *prog_name)
{
	int i;

	fprintf(stream, "\nDOCUMENTATION:\n%s\n", __doc__);
	fprintf(stream, "\n");
	fprintf(stream, " Usage: %s (options-see-below)\n", prog_name);
	fprintf(stream, " Listing options:\n");
	for (i = 0; long_options[i].name != 0; i++) {
		if (!long_options[i].flag && isalnum(long_options[i].val))
			fprintf(stream, " -%c, ", long_options[i].val);
		else
			fprintf(stream, "     ");

		printf(" --%s", long_options[i].name);

		if (long_options[i].has_arg == required_argument)
			fprintf(stream, " <ARG>");
		else if (long_options[i].has_arg == optional_argument)
			fprintf(stream, "[ARG]");

		fprintf(stream, "\n");
	}
	printf("\n");
}

static const char *hook_to_str(enum netstacklat_hook hook)
{
	switch (hook) {
	case NETSTACKLAT_HOOK_IP_RCV:
		return "ip-start";
	case NETSTACKLAT_HOOK_TCP_START:
		return "tcp-start";
	case NETSTACKLAT_HOOK_UDP_START:
		return "udp-start";
	case NETSTACKLAT_HOOK_TCP_SOCK_ENQUEUED:
		return "tcp-socket-enqueued";
	case NETSTACKLAT_HOOK_UDP_SOCK_ENQUEUED:
		return "udp-socket-enqueued";
	case NETSTACKLAT_HOOK_TCP_SOCK_READ:
		return "tcp-socket-read";
	case NETSTACKLAT_HOOK_UDP_SOCK_READ:
		return "udp-socket-read";
	default:
		return "invalid";
	}
}

static int hook_to_histmap(enum netstacklat_hook hook,
			   const struct netstacklat_bpf *obj)
{
	switch (hook) {
	case NETSTACKLAT_HOOK_IP_RCV:
		return bpf_map__fd(obj->maps.netstack_latency_ip_start_seconds);
	case NETSTACKLAT_HOOK_TCP_START:
		return bpf_map__fd(
			obj->maps.netstack_latency_tcp_start_seconds);
	case NETSTACKLAT_HOOK_UDP_START:
		return bpf_map__fd(
			obj->maps.netstack_latency_udp_start_seconds);
	case NETSTACKLAT_HOOK_TCP_SOCK_ENQUEUED:
		return bpf_map__fd(
			obj->maps.netstack_latency_tcp_sock_enqueued_seconds);
	case NETSTACKLAT_HOOK_UDP_SOCK_ENQUEUED:
		return bpf_map__fd(
			obj->maps.netstack_latency_udp_sock_enqueued_seconds);
	case NETSTACKLAT_HOOK_TCP_SOCK_READ:
		return bpf_map__fd(
			obj->maps.netstack_latency_tcp_sock_read_seconds);
	case NETSTACKLAT_HOOK_UDP_SOCK_READ:
		return bpf_map__fd(
			obj->maps.netstack_latency_udp_sock_read_seconds);
	default:
		return -EINVAL;
	}
}

static int parse_bounded_double(double *res, const char *str, double low,
				double high, const char *name)
{
	char *endptr;
	errno = 0;

	*res = strtod(str, &endptr);
	if (endptr == str || strlen(str) != endptr - str) {
		fprintf(stderr, "%s %s is not a valid number\n", name, str);
		return -EINVAL;
	}

	if (errno == ERANGE) {
		fprintf(stderr, "%s %s overflowed\n", name, str);
		return -ERANGE;
	}

	if (*res < low || *res > high) {
		fprintf(stderr, "%s must be in range [%g, %g]\n", name, low, high);
		return -ERANGE;
	}

	return 0;
}

static int parse_arguments(int argc, char *argv[],
			   struct netstacklat_config *conf)
{
	int opt, err, ret;
	char optstr[64];
	double fval;

	ret = generate_optstr(optstr, sizeof(optstr));
	if (ret < 0) {
		fprintf(stderr,
			"Internal error: optstr too short to fit all long_options\n");
		return ret;
	}

	while ((opt = getopt_long(argc, argv, optstr, long_options,
				  NULL)) != -1) {
		switch (opt) {
		case 'r': // report interval
			err = parse_bounded_double(
				&fval, optarg, 0.01, 3600 * 24,
				optval_to_longopt(opt)->name);
			if (err)
				return err;

			conf->report_interval_s = fval;
			break;
		case 'h': // help
			print_usage(stdout, argv[0]);
			exit(EXIT_SUCCESS);
		default:
			// unrecognized option reported by getopt, so just print usage
			print_usage(stderr, argv[0]);
			return -EINVAL;
		}
	}

	return 0;
}

static int find_first_nonzero_bucket(size_t n, const __u64 hist[n])
{
	int i;

	for (i = 0; i < n; i++) {
		if (hist[i] > 0)
			return i;
	}

	return -1;
}

static int find_last_nonzero_bucket(size_t n, const __u64 hist[n])
{
	int i;

	for (i = n - 1; i >= 0; i--) {
		if (hist[i] > 0)
			return i;
	}

	return -1;
}

static int find_largest_bucket(size_t n, const __u64 hist[n])
{
	__u64 max_val = 0;
	int i;

	for (i = 0; i < n; i++) {
		if (hist[i] > max_val)
			max_val = hist[i];
	}

	return max_val;
}

static double ns_to_siprefix(double ns, char **prefix)
{
	static char *prefixes[] = { "n", "u", "m", "" };
	int psteps = 0;

	while (ns >= 1000 && psteps < ARRAY_SIZE(prefixes) - 1) {
		ns /= 1000;
		psteps++;
	}

	*prefix = prefixes[psteps];

	return ns;
}

static void print_nchars(FILE *stream, char c, int n)
{
	while (n-- > 0)
		putc(c, stream);
}

static int print_bucket_interval(FILE *stream, double low_bound_ns,
				 double high_bound_ns)
{
	char *lprefix, *hprefix;
	double low_si, high_si;

	low_si = ns_to_siprefix(low_bound_ns, &lprefix);

	if (isinf(high_bound_ns)) {
		high_si = INFINITY;
		hprefix = " ";
	} else {
		high_si = ns_to_siprefix(high_bound_ns, &hprefix);
	}

	return fprintf(stream, "%c%.3g%ss, %.3g%ss]",
		       low_bound_ns == 0 ? '[' : '(', low_si, lprefix, high_si,
		       hprefix);
}

static void print_histbar(FILE *stream, __u64 count, __u64 max_count)
{
	int barlen = round((double)count / max_count * MAX_BAR_STRLEN);

	fprintf(stream, "|");
	print_nchars(stream, '@', barlen);
	print_nchars(stream, ' ', MAX_BAR_STRLEN - barlen);
	fprintf(stream, "|");
}

static void print_log2hist(FILE *stream, size_t n, const __u64 hist[n],
			   double multiplier)
{
	int bucket, start_bucket, end_bucket, max_bucket, len;
	double low_bound, high_bound, avg;
	__u64 count = 0;
	char *prefix;

	start_bucket = find_first_nonzero_bucket(n - 1, hist);
	end_bucket = find_last_nonzero_bucket(n - 1, hist);
	max_bucket = find_largest_bucket(n - 1, hist);

	for (bucket = max(0, start_bucket); bucket <= end_bucket; bucket++) {
		low_bound = pow(2, bucket - 1) * multiplier;
		high_bound = pow(2, bucket) * multiplier;

		// First bucket includes 0 (i.e. [0, 1] rather than (0.5, 1])
		if (bucket == 0)
			low_bound = 0;
		// Last bucket includes all values too large for the second-last bucket
		if (bucket == n - 2)
			high_bound = INFINITY;

		len = print_bucket_interval(stream, low_bound, high_bound);
		print_nchars(stream, ' ',
			     max(0, MAX_BUCKETSPAN_STRLEN - len) + 1);
		fprintf(stream, "%*llu ", MAX_BUCKETCOUNT_STRLEN, hist[bucket]);
		print_histbar(stream, hist[bucket], max_bucket);
		fprintf(stream, "\n");

		count += hist[bucket];
	}

	// Final "bucket" is the sum of all values in the histogram
	if (count > 0) {
		avg = ns_to_siprefix((double)hist[n - 1] / count, &prefix);
		fprintf(stream, "count: %llu, average: %.2f%ss\n", count, avg,
			prefix);
	} else {
		fprintf(stream, "count: %llu, average: -\n", count);
	}
}

static void merge_percpu_hist(size_t n, int ncpus,
			      const __u64 percpu_hist[n][ncpus],
			      __u64 merged_hist[n])
{
	int idx, cpu;

	memset(merged_hist, 0, sizeof(__u64) * n);

	for (idx = 0; idx < n; idx++) {
		for (cpu = 0; cpu < ncpus; cpu++) {
			merged_hist[idx] += percpu_hist[idx][cpu];
		}
	}
}

static int fetch_hist_map(int map_fd, __u64 hist[HIST_NBUCKETS])
{
	__u32 in_batch, out_batch, count = HIST_NBUCKETS;
	int ncpus = libbpf_num_possible_cpus();
	__u32 idx, buckets_fetched = 0;
	__u64 (*percpu_hist)[ncpus];
	__u32 *keys;
	int err = 0;

	DECLARE_LIBBPF_OPTS(bpf_map_batch_opts, batch_opts, .flags = BPF_EXIST);

	percpu_hist = calloc(HIST_NBUCKETS, sizeof(*percpu_hist));
	keys = calloc(HIST_NBUCKETS, sizeof(*keys));
	if (!percpu_hist || !keys) {
		err = -ENOMEM;
		goto exit;
	}

	while (buckets_fetched < HIST_NBUCKETS) {
		err = bpf_map_lookup_batch(map_fd,
					   buckets_fetched > 0 ? &in_batch : NULL,
					   &out_batch, keys + buckets_fetched,
					   percpu_hist + buckets_fetched, &count,
					   &batch_opts);
		if (err == -ENOENT) // All entries fetched
			err = 0;
		else if (err)
			goto exit;

		// Verify keys match expected idx range
		for (idx = buckets_fetched; idx < buckets_fetched + count; idx++) {
			if (keys[idx] != idx) {
				err = -EBADSLT;
				goto exit;
			}
		}

		in_batch = out_batch;
		buckets_fetched += count;
		count = HIST_NBUCKETS - buckets_fetched;
	}

	merge_percpu_hist(HIST_NBUCKETS, ncpus, percpu_hist, hist);

exit:
	free(percpu_hist);
	free(keys);
	return err;
}

static int report_stats(const struct netstacklat_bpf *obj)
{
	enum netstacklat_hook hook;
	__u64 hist[HIST_NBUCKETS] = { 0 };
	time_t t;
	int err;

	time(&t);
	printf("%s", ctime(&t));

	for (hook = 1; hook < NETSTACKLAT_N_HOOKS; hook++) {
		printf("%s:\n", hook_to_str(hook));

		err = fetch_hist_map(hook_to_histmap(hook, obj), hist);
		if (err)
			return err;

		print_log2hist(stdout, ARRAY_SIZE(hist), hist, 1);
		printf("\n");
	}
	fflush(stdout);

	return 0;
}

static int enable_sw_rx_tstamps(void)
{
	int tstamp_opt = SOF_TIMESTAMPING_RX_SOFTWARE;
	int sock_fd, err;

	sock_fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock_fd < 0) {
		err = -errno;
		fprintf(stderr, "Failed opening socket: %s\n", strerror(-err));
		return err;
	}

	err = setsockopt(sock_fd, SOL_SOCKET, SO_TIMESTAMPING, &tstamp_opt,
			 sizeof(tstamp_opt));
	if (err) {
		err = -errno;
		fprintf(stderr, "Failed setting SO_TIMESTAMPING option: %s\n",
			strerror(-err));
		goto err_socket;
	}

	return sock_fd;

err_socket:
	close(sock_fd);
	return err;
}

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

static int handle_signal(int sig_fd)
{
	struct signalfd_siginfo sig_info;
	ssize_t size;

	size = read(sig_fd, &sig_info, sizeof(sig_info));
	if (size != sizeof(sig_info)) {
		fprintf(stderr, "Failed reading signal fd\n");
		return -EBADFD;
	}

	switch (sig_info.ssi_signo) {
	case SIGINT:
	case SIGTERM:
		return NETSTACKLAT_ABORT;
	default:
		fprintf(stderr, "Unexpected signal: %d\n", sig_info.ssi_signo);
		return -EBADR;
	}
}

static int setup_timer(__u64 interval_ns)
{
	struct itimerspec timercfg = {
		.it_value = { .tv_sec = interval_ns / NS_PER_S,
			      .tv_nsec = interval_ns % NS_PER_S },
		.it_interval = { .tv_sec = interval_ns / NS_PER_S,
				 .tv_nsec = interval_ns % NS_PER_S }
	};
	int fd, err;

	fd = timerfd_create(CLOCK_MONOTONIC, 0);
	if (fd < 0) {
		return -errno;
	}

	err = timerfd_settime(fd, 0, &timercfg, NULL);
	if (err) {
		err = -errno;
		close(fd);
		return err;
	}

	return fd;
}

static int handle_timer(int timer_fd, const struct netstacklat_bpf *obj)
{
	__u64 timer_exps;
	ssize_t size;

	size = read(timer_fd, &timer_exps, sizeof(timer_exps));
	if (size != sizeof(timer_exps)) {
		fprintf(stderr, "Failed reading timer fd\n");
		return -EBADFD;
	}

	if (timer_exps == 0)
		return 0;
	if (timer_exps > 1)
		fprintf(stderr, "Warning: Missed %llu reporting intervals\n",
			timer_exps - 1);

	return report_stats(obj);
}

static int epoll_add_event(int epoll_fd, int fd, __u64 event_type, __u64 value)
{
	struct epoll_event ev = {
		.events = EPOLLIN,
		.data = { .u64 = event_type | value },
	};

	if (value & NETSTACKLAT_EPOLL_TYPE_MASK)
		return -EINVAL;

	return epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd, &ev) ? -errno : 0;
}

static int setup_epoll_instance(int sig_fd, int timer_fd)
{
	int epoll_fd, err = 0;

	epoll_fd = epoll_create1(EPOLL_CLOEXEC);
	if (epoll_fd < 0)
		return -errno;

	err = epoll_add_event(epoll_fd, sig_fd, NETSTACKLAT_EPOLL_SIG, sig_fd);
	if (err)
		goto err;

	err = epoll_add_event(epoll_fd, timer_fd, NETSTACKLAT_EPOLL_TIMER,
			      timer_fd);
	if (err)
		goto err;

	return epoll_fd;

err:
	close(epoll_fd);
	return err;
}

static int poll_events(int epoll_fd, const struct netstacklat_bpf *obj)
{
	struct epoll_event events[MAX_EPOLL_EVENTS];
	int i, n, fd, err = 0;
	__u64 epoll_type;

	n = epoll_wait(epoll_fd, events, MAX_EPOLL_EVENTS, 100);
	if (n < 0)
		return -errno;

	for (i = 0; i < n; i++) {
		epoll_type = events[i].data.u64 & NETSTACKLAT_EPOLL_TYPE_MASK;
		fd = events[i].data.u64 & ~NETSTACKLAT_EPOLL_TYPE_MASK;

		switch (epoll_type) {
		case NETSTACKLAT_EPOLL_SIG:
			err = handle_signal(fd);
			break;
		case NETSTACKLAT_EPOLL_TIMER:
			err = handle_timer(fd, obj);
			break;
		default:
			fprintf(stderr, "Warning: unexpected epoll data: %lu\n",
				events[i].data.u64);
			break;
		}

		if (err)
			break;
	}

	return err;
}

int main(int argc, char *argv[])
{
	int sig_fd, timer_fd, epoll_fd, sock_fd, err;
	struct netstacklat_config config = {
		.report_interval_s = 5,
	};
	struct netstacklat_bpf *obj;
	char errmsg[128];

	err = parse_arguments(argc, argv, &config);
	if (err) {
		fprintf(stderr, "Failed parsing arguments: %s\n",
			strerror(-err));
		return EXIT_FAILURE;
	}

	sock_fd = enable_sw_rx_tstamps();
	if (sock_fd < 0) {
		err = sock_fd;
		fprintf(stderr,
			"Failed enabling software RX timestamping: %s\n",
			strerror(-err));
		return EXIT_FAILURE;
	}

	obj = netstacklat_bpf__open_and_load();
	if (!obj) {
		err = libbpf_get_error(obj);
		libbpf_strerror(err, errmsg, sizeof(errmsg));
		fprintf(stderr, "Failed loading eBPF programs: %s\n", errmsg);
		goto exit_sockfd;
	}

	err = netstacklat_bpf__attach(obj);
	if (err) {
		libbpf_strerror(err, errmsg, sizeof(errmsg));
		fprintf(stderr, "Failed to attach eBPF programs: %s\n", errmsg);
		goto exit_destroy_bpf;
	}

	sig_fd = init_signalfd();
	if (sig_fd < 0) {
		err = sig_fd;
		fprintf(stderr, "Failed setting up signal handling: %s\n",
			strerror(-err));
		goto exit_detach_bpf;
	}

	timer_fd = setup_timer(config.report_interval_s * NS_PER_S);
	if (timer_fd < 0) {
		err = timer_fd;
		fprintf(stderr, "Failed creating timer: %s\n", strerror(-err));
		goto exit_sigfd;
	}

	epoll_fd = setup_epoll_instance(sig_fd, timer_fd);
	if (epoll_fd < 0) {
		err = epoll_fd;
		fprintf(stderr, "Failed setting up epoll: %s\n",
			strerror(-err));
		goto exit_timerfd;
	}

	// Report stats until user shuts down program
	while (true) {
		err = poll_events(epoll_fd, obj);

		if (err) {
			if (err == NETSTACKLAT_ABORT) {
				// Report stats a final time before terminating
				err = report_stats(obj);
			} else {
				libbpf_strerror(err, errmsg, sizeof(errmsg));
				fprintf(stderr, "Failed polling fds: %s\n",
					errmsg);
			}
			break;
		}
	}

	// Cleanup
	close(epoll_fd);
exit_timerfd:
	close(timer_fd);
exit_sigfd:
	close(sig_fd);
exit_detach_bpf:
	netstacklat_bpf__detach(obj);
exit_destroy_bpf:
	netstacklat_bpf__destroy(obj);
exit_sockfd:
	close(sock_fd);
	return err ? EXIT_FAILURE : EXIT_SUCCESS;
}
