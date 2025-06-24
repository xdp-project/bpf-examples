/* SPDX-License-Identifier: GPL-2.0-or-later */
#define _GNU_SOURCE
#include <sys/epoll.h>
#include <getopt.h>
#include <math.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <linux/bpf.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "stats.bpf.skel.h"
#include "trie-free-latency.bpf.skel.h"
#include "trie.h"

static unsigned int n_entries = 0;
static unsigned int n_iterations = 0;

static int fill_map(struct bpf_map *map)
{
	int err;
	int i;

	for (i = 0 ; i < n_entries; i++) {
		struct trie_key key = {
			.prefixlen = 32,
			.data = i
		};
		__u32 val = 1;

		err = bpf_map__update_elem(map, &key, sizeof(key), &val, sizeof(val), 0);
		if (err) {
			fprintf(stderr, "Error: %d for key=%d\n", err, i);
			return err;
		}
	}
	return 0;
}


static __u64 wait_for_free(struct trie_free_latency_bpf *skel, struct bpf_map *map)
{
	struct bpf_map *key = NULL, *prev = NULL;
	struct latency_record r;

	for (;;) {
		int err = bpf_map__get_next_key(map, &prev, &key, sizeof(key));

		if (-err == ENOENT) {
			// Reached end of map. Reset.
			prev = NULL;
			usleep(2000);
		} else {
			if (bpf_map__lookup_elem(map, &key, sizeof(key),
						&r, sizeof(r), 0) == 0) {
				if (!strcmp(r.name, "trie_map"))
					return r.val;
			}
			prev = key;
		}
	}
	return -1;
}

static void usage(const char *progname)
{
	fprintf(stderr, "Usage: %s -e <num entries> -i <num iterations>\n", progname);
	exit(EXIT_FAILURE);
}

static int parse_args(int argc, char **argv)
{
	struct option lopts[] = {
		{ NULL, 0, 0, 0 }
	};
	int opt, opt_index;

	for (;;) {
		opt = getopt_long(argc, argv, "e:i:", lopts, &opt_index);
		if (opt == EOF)
			break;

		switch (opt) {
		case 'e':
			n_entries = atoi(optarg);
			break;
		case 'i':
			n_iterations = atoi(optarg);
			break;
		default:
			usage(argv[0]);
		}
	}

	if (n_entries == 0 && n_iterations == 0)
		usage(argv[0]);

	if (n_entries == 0) {
		fprintf(stderr, "Error: -e argument must be greater than zero.\n");
		exit(EXIT_FAILURE);
	}

	if (n_iterations == 0) {
		fprintf(stderr, "Error: -i argument must be greater than zero.\n");
		exit(EXIT_FAILURE);
	}

	if (n_entries > MAX_ENTRIES) {
		fprintf(stderr, "Error: -e argument too large. Increase MAX_ENTRIES.\n");
		exit(EXIT_FAILURE);
	}

	return 0;
}

static int run(struct stats_bpf *stats, __u64 *latency_ns)
{
	struct trie_free_latency_bpf *skel;
	int err = 0;

	skel = trie_free_latency_bpf__open();
	if (!skel)
		goto cleanup;

	err = trie_free_latency_bpf__load(skel);
	if (err)
		goto cleanup;

	err = trie_free_latency_bpf__attach(skel);
	if (err)
		goto cleanup;

	err = fill_map(skel->maps.trie_map);
	if (err)
		goto cleanup;

	// Wait for map to be freed
	trie_free_latency_bpf__destroy(skel);
	*latency_ns = wait_for_free(skel, stats->maps.latencies);

	return 0;

cleanup:
	trie_free_latency_bpf__destroy(skel);
	return err;
}

static inline __u64 square(__u64 val)
{
	return val * val;
}

static inline __u64 calc_mean(__u64 *latencies)
{
	__u64 mean;
	int i;

	for (mean = 0, i = 0; i < n_iterations; i++) {
		mean += latencies[i];
	}

	return mean / n_iterations;
}

static inline __u64 calc_stddev(__u64 *latencies, __u64 mean)
{
	__u64 stddev, *squares;
	int i;

	squares = calloc(n_iterations, sizeof(*squares));
	if (!squares) {
		perror("calloc");
		exit(EXIT_FAILURE);
	}

	for (i = 0; i < n_iterations; i++) {
		squares[i] = square(latencies[i] - mean);
	}

	for (stddev = 0, i = 0; i < n_iterations; i++) {
		stddev += squares[i];
	}

	free(squares);

	if (!stddev)
		return 0;

	return sqrt(stddev / (n_iterations - 1));
}


static void print_stats(__u64 *latencies)
{
	__u64 mean, stddev;
	double cov;

	mean = calc_mean(latencies);
	stddev = calc_stddev(latencies, mean);
	cov = (double)(100 * stddev) / mean;

	printf("Average time to free %u entries is %llums (±%.2f%%) "
			"(%lluns per entry)\n", n_entries,
			mean / 1000000, cov, mean / n_entries);
}

int main(int argc, char **argv)
{
	struct stats_bpf *stats;
	__u64 *latencies = NULL;
	int i, err;

	err = parse_args(argc, argv);
	if (err)
		usage(argv[0]);

	stats = stats_bpf__open();
	if (!stats)
		goto cleanup;

	err = stats_bpf__load(stats);
	if (err)
		goto cleanup;

	err = stats_bpf__attach(stats);
	if (err)
		goto cleanup;

	latencies = calloc(n_iterations, sizeof(*latencies));
	if (!latencies) {
		perror("calloc");
		err = EXIT_FAILURE;
		goto cleanup;
	}

	for (i = 0; i < n_iterations; i++) {
		err = run(stats, &latencies[i]);
		if (err)
			goto cleanup;
	}

	print_stats(latencies);

cleanup:
	free(latencies);
	stats_bpf__destroy(stats);
	return err;
}
