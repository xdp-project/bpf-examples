/* SPDX-License-Identifier: GPL-2.0 */
/* Copied from $(LINUX)/tools/testing/selftests/bpf/bpf_util.h */
#ifndef __BPF_UTIL__
#define __BPF_UTIL__

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

static inline unsigned int bpf_num_possible_cpus(void)
{
	static const char *fcpu = "/sys/devices/system/cpu/possible";
	unsigned int start, end, possible_cpus = 0;
	char buff[128];
	FILE *fp;
	int n;

	fp = fopen(fcpu, "r");
	if (!fp) {
		printf("Failed to open %s: '%s'!\n", fcpu, strerror(errno));
		exit(1);
	}

	while (fgets(buff, sizeof(buff), fp)) {
		n = sscanf(buff, "%u-%u", &start, &end);
		if (n == 0) {
			printf("Failed to retrieve # possible CPUs!\n");
			exit(1);
		} else if (n == 1) {
			end = start;
		}
		possible_cpus = start == 0 ? end + 1 : 0;
		break;
	}
	fclose(fp);

	return possible_cpus;
}

#define __bpf_percpu_val_align	__attribute__((__aligned__(8)))

#define BPF_DECLARE_PERCPU(type, name)				\
	struct { type v; /* padding */ } __bpf_percpu_val_align	\
		name[bpf_num_possible_cpus()]
#define bpf_percpu(name, cpu) name[(cpu)].v

#ifndef ARRAY_SIZE
# define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
#endif

#ifndef sizeof_field
#define sizeof_field(TYPE, MEMBER) sizeof((((TYPE *)0)->MEMBER))
#endif

#ifndef offsetofend
#define offsetofend(TYPE, MEMBER) \
	(offsetof(TYPE, MEMBER)	+ sizeof_field(TYPE, MEMBER))
#endif

#endif /* __BPF_UTIL__ */
