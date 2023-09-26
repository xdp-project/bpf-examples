// SPDX-License-Identifier: GPL-2.0

#include <stdio.h>
#include <unistd.h>
#include <asm/unistd.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <linux/netfilter.h>


static inline int sys_bpf(enum bpf_cmd cmd, union bpf_attr *attr, unsigned int size)
{
	return syscall(__NR_bpf, cmd, attr, size);
}

struct ipv4_lpm_key {
	__u32 prefixlen;
	__u32 data;
};


int main(int argc, char **argv)
{
	int prog_fd, map_fd;
	int err;
	struct bpf_object *obj;
	struct bpf_program *prog;
	union bpf_attr attr = { };

	obj = bpf_object__open_file("./netfilter_ip4_blocklist.bpf.o", NULL);
	if (libbpf_get_error(obj)) {
		printf("fail to open bpf file\n");
		return 1;
	}
	prog = bpf_object__find_program_by_name(obj, "netfilter_ip4block");
	if (!prog) {
		printf("fail to find bpf program\n");
		return 1;
	}
	bpf_program__set_type(prog, BPF_PROG_TYPE_NETFILTER);
	if (bpf_object__load(obj)) {
		printf("loading BPF object file failed\n");
		return 1;
	}
	map_fd = bpf_object__find_map_fd_by_name(obj, "ipv4_lpm_map");
	if (map_fd < 0) {
		printf("Fail to locate trie ipv4_lpm_map\n");
		return 1;
	}
	/* attach to netfilter forward handler */
	prog_fd = bpf_program__fd(prog);
	attr.link_create.prog_fd = prog_fd;
	attr.link_create.attach_type = BPF_NETFILTER;
	attr.link_create.netfilter.pf = NFPROTO_IPV4;
	attr.link_create.netfilter.hooknum = NF_INET_FORWARD;
	attr.link_create.netfilter.priority = -128;
	err = sys_bpf(BPF_LINK_CREATE, &attr, sizeof(attr));
	if (err < 0) {
		perror("Fail to link bpf program to netfilter forward hook\n");
		return 1;
	}
	/* attach to netfilter output handler */
	attr.link_create.netfilter.hooknum = NF_INET_LOCAL_OUT;
	err = sys_bpf(BPF_LINK_CREATE, &attr, sizeof(attr));
	if (err < 0) {
		perror("Fail to link bpf program to netfilter output hook\n");
		return 1;
	}
	printf("bpf program/map loaded....\n");
	/* add rules */
	{
		struct ipv4_lpm_key key;
		__u32 value = 0;
		__u8 *p = (__u8 *) &key.data;
		/* block 192.168.11.107/32 */
		key.prefixlen = 27;
		/* same as key.data = 0x6B0BA8C0; on a little-endian machine */
		p[0] = 192;
		p[1] = 168;
		p[2] = 11;
		p[3] = 107;
		bpf_map_update_elem(map_fd, &key, &value, BPF_ANY);
		/* block 192.168.11.107/24 */
		key.prefixlen = 24;
		value++;
		bpf_map_update_elem(map_fd, &key, &value, BPF_ANY);
		/* block 192.168.11.107/27 */
		key.prefixlen = 32;
		value++;
		bpf_map_update_elem(map_fd, &key, &value, BPF_ANY);
		/* remove rule */
		/* bpf_map_delete_elem(map_fd, &key); */
		printf("rules inserted, ready to work\n");
	}
	while (1)
		sleep(600);
	return 0;
}
