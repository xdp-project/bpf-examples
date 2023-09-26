# Introduction

BPF_PROG_TYPE_NETFILTER was introduced in 6.4, now with a new kernel, a bpf program could attach to netfilter hooks and handles package in a similiar way as iptables/nftables. By now, 6.5.0, there is no bpf kfunc implemented yet for DNAT/SNAT, and the only thing a bpf program can do is to decide whether to DROP the package or not.

* netfilter_ip4_blocklist.c/netfilter_ip4_blocklist.bpf.c

This sample code implements a simple ipv4 blocklist.
The bpf program drops package if destination ip address hits a match in the map of type BPF_MAP_TYPE_LPM_TRIE,
The userspace code would load the bpf program, attach it to netfilter's FORWARD/OUTPUT hook, and then write ip patterns into the bpf map.


# TODO

This sample hard-codes ip address to be blocked, just for demonstration.
It would be better to break the userspace program into two parts:
* init program
Loads bpf program and pin bpf program and map into somewhere under /sys/fs/bpf
* interactive program
add/delete/query ip blocklist via bpf map under /sys/fs/bpf

