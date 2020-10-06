#!/bin/bash

set -o errexit

TESTENV=../lib/testenv/testenv.sh

if [[ "$1" == "teardown" ]] || [[ "$1" == "reset" ]]; then
    $TESTENV teardown -n bpf-encap
    [[ "$1" == "teardown" ]] && exit 0
fi

$TESTENV setup -n bpf-encap --legacy-ip
ip link add dev bpf-encap2 type veth peer name veth1 netns bpf-encap
ip link set dev bpf-encap2 up
ip a add dev bpf-encap2 10.11.2.1/24
ip a add dev bpf-encap2 fc00:dead:cafe:2::1/64
$TESTENV exec ip link set dev veth1 up
$TESTENV exec ip a add 10.11.2.2/24 dev veth1
$TESTENV exec ip a add fc00:dead:cafe:2::2/64 dev veth1
$TESTENV exec -- sysctl -w net.ipv4.ip_forward=1 net.ipv6.conf.all.forwarding=1 net.ipv4.conf.veth0.rp_filter=2 net.ipv4.conf.veth0.accept_local=0
#$TESTENV exec -- ip link set dev veth0 xdp object xdp_encap.o
$TESTENV exec -- tc qdisc add dev veth0 clsact
$TESTENV exec -- tc filter add dev veth0 ingress bpf da obj tc_bpf_encap.o
ping fc00:dead:cafe:1::2 &
tcpdump -expni bpf-encap2
