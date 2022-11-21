#!/bin/bash -x
ip link set dev enp1s0 xdpgeneric off
rm -f /sys/fs/bpf/accept_map /sys/fs/bpf/xdp_stats_map
ip tuntap add mode tun tun0
ip link set dev tun0 down
ip link set dev tun0 addr 10.0.2.254/24
ip link set dev tun0 up
export LD_LIBRARY_PATH=/usr/local/lib
./af_xdp_user -S -d enp1s0 -Q 1 --filename ./af_xdp_kern.o
