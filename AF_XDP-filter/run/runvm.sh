#!/bin/bash -x
# SPDX-License-Identifier: GPL-2.0
ip link set dev enp1s0 xdpgeneric off
rm -f /sys/fs/bpf/accept_map /sys/fs/bpf/xdp_stats_map
ip tuntap add mode tun tun0
ip link set dev tun0 down
ip link set dev tun0 addr 192.168.122.254/24
ip link set dev tun0 up
for device in /proc/sys/net/ipv4/conf/*
do
  echo 0 >${device}/rp_filter
done
cd ..
./af_xdp_user -S -d enp1s0 -Q 1 --filename ./af_xdp_kern.o
