#!/bin/bash -x
# SPDX-License-Identifier: GPL-2.0
ip link set lo up
ip link set vpeer2 up
ip addr add 10.10.0.20/16 dev vpeer2
ip link set dev vpeer2 xdpgeneric off
ip tuntap add mode tun tun0
ip link set dev tun0 down
ip link set dev tun0 addr 10.10.0.30/24
ip link set dev tun0 up

mount -t bpf bpf /sys/fs/bpf
df /sys/fs/bpf
ls -l /sys/fs/bpf
rm -f /sys/fs/bpf/accept_map /sys/fs/bpf/xdp_stats_map
if [[ -z "${LEAVE}" ]]
then 
  export LD_LIBRARY_PATH=/usr/local/lib
  ./af_xdp_user -S -d vpeer2 -Q 1 --filename ./af_xdp_kern.o &
  ns2_pid=$!
  sleep 20
  kill -INT ${ns2_pid}
fi 
wait
