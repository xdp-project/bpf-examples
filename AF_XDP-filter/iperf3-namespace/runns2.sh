#!/bin/bash -x
# SPDX-License-Identifier: GPL-2.0
# Server side helper script for TCP performance testing with eBPF filter
# Set FILTER env var to af_xdp_kern or af_xdp_kern_passall according to which filter to use
# Set LEAVE env var non-null for baseline test with no eBPF filter
# Set PORT to choose a port for the server to listen on
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
  for device in /proc/sys/net/ipv4/conf/*
  do
    echo 0 >${device}/rp_filter
  done
  cd ..
  ./af_xdp_user -S -d vpeer2 -Q 1 --filename ./${FILTER}.o &
  ns2_pid=$!
  sleep 2
  iperf3 -s -p ${PORT} &
  iperf3_pid=$!
  sleep 20
  kill -INT ${ns2_pid} ${iperf3_pid}
else
  iperf3 -s -p ${PORT} &
  iperf3_pid=$!
  sleep 20
  kill -INT ${iperf3_pid}  
fi 
wait
