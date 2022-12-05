#!/bin/bash -x
# SPDX-License-Identifier: GPL-2.0
# Run script for eBPF TCP performance testing between 2 real machines
# Run this on the server. Assumes server IP address is 10.1.0.2
# Assumes client is reachable on another network as 192.168.17.9
# Arranged for a Pensando NIC which uses 16 queues.
# Set FILTER env var to af_xdp_kern or af_xdp_kern_passall according to which filter to use
# Set LEAVE env var non-null for baseline test with no eBPF filter
# Set PORT to choose a port for the server to listen on

ip link set dev enp25s0 xdpgeneric off
rm -f /sys/fs/bpf/accept_map /sys/fs/bpf/xdp_stats_map
ip tuntap add mode tun tun0
ip link set dev tun0 down
ip link set dev tun0 addr 10.1.0.254/24
ip link set dev tun0 up
if [[ -z "${LEAVE}" ]]
then 
  for device in /proc/sys/net/ipv4/conf/*
  do
    echo 0 >${device}/rp_filter
  done
  cd ..
  ./af_xdp_user -S -d enp25s0 -Q 16 --filename ./${FILTER}.o &
  real_pid=$!
  iperf3 -s -p ${PORT}  &
  iperf3_pid=$!
  ssh 192.168.17.9 iperf3 -c 10.1.0.2 -p ${PORT} | tee client.log
  kill -INT ${iperf3_pid} ${real_pid}
else
  iperf3 -s -p ${PORT} &
  iperf3_pid=$!
  ssh 192.168.17.9 iperf3 -c 10.1.0.2 -p ${PORT} | tee client.log
  kill -INT ${iperf3_pid}
fi
wait

