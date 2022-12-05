#!/bin/bash -x
# SPDX-License-Identifier: GPL-2.0
# Run script for eBPF TCP performance testing between 2 virtual machines
# Run this on the server.
# Set FILTER env var to af_xdp_kern or af_xdp_kern_passall according to which filter to use
# Set LEAVE env var non-null for baseline test with no eBPF filter
# Set CLIENT env var to the IP address of the client
# Set SERVER env var to the IP address of the server

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
  ./af_xdp_user -S -d enp25s0 -Q 1 --filename ./${FILTER}.o &
  real_pid=$!
  netserver -p 50000 -4 -D -f &
  netserver_pid=$!
  ssh ${CLIENT} netperf -4 -t TCP_RR -H ${SERVER} -p 50000 -- -D | tee client_rr.log
  ssh ${CLIENT} netperf -4 -t TCP_CRR -H ${SERVER} -p 50000 -- -D | tee client_crr.log
  kill -INT ${netserver_pid}
else
  netserver -p 50000 -4 -D -f &
  netserver_pid=$!
  ssh ${CLIENT} netperf -4 -t TCP_RR -H ${SERVER} -p 50000 -- -D | tee client_rr.log
  ssh ${CLIENT} netperf -4 -t TCP_CRR -H ${SERVER} -p 50000 -- -D | tee client_crr.log
-- -D
  kill -INT ${netserver_pid}
fi
wait

