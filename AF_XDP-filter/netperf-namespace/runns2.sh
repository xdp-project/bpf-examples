#!/bin/bash -x
# SPDX-License-Identifier: GPL-2.0
# Server side helper script for TCP performance testing with eBPF filter
# Set FILTER env var to af_xdp_kern or af_xdp_kern_passall according to which filter to use
# Set LEAVE env var non-null for baseline test with no eBPF filter
# Set TCPDUMP env var non-null to take tcpdumps of the interfaces
ip link set lo up
ip link set vpeer2 up
ip addr add 10.10.0.20/16 dev vpeer2
ip link set dev vpeer2 xdpgeneric off
if [[ -n "${TCPDUMP}" ]]
then
  tcpdump -i tun0 -w tun0.tcpdump &
  tcpdump_tun0_pid=$!
  tcpdump -i vpeer2 -w vpeer2.tcpdump &
  tcpdump_vpeer2_pid=$!
fi

(
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
    ./filter-xdp_stats &
    filter_pid=$!
    netserver -p ${PORT} -4 -D -f &
    netserver_pid=$!
    sleep 120
    kill -TERM ${ns2_pid} ${filter_pid}
    kill -INT ${netserver_pid}
  else
    netserver -p ${PORT} -4 -D -f &
    netserver_pid=$!
    sleep 120
    kill -INT ${netserver_pid}  
  fi 
  wait
)
if [[ -n "${TCPDUMP}" ]]
then
  kill -INT ${tcpdump_tun0_pid}
  kill -INT ${tcpdump_vpeer2_pid}
fi
wait
