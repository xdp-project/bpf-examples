#!/bin/bash -x
# SPDX-License-Identifier: GPL-2.0
ip netns delete ns1
ip netns delete ns2
sleep 2

ip netns add ns1
ip netns add ns2

ip link add veth1 type veth peer name vpeer1
ip link add veth2 type veth peer name vpeer2

ip link set veth1 up
ip link set veth2 up

ip link set vpeer1 netns ns1
ip link set vpeer2 netns ns2

ip link add br0 type bridge
ip link set br0 up

ip link set veth1 master br0
ip link set veth2 master br0

ip addr add 10.10.0.1/16 dev br0

iptables -P FORWARD ACCEPT
iptables -F FORWARD


ip netns exec ns2 ./runns2.sh &
ip netns exec ns1 ./runns1.sh

wait
