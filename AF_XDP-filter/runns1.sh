#!/bin/bash -x

ip link set lo up
ip link set vpeer1 up
ip addr add 10.10.0.10/16 dev vpeer1
sleep 6
ping -c 10 10.10.0.20

