#!/bin/bash
#
# This HTB shaper setup script is available for easier comparing the
# accuracy against the EDT solution.
#
# Author: Jesper Dangaaard Brouer <netoptimizer@brouer.com>
# License: GPLv2
#
basedir=`dirname $0`
source ${basedir}/functions.sh

root_check_run_with_sudo "$@"

# Use common parameters
source ${basedir}/parameters.sh

export TC=/sbin/tc

# It seems measured BW is TCP goodput, but configured BW is wirespeed.
# Measurements show around 930Mbit best-case.  Q-in-Q result in MTU
# 1522 bytes.  TCP goodput segments are 1448 bytes.
#
#RATE=$((930*1522/1448))Mbit
##RATE=$((933*1522/1448))Mbit
##CEIL=$((999*1522/1448))
#CEIL=1Gbit
#CEIL=980mbit

# EDT shaper show TCP goodput of 956 Mbit/s.
#  echo $((956*1514/1448)) = 999
RATE=999Mbit
CEIL=1000Mbit

#RATE=500mbit
#CEIL=577mbit

# Each of the HTB root-class(es) get these RATE+CEIL upper bandwidth bounds.
ROOT_RATE=9000Mbit
ROOT_CEIL=9500Mbit

DEFAULT_RATE=6000Mbit
DEFAULT_CEIL=6000Mbit

TC=/usr/sbin/tc
VERBOSE=1

function tc() {
    _call_tc "" "$@"
}

# Delete existing root qdisc
call_tc_allow_fail qdisc del dev "$DEV" root

if [[ -n $REMOVE ]]; then
    exit 0
fi

# HTB shaper
#tc qdisc add dev "$DEV" root handle 1: htb default 2
tc qdisc add dev "$DEV" root handle 1: htb default 16

# The root-class set upper bandwidth usage
tc class add dev "$DEV" parent 1: classid 1:1 \
       htb rate $ROOT_RATE ceil $ROOT_CEIL

# Default class 1:2
tc class add dev "$DEV" parent 1: classid 1:2 htb \
        rate "$DEFAULT_RATE" ceil "$DEFAULT_CEIL"
#       burst 100000 cburst 100000
tc qdisc add dev $DEV parent 1:2 fq_codel


# Class for vlan 16
tc class add dev "$DEV" parent 1: classid 1:16 htb rate "$RATE" ceil "$CEIL" \
        burst $((1522*2)) cburst $((1522*2)) \
        linklayer ethernet
#       burst 1522 cburst 1522
        #burst 1 cburst 1
#       burst $((1522*2)) cburst $((1522*2))
#       overhead $((14+4+4)) linklayer ethernet
#tc qdisc add dev "$DEV" parent 1:16 fq_codel
tc qdisc add dev "$DEV" parent 1:16 fq_codel quantum $((1514+4+4))
#tc qdisc add dev "$DEV" parent 1:16 pfifo

# parent filter:
#tc filter add dev "$DEV" parent 1:0 prio 100 protocol 802.1q u32
#
# vlan 16:
#tc filter add dev "$DEV" parent 1:0 prio 100 \
#        protocol 802.1q \
#        u32 match u16 0x0010 0x0fff at -4 \
#        flowid 1:16

tc filter add dev $DEV protocol all parent 1:0 prio 101 \
        basic match "meta(vlan mask 0xfff eq 16)" flowid 1:16
