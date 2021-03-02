#!/bin/bash
#
# Author: Jesper Dangaaard Brouer <netoptimizer@brouer.com>
# License: GPLv2
#
# Modified by Simon Sundberg <simon.sundberg@kau.se> to add support
# of optional section (--sec) option or attaching a pinned program
#
basedir=`dirname $0`
source ${basedir}/functions.sh

root_check_run_with_sudo "$@"

# Use common parameters
source ${basedir}/parameters.sh

export TC=/sbin/tc

# This can be changed via --file or --obj
if [[ -z ${BPF_OBJ} ]]; then
    # Fallback default
    BPF_OBJ=pping_kern_tc.o
fi

# This can be changed via --sec
if [[ -z ${SEC} ]]; then
    # Fallback default
    SEC=pping_egress
fi

info "Applying TC-BPF egress setup on device: $DEV with object file: $BPF_OBJ"

function tc_remove_clsact()
{
    local device=${1:-$DEV}
    shift

    # Removing qdisc clsact, also deletes all filters
    call_tc_allow_fail qdisc del dev "$device" clsact 2> /dev/null
}

function tc_init_clsact()
{
    local device=${1:-$DEV}
    shift

    # TODO: find method that avoids flushing (all users)

    # Also deletes all filters
    call_tc_allow_fail qdisc del dev "$device" clsact 2> /dev/null

    # Load qdisc clsact which allow us to attach BPF-progs as TC filters
    call_tc qdisc add dev "$device" clsact
}

function tc_egress_bpf_attach()
{
    local device=${1:-$DEV}
    local objfile=${2:-$BPF_OBJ}
    local section=${3:-$SEC}
    shift 3

    call_tc filter add dev "$device" pref 2  handle 2 \
	    egress bpf da obj "$objfile" sec "$section"
}

function tc_egress_bpf_attach_pinned()
{
    local device=${1:-$DEV}
    local pinprog=${2:-$PIN_PROG}
    shift 2

    call_tc filter add dev "$device" pref 2  handle 2 \
	    egress bpf da pinned "$pinprog"
}

function tc_egress_list()
{
    local device=${1:-$DEV}

    call_tc filter show dev "$device" egress
}

if [[ -n $REMOVE ]]; then
    tc_remove_clsact $DEV
    exit 0
fi

tc_init_clsact $DEV

if [[ -n $PIN_PROG ]]; then
    tc_egress_bpf_attach_pinned $DEV $PIN_PROG
else
    tc_egress_bpf_attach $DEV $BPF_OBJ $SEC
fi

# Practical to list egress filters after setup.
# (It's a common mistake to have several progs loaded)
if [[ -n $LIST ]]; then
    info "Listing egress filter on device"
    tc_egress_list $DEV
fi
