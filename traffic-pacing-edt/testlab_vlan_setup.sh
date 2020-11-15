#!/bin/bash
#
# Testlab setup script for VLAN Q-in-Q (double tagged VLAN) config.
#
# Author: Jesper Dangaaard Brouer <netoptimizer@brouer.com>
# License: GPLv2
#
basedir=`dirname $0`
source ${basedir}/functions.sh

root_check_run_with_sudo "$@"

# Use common parameters
source ${basedir}/parameters.sh

export IP=/sbin/ip
function ip() {
    call_ip "$@"
}

function create_vlan_device() {
    local vlan=${1}
    local device=${2:-$DEV}
    shift 2

    if [[ -z "$vlan" ]]; then
	err 2 "Missing VLAN is as input"
    fi

    ip link add link "$device" name ${device}.${vlan} type vlan id ${vlan}
    ip link set ${device}.${vlan} up
}

function create_vlan_device_802_1ad() {
    local vlan=${1}
    local device=${2:-$DEV}
    shift 2

    if [[ -z "$vlan" ]]; then
	err 2 "Missing VLAN is as input"
    fi

    ip link add link "$device" name ${device}.${vlan} type vlan id ${vlan} \
       protocol 802.1ad
    ip link set ${device}.${vlan} up
}


function delete_vlan_device() {
    local vlan=${1}
    local device=${2:-$DEV}
    shift 2

    if [[ -z "$vlan" ]]; then
	err 2 "Missing VLAN is as input"
    fi

    ip link del ${device}.${vlan}
}


if [[ -z "$1" ]]; then
    err 3 "Missing arg#1 for outer vlan"
fi
OUTER=$1

if [[ -z "$2" ]]; then
    err 3 "Missing arg#2 for inner vlan"
fi
INNER=$2

if [[ -n $REMOVE ]]; then
    delete_vlan_device $INNER ${DEV}.${OUTER}
    delete_vlan_device $OUTER $DEV
    exit 0
fi

create_vlan_device $OUTER $DEV
create_vlan_device $INNER ${DEV}.${OUTER}

# Set MTU to handle extra VLAN headers, NICs usually allow one VLAN
# header even though they have configured MTU 1500.
ip link set $DEV mtu 1508
ip link set ${DEV}.${OUTER} mtu 1504
