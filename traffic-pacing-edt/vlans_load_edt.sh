#!/bin/bash
#
# Script for loading EDT-pacer BPF-prog on all downstream VLANs
#
basedir=`dirname $0`
source ${basedir}/functions.sh

root_check_run_with_sudo "$@"

# Use common parameters
source ${basedir}/parameters.sh

# Default verbose
VERBOSE=1

# Downstream dev: ens6f0
VLAN_START=168
VLAN_END=205

cmd=${basedir}/bpf_egress_loader.sh

options=""

if [[ -n $REMOVE ]]; then
    options+=" --remove"
fi
if [[ -n $DRYRUN ]]; then
    options+=" --dry-run"
    #cmd="echo $cmd"
fi
if [[ -n $VERBOSE ]]; then
    options+=" --verbose"
fi

for (( vlan=${VLAN_START}; vlan<=${VLAN_END}; vlan++ ))
do
    VLAN=${DEV}.$vlan
    $cmd --dev $VLAN $options
done
