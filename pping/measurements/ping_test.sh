#!/bin/bash

# A simple test test to measure the accuracy of the RTTs reported by ePPing.
# Runs ePPing in the ICMP tracking mode on a machine and then starts ping on
# the same machine. By capturing both the reported RTTs from ping and ePPing
# one can compare them and correlate them perfectly as each will generate
# exactly one report per packet

MACHINE=${MACHINE:-"Simon-RM-2"}
TARGET=${TARGET:-"172.16.24.31"}
IFACE=${IFACE:-"ens192"}
PING_FLAGS=${PING_FLAGS:-"-Dn -i 0.01 -c 1000"}
EPPING_FLAGS=${EPPING_FLAGS:-"-Cf -r 0 -F ppviz"}

start_epping() {
    local machine=$1
    local save_path=$2
    local iface=${3:-$IFACE}

    echo "${machine}: Settig up ePPing on ${iface}..."

    local cmd="mkdir -p $save_path; cd bpf-examples/pping; "
    cmd+="sudo nohup ./pping -i $IFACE $EPPING_FLAGS > ../../${save_path}/pping.out 2> ../../${save_path}/pping.err &"
    ssh $machine "$cmd"
    sleep 2 # Give pping some time to set up
}

stop_epping() {
    local machine=$1
    local iface=${2:-$IFACE}

    echo "${machine}: Stopping ePPing on $iface"
    ssh $machine "sudo pkill -f 'pping -i $iface'"
}

run_ping() {
    local machine=$1
    local target=$2
    local save_path=$3
    local ping_flags=${4:-$PING_FLAGS}

    echo "Pinging ${target} from ${machine}..."
    ssh $machine "mkdir -p $save_path; sudo ping $target $ping_flags > ${save_path}/ping.out 2> ${save_path}/ping.err"
}

copy_back_results() {
    local machine=$1
    local save_path=$2

    echo "Transfering results from ${machine}:${save_path} to local machine"

    if [[ $3 == "compress" ]]; then
	ssh $machine "xz -T0 ${save_path}/*"
    fi

    mkdir -p $save_path
    scp -p ${machine}:${save_path}/* $save_path && ssh $machine "rm -r $save_path"
}

currtime=$(date +%Y-%m-%dT%H%M%S)
base_path=${1}/${currtime}
n_runs=${2:-1}

for (( i = 1; i <= $n_runs; i++)); do
    if (( $n_runs > 1)); then
	save_path=${base_path}/run_${i}
	echo -e "\n\nRun $i"
    else
	save_path=$base_path
    fi

    start_epping $MACHINE $save_path
    run_ping $MACHINE $TARGET $save_path
    stop_epping $MACHINE
    copy_back_results $MACHINE $save_path "compress"
done

