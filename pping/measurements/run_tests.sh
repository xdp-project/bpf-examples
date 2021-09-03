#!/bin/bash

# A very shitty and fragile script to run some simple iperf3 tests from VM1->VM3
# without pping, with Kathie's pping and with my eBPF pping, collecting some
# simple results and plotting them
# Author: Simon Sundberg

PORT_START=8000
CPU_CORES=4
IPERF_FLAGS="-Z -t 100"
IP_TARGET="172.16.24.31"
IFACE="ens192"
KPPING_FLAGS=""
EPPING_FLAGS="-r 0 -I tc -f"
#PATH_PREFIX="pping_testing"

# $1 = path to save results in
# $2 = number of flows

start_mpstat() {
    # $1 VM nr
    # $2 save path

    echo "VM${1}: Starting mpstat..."
    ssh Simon-VM-${1} "mkdir -p $2; mpstat -P ALL -o JSON 1 > ${2}/VM${1}_mpstat.json" 2> /dev/null &
    sleep 1
}

stop_mpstat() {
    # $1 = VM nr
    echo "VM${1}: Stopping mpstat..."
    ssh Simon-VM-${1} "killall -s SIGINT mpstat"
}

start_iperf_servers() {
    # $1 = save path

    echo "VM3: Setting up iperf3 servers..."
    
    local CMD=""
    for ((i=0; i < CPU_CORES; i++)); do
	CMD+="iperf3 -s -p $(( PORT_START + i)) > /dev/null & "
    done

    ssh Simon-VM-3 "$CMD" 2> /dev/null &
    sleep 1

    start_mpstat 3 $1
}

stop_iperf_servers() {
    stop_mpstat 3

    echo "VM3: Killing iperf3 servers"
    ssh Simon-VM-3 "killall iperf3"
}

run_iperf_clients() {
    # $1 = save path
    # $2 = n streams

    start_mpstat 1 $1

    echo "VM1: Running iperf3 tests..."

    local CMD=""
    for ((i=0; i < CPU_CORES; i++)); do
	local N=$(( ($2 / CPU_CORES) + (i < $2 % CPU_CORES) ))
	if (( N > 0 )); then
	    CMD+="iperf3 -c $IP_TARGET -p $(( PORT_START + i )) -P $N $IPERF_FLAGS --json > ${1}/iperf_${i}.json & "
	fi
    done

    ssh Simon-VM-1 "$CMD"

    stop_mpstat 1
}

start_kpping() {
    # Kathie's pping
    # $1 save path

    echo "VM2: Setting up Kathie's pping on ${IFACE}..."

    local CMD="mkdir -p $1; "
    CMD+="echo '$VM_PASSWORD' | sudo -Skb ./pping/pping -i $IFACE $KPPING_FLAGS > ${1}/pping.out 2> ${1}/pping.err"
    ssh Simon-VM-2 "$CMD"
    sleep 2 # Give pping some time to set up
}

start_epping() {
    # My eBPF pping
    # $1 save path

    echo "VM2: Settig up eBPF pping on ${IFACE}..."

    local CMD="mkdir -p $1; cd bpf-examples/pping; "
    CMD+="echo '$VM_PASSWORD' | sudo -Skb ./pping -i $IFACE $EPPING_FLAGS > ../../${1}/pping.out 2> ../../${1}/pping.err"
    ssh Simon-VM-2 "$CMD"
    sleep 2 # Give pping some time to set up
}

stop_pping() {
    echo "VM2: Stopping pping..."
    ssh Simon-VM-2 "echo '$VM_PASSWORD' | sudo -Skb killall -s SIGINT pping" 2> /dev/null
}

run_tests() {
    # $1 = save path
    # $2 = n streams

    start_mpstat 2 $1
    start_iperf_servers $1
    run_iperf_clients $1 $2
    stop_iperf_servers
    stop_mpstat 2
}

copy_back_results() {
    # $1 = save path
    echo "Copying back results to local machine..."

    for (( i = 1; i < 4; i++ )); do
	mkdir -p ${1}/VM${i}
	scp -p "Simon-VM-${i}:${1}/*" "${1}/VM${i}/"
	ssh Simon-VM-${i} "rm -r ${1}"
    done
}

if [[ -z "$VM_PASSWORD" ]]; then
   read -p "VM2 password:" -s VM_PASSWORD
fi

echo "Running test with no pping..."
SPATH="${1}/no_pping"
run_tests $SPATH $2
copy_back_results $SPATH

echo -e "\n\nRunning test with Kathie's pping..."
SPATH="${1}/k_pping"
start_kpping $SPATH
run_tests $SPATH $2
stop_pping
copy_back_results $SPATH

echo -e "\n\nRunning test with my eBPF pping..."
SPATH="${1}/e_pping"
start_epping $SPATH
run_tests $SPATH $2
stop_pping
copy_back_results $SPATH

#TODO plotting...
