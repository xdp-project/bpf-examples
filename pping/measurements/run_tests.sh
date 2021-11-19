#!/bin/bash

# A very shitty and fragile script to run some simple iperf3 tests from VM1->VM3
# without pping, with Kathie's pping and with my eBPF pping, collecting some
# simple results and plotting them
# Author: Simon Sundberg

M1=${M1:-"Simon-RM-1"}
M2=${M2:-"Simon-RM-2"}
M3=${M3:-"Simon-RM-3"}

declare -A MACHINE_NAMES=( [M1]=$M1 [M2]=$M2 [M3]=$M3 )

IP_TARGET=${IP_TARGET:-"172.16.24.31"}
IFACE=${IFACE:-"ens192"}

PORT_START=8000
CPU_CORES=4
IPERF_FLAGS="-Z -t 120 -O 60"
KPPING_FLAGS=""
EPPING_FLAGS="-r 0 -I tc -f"
INTERTEST_INTERVAL=${INTERTEST_INTERVAL:-10} #sec

# $1 = path to save results in
# $2 = number of flows

start_mpstat() {
    # $1 machine (M1, M2 or M3)
    # $2 save path

    echo "${MACHINE_NAMES[$1]}: Starting mpstat..."
    ssh ${MACHINE_NAMES[$1]} "mkdir -p $2; TZ=UTC mpstat -P ALL -o JSON 1 > ${2}/${1}_mpstat.json" 2> /dev/null &
    sleep 1
}

stop_mpstat() {
    # $1 machine (M1, M2 or M3)

    echo "${MACHINE_NAMES[$1]}: Stopping mpstat..."
    ssh ${MACHINE_NAMES[$1]} "killall -s SIGINT mpstat"
}

start_iperf_servers() {
    # $1 = save path

    echo "${M3}: Setting up iperf3 servers..."
    
    local CMD=""
    for ((i=0; i < CPU_CORES; i++)); do
	CMD+="iperf3 -s -p $(( PORT_START + i)) > /dev/null & "
    done

    ssh $M3 "$CMD" 2> /dev/null &
    sleep 1

    start_mpstat "M3" $1
}

stop_iperf_servers() {
    stop_mpstat "M3"

    echo "${M3}: Killing iperf3 servers"
    ssh $M3 "killall iperf3"
}

run_iperf_clients() {
    # $1 = save path
    # $2 = n streams

    start_mpstat "M1" $1

    echo "${M1}: Running iperf3 tests..."

    local CMD=""
    for ((i=0; i < CPU_CORES; i++)); do
	local N=$(( ($2 / CPU_CORES) + (i < $2 % CPU_CORES) ))
	if (( N > 0 )); then
	    CMD+="iperf3 -c $IP_TARGET -p $(( PORT_START + i )) -P $N $IPERF_FLAGS --json > ${1}/iperf_${i}.json & "
	fi
    done

    ssh $M1 "$CMD"

    stop_mpstat "M1"
}

start_kpping() {
    # Kathie's pping
    # $1 save path

    echo "${M2}: Setting up Kathie's pping on ${IFACE}..."

    local CMD="mkdir -p $1; "
    CMD+="echo '$M2_PASSWORD' | sudo -Skb TZ=UTC ./pping/pping -i $IFACE $KPPING_FLAGS > ${1}/pping.out 2> ${1}/pping.err"
    ssh $M2 "$CMD"
    sleep 2 # Give pping some time to set up
}

start_epping() {
    # My eBPF pping
    # $1 save path

    echo "${M2}: Settig up eBPF pping on ${IFACE}..."

    local CMD="mkdir -p $1; cd bpf-examples/pping; "
    CMD+="echo '$M2_PASSWORD' | sudo -Skb TZ=UTC ./pping -i $IFACE $EPPING_FLAGS > ../../${1}/pping.out 2> ../../${1}/pping.err"
    ssh $M2 "$CMD"
    sleep 2 # Give pping some time to set up
}

stop_pping() {
    echo "${M2}: Stopping pping..."
    ssh $M2 "echo '$M2_PASSWORD' | sudo -Skb killall -s SIGINT pping" 2> /dev/null
}

run_tests() {
    # $1 = save path
    # $2 = n streams

    start_mpstat "M2" $1
    start_iperf_servers $1
    run_iperf_clients $1 $2
    stop_iperf_servers
    stop_mpstat "M2"
}

copy_back_results() {
    # $1 = save path
    echo "Copying back results to local machine..."

    for M in "M1" "M2" "M3"; do
	mkdir -p ${1}/${M}
	ssh ${MACHINE_NAMES[$M]} "xz ${1}/*"
	scp -p "${MACHINE_NAMES[$M]}:${1}/*" "${1}/${M}/"
	ssh ${MACHINE_NAMES[$M]} "rm -r ${1}"
    done
}

if [[ -z "$M2_PASSWORD" ]]; then
   read -p "M2 password: " -s M2_PASSWORD
fi

echo "Running test with no pping..."
SPATH="${1}/no_pping"
run_tests $SPATH $2
copy_back_results $SPATH

sleep $INTERTEST_INTERVAL

echo -e "\n\nRunning test with Kathie's pping..."
SPATH="${1}/k_pping"
start_kpping $SPATH
run_tests $SPATH $2
stop_pping
copy_back_results $SPATH

sleep $INTERTEST_INTERVAL

echo -e "\n\nRunning test with my eBPF pping..."
SPATH="${1}/e_pping"
start_epping $SPATH
run_tests $SPATH $2
stop_pping
copy_back_results $SPATH

./plot_results.sh $1
