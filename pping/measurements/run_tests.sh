#!/bin/bash

# A very shitty and fragile script to run some simple iperf3 tests from VM1->VM3
# without pping, with Kathie's pping and with my eBPF pping, collecting some
# simple results and plotting them
# Author: Simon Sundberg

M1=${M1:-"testbed-40g-01"}
M2=${M2:-"testbed-lenovo"}
M3=${M3:-"testbed-40g-02"}

declare -A MACHINE_NAMES=( [M1]=$M1 [M2]=$M2 [M3]=$M3 )

IP_TARGET=${IP_TARGET:-"10.70.2.2"}
IFACE=${IFACE:-"ens3f1"}

PORT_START=${PORT_START:-8000}
CPU_CORES=${CPU_CORES:-8}
IPERF3_FLAGS=${IPERF3_FLAGS:-"-Z -t 180"}
KPPING_FLAGS=${KPPING_FLAGS:-"--sumInt 1"}
EPPING_FLAGS=${EPPING_FLAGS:-"-r 0 -I xdp -f"}
INTERTEST_INTERVAL=${INTERTEST_INTERVAL:-10} #sec

export MPLBACKEND=agg

# $1 = path to save results in
# $2 = number of flows

start_sar() {
    # $1 machine (M1, M2 or M3)
    # $2 save path

    echo "${MACHINE_NAMES[$1]}: Starting sar..."
    ssh ${MACHINE_NAMES[$1]} "mkdir -p $2; TZ=UTC nohup sar -o ${2}/${1}_stats.sar 1 > /dev/null 2>&1 &"
}

stop_sar() {
    # $1 machine (M1, M2 or M3)

    echo "${MACHINE_NAMES[$1]}: Stopping sar..."
    ssh ${MACHINE_NAMES[$1]} 'pkill -u $(whoami) -f "sar -o .*_stats.sar"'
}

start_tcp_monitoring() {
    # $1 = machine (M1, M2 or M3)
    # $2 = save path
    # $3 = interval

    local INTERVAL=${3:-1}
    local CMD="mkdir -p $2;"
    CMD+=" watch -pn $INTERVAL "\""(TZ=UTC date +%Y-%m-%dT%H:%M:%S; ss -tinHO) >> ${2}/ss_tcp.log"\"" &> /dev/null"

    echo "${MACHINE_NAMES[$1]}: Starting TCP monitoring (periodic ss -ti)..."
    ssh -tt ${MACHINE_NAMES[$1]} "$CMD" &
}

stop_tcp_monitoring() {
    # $1 = machine (M1, M2 or M3)

    echo "${MACHINE_NAMES[$1]}: Stopping tcp monitoring..."
    ssh ${MACHINE_NAMES[$1]} 'pkill -u $(whoami) -f "watch.* ss -ti"'
}

start_system_monitoring() {
    #$1 = save path
    for M in "M1" "M2" "M3"; do
        start_sar $M $1
    done

    start_tcp_monitoring "M1" $1

    sleep 2 # Give the monitoring some time to set up
}

stop_system_monitoring() {
    for M in "M1" "M2" "M3"; do
        stop_sar $M
    done

    stop_tcp_monitoring "M1"
}

start_iperf3_servers() {
    echo "${M3}: Setting up iperf3 servers..."

    local CMD=""
    for ((i=0; i < CPU_CORES; i++)); do
        CMD+="nohup iperf3 -s -p $(( PORT_START + i)) > /dev/null 2>&1 & "
    done

    ssh $M3 "$CMD"
    sleep 1
}

stop_iperf3_servers() {
    echo "${M3}: Killing iperf3 servers"
    ssh $M3 'pkill -u $(whoami) -f "iperf3 -s"'
}

run_iperf3_clients() {
    # $1 = save path
    # $2 = n streams

    echo "${M1}: Running iperf3 tests..."

    local CMD="mkdir -p $1; echo "\""Start: \$(TZ=UTC date -Iseconds)"\"" > ${1}/test_interval.log; "
    for ((i=0; i < CPU_CORES; i++)); do
        local N=$(( ($2 / CPU_CORES) + (i < $2 % CPU_CORES) ))
        if (( N > 0 )); then
            CMD+="iperf3 -c $IP_TARGET -p $(( PORT_START + i )) -P $N $IPERF3_FLAGS --json > ${1}/iperf_${i}.json & "
        fi
    done

    CMD=${CMD%' & '}
    CMD+="; echo "\""End: \$(TZ=UTC date -Iseconds)"\"" >> ${1}/test_interval.log"

    ssh $M1 "$CMD"
}

start_kpping() {
    # Kathie's pping
    # $1 save path

    echo "${M2}: Setting up Kathie's pping on ${IFACE}..."

    local CMD="mkdir -p $1; "
    CMD+="TZ=UTC sudo nohup taskset -c 0 ./pping/pping -i $IFACE $KPPING_FLAGS > ${1}/pping.out 2> ${1}/pping.err &"
    ssh $M2 "$CMD"
    sleep 2 # Give pping some time to set up
}

start_epping() {
    # My eBPF pping
    # $1 save path

    echo "${M2}: Settig up eBPF pping on ${IFACE}..."

    local CMD="mkdir -p $1; cd bpf-examples/pping; "
    CMD+="TZ=UTC sudo nohup taskset -c 0 ./pping -i $IFACE $EPPING_FLAGS > ../../${1}/pping.out 2> ../../${1}/pping.err &"
    ssh $M2 "$CMD"
    sleep 2 # Give pping some time to set up
}

stop_epping() {
    echo "${M2}: Stopping pping..."
    ssh $M2 "sudo pkill --signal SIGINT -f 'pping -i $IFACE'"
}

stop_kpping() {
    echo "${M2}: Stopping pping..."
    ssh $M2 "sudo pkill -f 'pping -i $IFACE'"
}

run_test() {
    # $1 = save path
    # $2 = n streams

    mkdir -p $1

    start_iperf3_servers
    start_system_monitoring $1

    run_iperf3_clients $1 $2

    stop_system_monitoring
    stop_iperf3_servers
}

copy_back_results() {
    # $1 = save path
    echo "Copying back results to local machine..."

    for M in "M1" "M2" "M3"; do
        mkdir -p ${1}/${M}
        ssh ${MACHINE_NAMES[$M]} "xz -T0 ${1}/*"
        scp -p "${MACHINE_NAMES[$M]}:${1}/*" "${1}/${M}/"
        ssh ${MACHINE_NAMES[$M]} "rm -r ${1}"
    done

    xz -d ${1}/M1/test_interval.log.xz
    mv ${1}/M1/test_interval.log -t $1
}

if (( $2 > 128 * $CPU_CORES )); then
    echo "Error - cannot create $2 concurrent flows with just $CPU_CORES instances of iperf3"
    exit 1
fi

echo "Running test with no pping..."
SPATH="${1}/no_pping"
run_test $SPATH $2
copy_back_results $SPATH

sleep $INTERTEST_INTERVAL

echo -e "\n\nRunning test with Kathie's pping..."
SPATH="${1}/k_pping"
start_kpping $SPATH
run_test $SPATH $2
stop_kpping
copy_back_results $SPATH

sleep $INTERTEST_INTERVAL

echo -e "\n\nRunning test with my eBPF pping..."
SPATH="${1}/e_pping"
start_epping $SPATH
run_test $SPATH $2
stop_epping
copy_back_results $SPATH

IFACE=$IFACE ./plot_results.sh $1 $IP_TARGET
