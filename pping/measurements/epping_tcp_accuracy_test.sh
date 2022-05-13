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
IPERF3_FLAGS=${IPERF3_FLAGS:-"-t 10 -Z --fq-rate 1g"}

EPPING_FLAGS=${EPPING_FLAGS:-"-r 0 -I xdp -f -F ppviz"}

END_WITH_DELAYED_PING=${END_WITH_DELAYED_PING:-false}

NETEM_DELAYS=("0ms 1ms 5ms 10ms 50ms 100ms 200ms 500ms 1000ms")
NETEM_MACHINE=$M3
NETEM_IFACE=${NETEM_IFACE:-"enp1s0f1np1"}
TCPDUMP_ARGS="-s 96"

INTERTEST_INTERVAL=${INTERTEST_INTERVAL:-10} #sec
ADD_DATETIME_SUBPATH=${ADD_DATETIME_SUBPATH:-true}

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

start_tcpdump() {
    local machine=$1
    local savepath=$2
    local iface=${3:-$IFACE}
    local tcpdump_args=${4:-$TCPDUMP_ARGS}

    local CMD="mkdir -p $savepath; "
    CMD+="TZ=UTC sudo nohup tcpdump -i $iface -w ${savepath}/packetdump.pcap $tcpdump_args > ${savepath}/tcpdump_info.txt 2>&1 &"

    echo "${MACHINE_NAMES[$machine]}: Starting tcpdump with args: $tcpdump_args"
    ssh ${MACHINE_NAMES[$machine]} "$CMD"
}

stop_tcpdump() {
    local machine=$1
    local iface=${2:-$IFACE}

    echo "${MACHINE_NAMES[$machine]}: Stopping tcpdump -i $iface"
    ssh ${MACHINE_NAMES[$machine]} "sudo pkill -f 'tcpdump -i $iface'"
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
    start_tcpdump "M2" $1 $IFACE

    sleep 2 # Give the monitoring some time to set up
}

stop_system_monitoring() {
    for M in "M1" "M2" "M3"; do
        stop_sar $M
    done

    stop_tcp_monitoring "M1"
    stop_tcpdump "M2" $IFACE
}

setup_netem() {
    local machine=$1
    local iface=${2:-$NETEM_IFACE}
    local netem_args=${3:-$NETEM_ARGS}

    echo "${machine}: Setting up netem $netem_args on dev $iface"
    ssh $machine "sudo tc qdisc add dev $iface root netem $netem_args"
}

teardown_netem() {
    local machine=$1
    local iface=${2:-$NETEM_IFACE}

    echo "${machine}: Removing netem from dev ${iface}"
    ssh $machine "sudo tc qdisc del dev $iface root netem"
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

    if [[ "$END_WITH_DELAYED_PING" == true ]]; then
	CMD+="; sleep 1; sudo nping --tcp-connect -c 1 $IP_TARGET > /dev/null"
    fi

    ssh $M1 "$CMD"
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

run_test() {
    # $1 = save path
    # $2 = n streams

    mkdir -p $1

    start_iperf3_servers
    start_system_monitoring $1

    run_iperf3_clients $1 $2

    sleep 1

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

basepath=$1
n_flows=${2:-1}

if (( $n_flows > 128 * $CPU_CORES )); then
    echo "Error - cannot create $n_flows concurrent flows with just $CPU_CORES instances of iperf3"
    exit 1
fi

if [[ "$ADD_DATETIME_SUBPATH" == true ]]; then
   currtime=$(date +%Y-%m-%dT%H%M%S)
   basepath=${basepath}/${currtime}
fi

for delay in ${NETEM_DELAYS[@]}; do
    setup_netem $NETEM_MACHINE $NETEM_IFACE "delay $delay limit 1000000"

    echo -e "\n\nRunning test with delay=${delay}"
    currpath="${basepath}/delay_${delay}/e_pping"
    start_epping $currpath
    run_test $currpath $n_flows
    stop_epping

    teardown_netem $NETEM_MACHINE $NETEM_IFACE

    copy_back_results $currpath
    IFACE=$IFACE OMIT=0 ./plot_results.sh "${basepath}/delay_${delay}" $IP_TARGET

    sleep $INTERTEST_INTERVAL
done
