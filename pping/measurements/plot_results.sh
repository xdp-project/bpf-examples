#!/bin/bash

# Plot the results from run_tests.sh
# Assumes files have same names and folder layout as generated by run_tests.sh

# $1 = root folder

echo "Plotting comparsion graphs..."
./pping_compare_viz.py -i $1 -o ${1}/pping_comparison.png

echo "Plotting eBPF pping map cleaning and lost events..."
./pping_err_viz.py -i ${1}/e_pping/VM2/pping.err -o ${1}/epping_mapcleaning.png -T "Map cleaning and lost events"


for pping in no_pping k_pping e_pping; do
    echo -e "\nPlotting results for ${1}/${pping}..."

    echo "Plotting CPU load..."
    for (( i = 1; i < 4; i++ )); do
	./mpstat_viz.py -i ${1}/${pping}/VM${i}/VM${i}_mpstat.json -o ${1}/VM${i}_cpu_${pping}.png -t -T "VM${i} cpu load $pping"
    done

    echo "Plotting iperf traffic..."
    IPERF_INPUT=""
    for iperf_file in ${1}/${pping}/VM1/iperf*.json; do
	IPERF_INPUT+="-i $iperf_file "
    done
    ./iperf_viz.py $IPERF_INPUT -o ${1}/network_throughput_${pping}.png -T "Iperf traffic $pping"
done

echo -e "\nDone"
