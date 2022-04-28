#!/bin/bash

N_FLOWS=(1 10 100 1000)
IFACE=${IFACE:-"ens3f1"}
IP_TARGET=${IP_TARGET:-"10.70.2.2"}
OMIT=${OMIT:-60}
INTERTEST_INTERVAL=${INTERTEST_INTERVAL:-10} #sec
export IFACE
export IP_TARGET
export OMIT
export INTERTEST_INTERVAL
export MPLBACKEND=agg

ADD_DATETIME_SUBPATH=${ADD_DATETIME_SUBPATH:-true}

# $1 = path to save results in
# $2 = number of times to repeat the tests

basepath=$1
if [[ "$ADD_DATETIME_SUBPATH" == true ]]; then
   currtime=$(date +%Y-%m-%dT%H%M%S)
   basepath=${basepath}/${currtime}
fi

for (( i = 1; i <= $2; i++ )); do
    echo -e "\n\nStarting run $i \n\n"

    for flows in ${N_FLOWS[@]}; do
        echo -e "\nRun test with $flows flows\n"

        SPATH="${basepath}/run_${i}/${flows}_streams"
        ./run_tests.sh $SPATH $flows
        sleep $INTERTEST_INTERVAL
    done
done

echo -e "\nPlotting summarized statistics for all runs..."
./pping_summarize_viz.py -i $basepath -s $IP_TARGET -I $IFACE -O $OMIT
echo "Done!"
