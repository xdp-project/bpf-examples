#!/bin/bash

N_FLOWS=(1 10 100 500)
INTERTEST_INTERVAL=${INTERTEST_INTERVAL:-10} #sec

# $1 = path to save results in
# $2 = number of times to repeat the tests

if [[ -z "$M2_PASSWORD" ]]; then
    read -p "M2 password: " -s M2_PASSWORD
    export M2_PASSWORD
fi

echo -e "\n"

for (( i = 1; i <= $2; i++ )); do
    echo -e "Starting run $i \n\n"

    for flows in ${N_FLOWS[@]}; do
	echo -e "Run test with $flows flows\n"

	SPATH="${1}/run_${i}/${flows}_streams"
	./run_tests.sh $SPATH $flows
	sleep $INTERTEST_INTERVAL
    done
done

echo -e "\nPlotting summarized statistics for all runs..."
./pping_summarize_viz.py $1
echo "Done!"
