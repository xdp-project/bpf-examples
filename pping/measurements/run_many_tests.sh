#!/bin/bash

N_FLOWS=(1 5 10 100 500)

# $1 = path to save results in
# $2 = number of times to repeat the tests

if [[ -z "$VM_PASSWORD" ]]; then
    read -p "VM2 password:" -s VM_PASSWORD
    export VM_PASSWORD
fi

echo -e "\n"

for (( i = 1; i <= $2; i++ )); do
    echo -e "Starting run $i \n\n"

    for flows in ${N_FLOWS[@]}; do
	echo -e "Run test with $flows flows\n"

	SPATH="${1}/run_${i}/${flows}_streams"
	./run_tests.sh $SPATH $flows
	./plot_results.sh $SPATH
    done
done
