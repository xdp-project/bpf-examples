#!/bin/bash

# Test ePPing performance with various r-values (timestamp rate limits)

EPPING_BASE_ARGS="-I xdp -f"
R_VALUES=(0 10 100 1000)

ADD_DATETIME_SUBPATH=${ADD_DATETIME_SUBPATH:-true}

# $1 = path to save results in
# $2 = number of times to repeat the tests

export RUN_BASELINE=false
export RUN_KPPING=false
export RUN_EPPING=true

basepath=$1
reps=${2:-3}

if [[ "$ADD_DATETIME_SUBPATH" == true ]]; then
   currtime=$(date +%Y-%m-%dT%H%M%S)
   basepath=${basepath}/${currtime}
fi

export ADD_DATETIME_SUBPATH=false

for r in ${R_VALUES[@]}; do
    echo -e "\n Running tests with r=${r}"
    
    export EPPING_FLAGS="$EPPING_BASE_ARGS -r $r"
    r_dir="${basepath}/r_${r}"
    ./run_many_tests.sh $r_dir $reps
done
