#!/bin/bash

# A script meant to test at what point Kathie's PPing starts missing packets
# Author: Simon Sundberg

BASE_IPERF3_FLAGS=${BASE_IPERF3_FLAGS:-"-Z -t 60"}
RATES=(100m 500m 1g 2g 3g 3.1g 3.2g 3.3g 3.4g 3.5g 3.6g 3.7g 3.8g 3.9g 4g 5g 6g 7g 8g 9g 10g)

export MPLBACKEND=agg
export RUN_BASELINE=false
export RUN_KPPING=true
export RUN_EPPING=false
export END_WITH_DELAYED_PING=true
export OMIT=0

ADD_DATETIME_SUBPATH=${ADD_DATETIME_SUBPATH:-true}

basepath=$1
n_flows=${2:-1}

if [[ "$ADD_DATETIME_SUBPATH" == true ]]; then
   currtime=$(date +%Y-%m-%dT%H%M%S)
   basepath=${basepath}/${currtime}
fi

export ADD_DATETIME_SUBPATH=false

for rate in ${RATES[@]}; do

    echo -e "\n Running tests with rate=${rate}"

    IPERF3_FLAGS="$BASE_IPERF3_FLAGS --fq-rate $rate"
    export IPERF3_FLAGS
    
    rate_dir="${basepath}/rate_${rate}"

    ./run_tests.sh $rate_dir $n_flows
done

