#!/bin/bash

# $1 = root folder
# $2 = runs

N_FLOWS=(1 5 10 100 500)

for (( i=1; i <= $2; i++)); do
    for flows in ${N_FLOWS[@]}; do
	for pping in no_pping k_pping e_pping; do
	    for VM in VM1 VM2 VM3; do
		xz ${1}/run_${i}/${flows}_streams/${pping}/${VM}/*
	    done
	done
    done
done
