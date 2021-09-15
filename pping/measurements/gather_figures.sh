#!/bin/bash

# $1 = root folder
# $2 = runs

N_FLOWS=(1 5 10 100 500)
DESTDIR=${1}/comparison_figures

mkdir $DESTDIR

for (( i=1; i <= $2; i++)); do
    for flows in ${N_FLOWS[@]}; do
	SRCDIR=${1}/run_${i}/${flows}_streams
	SUFFIX=${flows}_flows_run_${i}
	cp "${SRCDIR}/pping_comparison.png" "${DESTDIR}/pping_comparison_${SUFFIX}.png"
	cp "${SRCDIR}/epping_mapcleaning.png" "${DESTDIR}/mapcleaning_${SUFFIX}.png"
    done
done
