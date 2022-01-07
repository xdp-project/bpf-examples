#!/bin/bash

# $1 = root folder

root_folder=${1:-"."}
dest_dir=${root_folder}/comparison_figures

mkdir -p $dest_dir

for run_dir in ${root_folder}/run_*; do
    run=${run_dir#"${root_folder}/run_"}
    for flow_dir in $run_dir/*_streams; do
        flows=${flow_dir#"${run_dir}/"}
        flows=${flows%"_streams"}
        suffix="${flows}_flows_run_${run}"

        for image_name in "pping_comparison" "epping_mapcleaning"; do
            cp "${flow_dir}/${image_name}.png" "${dest_dir}/${image_name}_${suffix}.png"
        done

    done
done

