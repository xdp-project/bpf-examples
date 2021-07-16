#!/bin/env python3
import numpy as np
import matplotlib.pyplot as plt
import os
import argparse


import common_plotting as complot
import mpstat_viz
import iperf_viz

def load_cpu_data(root_folder):
    load_dict = dict()
    for pping_type in ("no_pping", "k_pping", "e_pping"):
        j_data = mpstat_viz.load_mpstat_json(os.path.join(root_folder, pping_type, 
                                                          "VM2", "VM2_mpstat.json"))
        data = mpstat_viz.trim_only_under_load(mpstat_viz.to_percpu_df(j_data))
        load_dict[pping_type] = data["all"].copy()
    return load_dict


def load_iperf_data(root_folder):
    net_dict = dict()
    for pping_type in ("no_pping", "k_pping", "e_pping"):
        dpath = os.path.join(root_folder, pping_type, "VM1")
        iperf_data = []
        
        for iperf_file in os.listdir(dpath):
            if iperf_file.startswith("iperf") and iperf_file.endswith(".json"):
                j_data = iperf_viz.load_iperf3_json(os.path.join(dpath, iperf_file))
                iperf_data.append(iperf_viz.to_perstream_df(j_data, include_total=False))
                
        net_dict[pping_type] = iperf_viz.merge_iperf_data(*iperf_data)["all"].copy()
        
    return net_dict

def main():
    parser = argparse.ArgumentParser("Plot graphs comparing the performance overhead of pping versions")
    parser.add_argument("-i", "--input", type=str, help="root folder of the results from run_tests.sh", required=True)
    parser.add_argument("-o", "--output", type=str, help="image output file")
    args = parser.parse_args()

    cpu_data = load_cpu_data(args.input)
    iperf_data = load_iperf_data(args.input)

    fig, axes = plt.subplots(2, 1, figsize=(8, 10), constrained_layout=True)

    mpstat_viz.plot_percpu_timeseries(cpu_data, axes=axes[0])
    iperf_viz.plot_throughput_timeseries(iperf_data, axes=axes[1])
    fig.suptitle("Comparing performance of pping variants")

    if args.output is not None:
        fig.savefig(args.output, bbox_inches="tight");
    else:
        plt.show()

    return

if __name__ == "__main__":
    main()
