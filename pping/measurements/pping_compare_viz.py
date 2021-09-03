#!/bin/env python3
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import math
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

def parse_timestamp(t_str):
    """
    Returns seconds since start of day
    """
    h_m_s = t_str.split(":")
    return float(h_m_s[0]) * 3600 + float(h_m_s[1]) * 60 + float(h_m_s[2])

def count_epping_messages(file_name, src_ip="172.16.24.31"):
    """
    Count nr of rtt-events per second from the standard output of eBPF pping.
    The columns "filtered_rtt_events" is rtt-events from src_ip
    The column "all_events" includes both rtt-events and flow-events

    NOTE: Assumes all events in file_name are from the same day
    """
    t_off = None

    count = {"ts":[0], "rtt_events":[0], "filtered_rtt_events":[0], "all_events":[0]}

    with open(file_name) as file:
        for line in file:
            words = line.split()
            if len(words) < 7:
                continue

            if t_off is None:
                t_off = parse_timestamp(words[0])

            t = max(0, math.floor(parse_timestamp(words[0]) - t_off))

            if t > count["ts"][-1]:
                for missing_t in range(count["ts"][-1], t):
                    count["ts"].append(missing_t+1)
                    for key, count_vals in count.items():
                        if key != "ts":
                            count_vals.append(0)

            count["all_events"][t] += 1
            if words[2] == "ms":
                count["rtt_events"][t] += 1
                if words[-1].split(":")[0] == src_ip:
                    count["filtered_rtt_events"][t] += 1

    return pd.DataFrame(count)

def count_kpping_messages(file_name, src_ip="172.16.24.31"):
    """
    Count nr of rtt-events per second from the standard output of Kathie's pping.
    The columns "filtered_rtt_events" is rtt-events from src_ip

    NOTE: Assumes all events in file_name are from the same day
    """
    t_off = None

    count = {"ts":[0], "rtt_events":[0], "filtered_rtt_events":[0]}

    with open(file_name) as file:
        for i, line in enumerate(file):
            words = line.split()
            if len(words) != 4:
                continue

            if t_off is None:
                t_off = parse_timestamp(words[0])

            t = max(0, math.floor(parse_timestamp(words[0]) - t_off))

            if t > count["ts"][-1]:
                for missing_t in range(count["ts"][-1], t):
                    count["ts"].append(missing_t+1)
                    for key, count_vals in count.items():
                        if key != "ts":
                            count_vals.append(0)

            count["rtt_events"][t] += 1
            if words[-1].split(":")[0] == src_ip:
                count["filtered_rtt_events"][t] += 1

    return pd.DataFrame(count)

def plot_pping_output(kpping_data, epping_data, axes=None, grid=True):
    if axes is None:
        axes = plt.gca()

    axes.plot(kpping_data["ts"], kpping_data["rtt_events"], c="C1", ls="-", label="k_pping")
    axes.plot(kpping_data["ts"], kpping_data["filtered_rtt_events"], c="C1", ls="--", label="k_pping filtered")

    axes.plot(epping_data["ts"], epping_data["rtt_events"], c="C2", ls="-", label="e_pping")
    axes.plot(epping_data["ts"], epping_data["filtered_rtt_events"], c="C2", ls="--", label="e_pping filtered")

    axes.set_ylim(0)
    axes.set_xlabel("Time (s)")
    axes.set_ylabel("Events per second")
    axes.grid(grid)
    axes.legend()

    return axes

def main():
    parser = argparse.ArgumentParser("Plot graphs comparing the performance overhead of pping versions")
    parser.add_argument("-i", "--input", type=str, help="root folder of the results from run_tests.sh", required=True)
    parser.add_argument("-o", "--output", type=str, help="image output file")
    args = parser.parse_args()

    cpu_data = load_cpu_data(args.input)
    iperf_data = load_iperf_data(args.input)

    epping_messages = count_epping_messages(os.path.join(args.input, "e_pping", "VM2", "pping.out"))
    kpping_messages = count_kpping_messages(os.path.join(args.input, "k_pping", "VM2", "pping.out"))

    fig, axes = plt.subplots(3, 1, figsize=(8, 15), constrained_layout=True)

    mpstat_viz.plot_percpu_timeseries(cpu_data, axes=axes[0])
    iperf_viz.plot_throughput_timeseries(iperf_data, axes=axes[1])
    plot_pping_output(kpping_messages, epping_messages, axes=axes[2])
    fig.suptitle("Comparing performance of pping variants")

    if args.output is not None:
        fig.savefig(args.output, bbox_inches="tight");
    else:
        plt.show()

    return

if __name__ == "__main__":
    main()
