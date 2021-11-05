#!/bin/env python3

import pandas as pd
import matplotlib.pyplot as plt
import os
import argparse

import common_plotting as complot
import pping_compare_viz as pping_comp
import util

label_folder_map = {"baseline": "no_pping", "PPing": "k_pping", "ePPing": "e_pping"}


def read_all_cpu_data(root_folder):
    all_data = dict()
    path = root_folder
    for run in os.listdir(root_folder):
        path = os.path.join(root_folder, run)
        if run.startswith("run_") and os.path.isdir(path):

            for n_streams in os.listdir(path):
                path = os.path.join(root_folder, run, n_streams)
                if n_streams.endswith("_streams") and os.path.isdir(path):
                    if n_streams not in all_data:
                        all_data[n_streams] = {setup: list() for setup in
                                               label_folder_map.keys()}

                    data = pping_comp.load_cpu_data(path)
                    for setup, sdata in data.items():
                        all_data[n_streams][setup].append(
                            sdata[["timestamp", "total"]])

    for stream_data in all_data.values():
        for setup in stream_data.keys():
            stream_data[setup] = pd.concat(
                stream_data[setup]).reset_index(drop=True)
    return all_data


def read_all_iperf_data(root_folder):
    all_data = dict()
    path = root_folder
    for run in os.listdir(root_folder):
        path = os.path.join(root_folder, run)
        if run.startswith("run_") and os.path.isdir(path):

            for n_streams in os.listdir(path):
                path = os.path.join(root_folder, run, n_streams)
                if n_streams.endswith("_streams") and os.path.isdir(path):
                    if n_streams not in all_data:
                        all_data[n_streams] = {setup: list() for setup in
                                               label_folder_map.keys()}

                    data = pping_comp.load_iperf_data(path)
                    for setup, sdata in data.items():
                        all_data[n_streams][setup].append(sdata)

    for stream_data in all_data.values():
        for setup in stream_data.keys():
            stream_data[setup] = pd.concat(
                stream_data[setup]).reset_index(drop=True)
    return all_data


def read_all_rtt_reports(root_folder):
    all_data = dict()
    path = root_folder
    for run in os.listdir(root_folder):
        path = os.path.join(root_folder, run)
        if run.startswith("run_") and os.path.isdir(path):

            for n_streams in os.listdir(path):
                path = os.path.join(root_folder, run, n_streams)
                if n_streams.endswith("_streams") and os.path.isdir(path):
                    if n_streams not in all_data:
                        all_data[n_streams] = {"PPing": list(), "ePPing": list()}

                    all_data[n_streams]["PPing"].append(
                        pping_comp.count_kpping_messages(path))

                    all_data[n_streams]["ePPing"].append(
                        pping_comp.count_epping_messages(path))

    for stream_data in all_data.values():
        for setup in stream_data.keys():
            stream_data[setup] = pd.concat(
                stream_data[setup]).reset_index(drop=True)
    return all_data


def plot_summarized_cpu_util(stream_data):
    fig, axes = plt.subplots(2, 1, figsize=(8, 9), constrained_layout=True)
    complot.plot_pergroup_cdf(stream_data, "total",
                              axes=axes[0], print_stats=True)
    complot.plot_pergroup_histogram(
        stream_data, "total", axes=axes[1], print_stats=False)
    axes[1].set_xlabel("CPU utalalization (%)")

    fig.canvas.draw()
    fig.canvas.draw()

    return fig, axes


def plot_summarized_network(stream_data):
    fig, axes = plt.subplots(2, 3, figsize=(24, 9), constrained_layout=True)

    complot.plot_pergroup_cdf(stream_data, "throughput", axes=axes[0, 0],
                              print_stats=True, stat_kwargs={"fmt": "{:.4e}"})
    complot.plot_pergroup_histogram(stream_data, "throughput", axes=axes[1, 0],
                                    print_stats=False)
    axes[1, 0].set_xlabel("Throughput (Bbps)")

    complot.plot_pergroup_cdf(stream_data, "rtt", axes=axes[0, 1],
                              print_stats=True)
    complot.plot_pergroup_histogram(stream_data, "rtt", axes=axes[1, 1],
                                    print_stats=False)
    axes[1, 1].set_xlabel("RTT (ms)")

    complot.plot_pergroup_cdf(stream_data, "retrans", axes=axes[0, 2],
                              print_stats=True)
    complot.plot_pergroup_histogram(stream_data, "retrans", axes=axes[1, 2],
                                    print_stats=False)
    axes[1, 2].set_xlabel("Retransmissions / s")

    fig.canvas.draw()
    fig.canvas.draw()

    return fig, axes


def plot_summarized_reports(stream_data):
    fig, axes = plt.subplots(2, 2, figsize=(16, 9), constrained_layout=True)

    axes[0, 0].plot([], [])  # Dummy - use up one color cycle
    complot.plot_pergroup_cdf(stream_data, "rtt_events", axes=axes[0, 0],
                              print_stats=True, stat_kwargs={"fmt": "{:.4e}"})
    axes[1, 0].plot([], [])
    complot.plot_pergroup_histogram(stream_data, "rtt_events", axes=axes[1, 0],
                                    print_stats=False)
    axes[1, 0].set_xlabel("Reports / s")

    axes[0, 1].plot([], [])
    complot.plot_pergroup_cdf(stream_data, "filtered_rtt_events",
                              axes=axes[0, 1], print_stats=True)
    axes[1, 1].plot([], [])
    complot.plot_pergroup_histogram(stream_data, "filtered_rtt_events",
                                    axes=axes[1, 1], print_stats=False)
    axes[1, 1].set_xlabel("Filtered reports / s")

    fig.canvas.draw()
    fig.canvas.draw()

    return fig, axes


def main():
    parser = argparse.ArgumentParser(
        description="Visualize statistics from several runs")
    parser.add_argument("root_path", type=str, help="root folder")
    parser.add_argument("-f", "--fileformat", type=str,
                        help="File format for images",
                        required=False, default="png")
    args = parser.parse_args()

    cpu_data = read_all_cpu_data(args.root_path)
    for n_streams, data in cpu_data.items():
        fig, axes = plot_summarized_cpu_util(data)
        fig.savefig(os.path.join(args.root_path,
                                 "cpu_" + n_streams + "." + args.fileformat),
                    bbox_inches="tight")

    iperf_data = read_all_iperf_data(args.root_path)
    for n_streams, data in iperf_data.items():
        fig, axes = plot_summarized_network(data)
        fig.savefig(os.path.join(args.root_path,
                                 "network_" + n_streams + "." + args.fileformat),
                    bbox_inches="tight")

    report_data = read_all_rtt_reports(args.root_path)
    for n_streams, data in report_data.items():
        fig, axes = plot_summarized_reports(data)
        fig.savefig(os.path.join(args.root_path,
                                 "reports_" + n_streams + "." + args.fileformat),
                    bbox_inches="tight")


if __name__ == "__main__":
    main()
