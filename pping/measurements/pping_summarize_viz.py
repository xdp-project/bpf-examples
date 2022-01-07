#!/bin/env python3

import pandas as pd
import matplotlib.pyplot as plt
import os
import argparse
import pathlib

import common_plotting as complot
import pping_compare_viz as pping_comp
import ss_tcp_viz

label_folder_map = {"baseline": "no_pping", "PPing": "k_pping", "ePPing": "e_pping"}


def _read_all_data(root_folder, read_func, **kwargs):
    all_data = dict()
    path = root_folder
    for run in os.listdir(root_folder):
        path = os.path.join(root_folder, run)
        if run.startswith("run_") and os.path.isdir(path):

            for n_streams in os.listdir(path):
                path = os.path.join(root_folder, run, n_streams)
                if n_streams.endswith("_streams") and os.path.isdir(path):
                    if n_streams not in all_data:
                        all_data[n_streams] = dict()

                    data = read_func(path, **kwargs)
                    for setup, sdata in data.items():
                        if setup not in all_data[n_streams]:
                            all_data[n_streams][setup] = []
                        all_data[n_streams][setup].append(sdata)

    for stream_data in all_data.values():
        for setup in stream_data.keys():
            if len(stream_data[setup]) > 0:
                stream_data[setup] = pd.concat(
                    stream_data[setup]).reset_index(drop=True)
            else:
                del stream_data[setup]
    return all_data


def read_all_cpu_data(root_folder, omit=0):
    return _read_all_data(root_folder, pping_comp.load_cpu_data, omit=omit)


def read_all_network_data(root_folder, interface="ens192", omit=0):
    return _read_all_data(root_folder, pping_comp.load_network_data,
                          interface=interface, omit=omit)


def get_ss_tcp_file(subfolder):
    tcpfiles = list(pathlib.Path(subfolder, "M1").glob("ss_tcp.log*"))
    if len(tcpfiles) > 1:
        print("Warning: Multiple tcp-files in {}, returning first".format(
            os.path.join(subfolder, "M1")))
    return tcpfiles[0] if len(tcpfiles) > 0 else None


def read_tcp_data(root_folder, omit=0):
    tcp_dict = dict()
    for label, folder in label_folder_map.items():
        subfolder = os.path.join(root_folder, folder)
        test_interval = pping_comp.get_test_interval(subfolder, omit=omit)
        tcpfile = get_ss_tcp_file(subfolder)
        if tcpfile is None:
            continue

        data = ss_tcp_viz.load_ss_tcp_data(tcpfile, norm_timestamps=True,
                                           filter_timerange=test_interval,
                                           sum_flows=True,
                                           filter_main_flows=True)
        tcp_dict[label] = data["all"].copy()
    return tcp_dict


def read_all_tcp_data(root_folder, omit=0):
    return _read_all_data(root_folder, read_tcp_data, omit=omit)


def read_all_pping_reports(root_folder, **kwargs):
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
                        pping_comp.count_kpping_messages(path, **kwargs))

                    all_data[n_streams]["ePPing"].append(
                        pping_comp.count_epping_messages(path, **kwargs))

    for stream_data in all_data.values():
        for setup in stream_data.keys():
            stream_data[setup] = pd.concat(
                stream_data[setup]).reset_index(drop=True)
    return all_data


def plot_summarized_cpu_util(cpu_data):
    fig, axes = plt.subplots(2, 1, figsize=(8, 9), constrained_layout=True)
    complot.plot_pergroup_cdf(cpu_data, "total", axes=axes[0],
                              print_stats=True)
    complot.plot_pergroup_histogram(cpu_data, "total", axes=axes[1],
                                    print_stats=False)
    axes[1].set_xlabel("CPU utalalization (%)")

    fig.canvas.draw()
    fig.canvas.draw()

    return fig, axes


def plot_summarized_network(net_data):
    fig, axes = plt.subplots(2, 4, figsize=(32, 9), constrained_layout=True)

    complot.plot_pergroup_cdf(net_data, "txbps", axes=axes[0, 0],
                              print_stats=True, stat_kwargs={"fmt": "{:.4e}"})
    complot.plot_pergroup_histogram(net_data, "txbps", axes=axes[1, 0],
                                    print_stats=False)
    axes[1, 0].set_xlabel("TX throughput (bps)")

    complot.plot_pergroup_cdf(net_data, "txpps", axes=axes[0, 1],
                              print_stats=True)
    complot.plot_pergroup_histogram(net_data, "txpps", axes=axes[1, 1],
                                    print_stats=False)
    axes[1, 1].set_xlabel("TX throughput (pkt/s)")

    complot.plot_pergroup_cdf(net_data, "txdrop", axes=axes[0, 2],
                              print_stats=True)
    complot.plot_pergroup_histogram(net_data, "txdrop", axes=axes[1, 2],
                                    print_stats=False)
    axes[1, 2].set_xlabel("TX Drops / s")

    complot.plot_pergroup_cdf(net_data, "rxdrop", axes=axes[0, 3],
                              print_stats=True)
    complot.plot_pergroup_histogram(net_data, "rxdrop", axes=axes[1, 3],
                                    print_stats=False)
    axes[1, 3].set_xlabel("RX Drops / s")

    fig.canvas.draw()
    fig.canvas.draw()

    return fig, axes


def plot_summarized_tcp_info(tcp_data):
    fig, axes = plt.subplots(2, 2, figsize=(16, 9), constrained_layout=True)
    complot.plot_pergroup_cdf(tcp_data, "throughput", axes=axes[0, 0],
                              print_stats=True, stat_kwargs={"fmt": "{:.4e}"})
    complot.plot_pergroup_histogram(tcp_data, "throughput", axes=axes[1, 0],
                                    print_stats=False)
    axes[1, 0].set_xlabel("TCP throughput (bps)")

    complot.plot_pergroup_cdf(tcp_data, "rtt", axes=axes[0, 1],
                              print_stats=True)
    complot.plot_pergroup_histogram(tcp_data, "rtt", axes=axes[1, 1],
                                    print_stats=False)
    axes[1, 1].set_xlabel("TCP RTT (ms)")

    fig.canvas.draw()
    fig.canvas.draw()

    return fig, axes


def plot_summarized_reports(stream_data):
    if "filtered_rtt_events" in stream_data["PPing"]:
        fig, axes = plt.subplots(2, 2, figsize=(16, 9), constrained_layout=True)

        axes[0, 1].plot([], [])
        complot.plot_pergroup_cdf(stream_data, "filtered_rtt_events",
                                  axes=axes[0, 1], print_stats=True)
        axes[1, 1].plot([], [])
        complot.plot_pergroup_histogram(stream_data, "filtered_rtt_events",
                                        axes=axes[1, 1], print_stats=False)
        axes[1, 1].set_xlabel("Filtered reports / s")
    else:
        fig, axes = plt.subplots(2, 1, figsize=(8, 9), squeeze=False,
                                 constrained_layout=True)

    axes[0, 0].plot([], [])  # Dummy - use up one color cycle
    complot.plot_pergroup_cdf(stream_data, "rtt_events", axes=axes[0, 0],
                              print_stats=True, stat_kwargs={"fmt": "{:.4e}"})
    axes[1, 0].plot([], [])
    complot.plot_pergroup_histogram(stream_data, "rtt_events", axes=axes[1, 0],
                                    print_stats=False)
    axes[1, 0].set_xlabel("Reports / s")

    fig.canvas.draw()
    fig.canvas.draw()

    return fig, axes


def main():
    parser = argparse.ArgumentParser(
        description="Visualize statistics from several runs")
    parser.add_argument("-i", "--input", type=str, help="root folder",
                        required=True)
    parser.add_argument("-s", "--source-ip", type=str,
                        help="src-ip used to count filtered reports",
                        required=False, default=None)
    parser.add_argument("-f", "--fileformat", type=str,
                        help="File format for images",
                        required=False, default="png")
    parser.add_argument("-I", "--interface", type=str,
                        help="interface pping is running on",
                        required=False, default="ens192")
    parser.add_argument("-O", "--omit", type=int,
                        help="nr seconds to omit from start of test",
                        required=False, default=0)
    args = parser.parse_args()

    cpu_data = read_all_cpu_data(args.input, omit=args.omit)
    for n_streams, data in cpu_data.items():
        if len(data) < 1:
            continue
        fig, axes = plot_summarized_cpu_util(data)
        fig.savefig(os.path.join(args.input, "cpu_" + n_streams + "." +
                                 args.fileformat), bbox_inches="tight")

    net_data = read_all_network_data(args.input, interface=args.interface,
                                     omit=args.omit)
    for n_streams, data in net_data.items():
        if len(data) < 1:
            continue
        fig, axes = plot_summarized_network(data)
        fig.savefig(os.path.join(args.input, "network_" + n_streams + "." +
                                 args.fileformat), bbox_inches="tight")

    tcp_data = read_all_tcp_data(args.input, omit=args.omit)
    for n_streams, data in tcp_data.items():
        if len(data) < 1:
            continue
        fig, axes = plot_summarized_tcp_info(data)
        fig.savefig(os.path.join(args.input, "tcp_" + n_streams + "." +
                                 args.fileformat), bbox_inches="tight")

    report_data = read_all_pping_reports(args.input, src_ip=args.source_ip,
                                         omit=args.omit)
    for n_streams, data in report_data.items():
        fig, axes = plot_summarized_reports(data)
        fig.savefig(os.path.join(args.input, "reports_" + n_streams + "." +
                                 args.fileformat), bbox_inches="tight")


if __name__ == "__main__":
    main()
