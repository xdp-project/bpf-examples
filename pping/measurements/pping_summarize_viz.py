#!/bin/env python3

import matplotlib.pyplot as plt
import os
import argparse

import common_plotting as complot
import process_data as prodat


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
    fig, axes = plt.subplots(2, 3, figsize=(24, 9), constrained_layout=True)
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

    complot.plot_pergroup_cdf(tcp_data, "retrans/s", axes=axes[0, 2],
                              print_stats=True, stat_kwargs={"fmt": "{:.2f}"})
    complot.plot_pergroup_histogram(tcp_data, "retrans/s", axes=axes[1, 2],
                                    print_stats=False)
    axes[1, 2].set_xlabel("Retrans/s")

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

    cpu_data = prodat.load_all_cpu_data(args.input, omit=args.omit)
    for n_streams, data in cpu_data.items():
        if len(data) < 1:
            continue
        fig, axes = plot_summarized_cpu_util(data)
        fig.savefig(os.path.join(args.input, "cpu_" + n_streams + "." +
                                 args.fileformat), bbox_inches="tight")

    net_data = prodat.load_all_network_data(args.input, interface=args.interface,
                                            omit=args.omit)
    for n_streams, data in net_data.items():
        if len(data) < 1:
            continue
        fig, axes = plot_summarized_network(data)
        fig.savefig(os.path.join(args.input, "network_" + n_streams + "." +
                                 args.fileformat), bbox_inches="tight")

    tcp_data = prodat.load_all_tcp_data(args.input, omit=args.omit,
                                        dst=args.source_ip,
                                        include_individual_flows=False)
    for n_streams, data in tcp_data.items():
        if len(data) < 1:
            continue
        fig, axes = plot_summarized_tcp_info(data)
        fig.savefig(os.path.join(args.input, "tcp_summarized_" + n_streams + "." +
                                 args.fileformat), bbox_inches="tight")

    tcp_perflow_data = prodat.load_all_tcp_data(args.input, omit=args.omit,
                                                dst=args.source_ip,
                                                include_individual_flows=True)
    for n_streams, data in tcp_perflow_data.items():
        if len(data) < 1:
            continue
        for setup in data.keys():
            df = data[setup]
            data[setup] = df.loc[df["flow"] != "all"]
        fig, axes = plot_summarized_tcp_info(data)
        fig.savefig(os.path.join(args.input, "tcp_perflow_" + n_streams + "." +
                                 args.fileformat), bbox_inches="tight")

    report_data = prodat.load_all_pping_reports(args.input, src_ip=args.source_ip,
                                                omit=args.omit)
    for n_streams, data in report_data.items():
        if len(data) < 1:
            continue
        fig, axes = plot_summarized_reports(data)
        fig.savefig(os.path.join(args.input, "reports_" + n_streams + "." +
                                 args.fileformat), bbox_inches="tight")

    all_data = dict()
    if len(cpu_data) > 0:
        all_data["cpu"] = cpu_data
    if len(net_data) > 0:
        all_data["network"] = net_data
    if len(tcp_data) > 0:
        all_data["tcp"] = tcp_data
    if len(report_data) > 0:
        all_data["pping"] = report_data

    if len(all_data) > 0:
        merged_data = prodat.merge_all_data(all_data, how="outer")
        merged_data.to_csv(os.path.join(args.input, "data.csv.xz"))


if __name__ == "__main__":
    main()
