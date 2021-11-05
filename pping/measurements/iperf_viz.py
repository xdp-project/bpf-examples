#!/bin/env python3

import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import json
import argparse

import common_plotting as complot
import util

# Data mangling
def load_iperf3_json(filename, compression="auto"):
    with util.open_compressed_file(filename, compression, mode="rt") as file:
        data = json.load(file)
    return data


def socket_to_stream_map(iperf_json, shortnames=False):
    socket_map = dict()
    for con in iperf_json["start"]["connected"]:
        if shortnames:
            stream = str(con["local_port"])
        else:
            stream = "{}:{}+{}:{}".format(con["local_host"], con["local_port"],
                                          con["remote_host"], con["remote_port"])

        socket_map[con["socket"]] = stream

    return socket_map


def get_test_interval(iperf_file, skip_omitted=True):
    jdata = load_iperf3_json(iperf_file)

    start = jdata["start"]["timestamp"]["timesecs"]
    if skip_omitted:
        start += jdata["start"]["test_start"]["omit"]
    end = start + jdata["end"]["sum_sent"]["end"]
    return pd.to_datetime([start, end], unit="s").values


def to_perstream_df(iperf_json, skip_omitted=True, norm_timestamps=True,
                    shortnames=True, include_total=True):
    t_start = iperf_json["start"]["timestamp"]["timesecs"]
    omit_sec = iperf_json["start"]["test_start"]["omit"]
    sock_map = socket_to_stream_map(iperf_json, shortnames=shortnames)

    per_stream = dict()
    for interval in iperf_json["intervals"]:
        for stream in interval["streams"]:
            if skip_omitted and stream["omitted"]:
                continue

            stream_name = sock_map[stream["socket"]]

            if stream_name not in per_stream:
                per_stream[stream_name] = {"timestamp": [], "throughput": [],
                                           "retrans": [], "rtt": []}

            entry = per_stream[stream_name]
            entry["timestamp"].append(
                stream["end"] + (0 if stream["omitted"] else omit_sec))
            entry["throughput"].append(stream["bits_per_second"])
            entry["retrans"].append(stream["retransmits"])
            entry["rtt"].append(stream["rtt"] / 1000)

    for stream, data in per_stream.items():
        if not norm_timestamps:
            data["timestamp"] = pd.to_datetime(
                np.add(data["timestamp"], t_start), unit="s")
        elif skip_omitted:
            data["timestamp"] = np.subtract(data["timestamp"], omit_sec)

        per_stream[stream] = pd.DataFrame(data)

    if include_total:
        per_stream["all"] = sum_streams(per_stream)

    return per_stream


def sum_streams(stream_dfs):
    # Should correspond to the "sum" entries in the JSON, but can flexibly be used for any set of streams
    ss = pd.DataFrame(columns=["timestamp", "throughput", "retrans", "rtt"])
    add_cols = ss.columns[1:]
    n = 0
    for stream, df in stream_dfs.items():
        if stream == "all":
            continue

        n += 1
        if len(ss) == 0:
            ss = df.copy()
        else:
            ss[add_cols] += df[add_cols]

    ss["rtt"] /= n

    return ss


def merge_iperf_data(*args, compute_total=True):
    stream_dfs = dict()
    for arg in args:
        for stream, df in arg.items():
            if stream != "all":
                stream_dfs[stream] = df

    if compute_total:
        stream_dfs["all"] = sum_streams(stream_dfs)

    return stream_dfs


# Plotting
def plot_throughput_timeseries(stream_dfs, axes=None, plot_retrans=True, **kwargs):
    stat_kwargs = {"fmt": "{:.3e}"}
    axes = complot.plot_pergroup_timeseries(stream_dfs, "throughput", axes=axes,
                                            stat_kwargs=stat_kwargs, **kwargs)

    axes.set_ylabel("Throughput (bits/s)")
    axes.set_ylim(0)

    if plot_retrans and "all" in stream_dfs:
        ax2 = axes.twinx()
        ax2.plot(stream_dfs["all"]["timestamp"].values, stream_dfs["all"]["retrans"].values,
                 color="k", linestyle="--", zorder=2.5)
        ax2.set_ylabel("Retransmissions")
        ax2.set_ylim(0)

    return axes


def plot_rtt_timeseries(stream_dfs, axes=None, **kwargs):
    stat_kwargs = {"fmt": "{:.2f}"}
    axes = complot.plot_pergroup_timeseries(stream_dfs, "rtt", axes=axes, 
                                            normalize_all=False, 
                                            stat_kwargs=stat_kwargs, **kwargs)

    axes.set_ylabel("RTT (ms)")
    axes.set_ylim(0)

    return axes


def plot_iperf(stream_dfs, title=None):
    fig, axes = plt.subplots(2, 1, figsize=(8, 12), constrained_layout=True)

    plot_throughput_timeseries(stream_dfs, axes=axes[0])
    plot_rtt_timeseries(stream_dfs, axes=axes[1])

    if title is not None:
        fig.suptitle(title)

    # Hack fix for it to render correctly on older matplotlib
    # https://stackoverflow.com/a/59341086
    fig.canvas.draw()
    fig.canvas.draw()

    return fig


def main():
    parser = argparse.ArgumentParser(description="Visualize iperf3 JSON output")
    parser.add_argument("-i", "--input", action="append", type=str, help="json input file", required=True)
    parser.add_argument("-o", "--output", type=str, help="image output file", required=False)
    parser.add_argument("-T", "--title", type=str, help="figure title", required=False)
    args = parser.parse_args()

    json_data = [load_iperf3_json(file) for file in args.input]
    data = merge_iperf_data(*[to_perstream_df(data) for data in json_data])
    fig = plot_iperf(data, title=args.title)

    if args.output is not None:
        fig.savefig(args.output, bbox_inches="tight")
    else:
        plt.show()

    return


if __name__ == "__main__":
    main()
