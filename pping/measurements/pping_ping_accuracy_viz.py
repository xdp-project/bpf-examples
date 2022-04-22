#!/bin/env python3

import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import scipy.stats as stats
import pathlib
import sys
import re
import argparse
import os

import util
import common_plotting as complot


def parse_epping_rtts(filename):
    data = list()

    with util.open_compressed_file(filename, mode="rt") as infile:
        for line in infile:
            parsed_info = parse_epping_rtt_line(line.rstrip())

            if parsed_info is not None:
                data.append(parsed_info)

    return pd.DataFrame(data)


def parse_epping_rtt_line(line):
    standard_format = is_epping_standard_rtt_line(line)
    ppviz_format = is_epping_ppviz_rtt_line(line)
    if not standard_format and not ppviz_format:
        return None

    words = line.split()
    flow = words[-1]

    if standard_format:
        time = words[0]
        rtt = float(words[1]) / 1000
    else:
        time = pd.to_datetime(words[0], unit="s")
        rtt = float(words[1])

    return {"timestamp": time, "rtt": rtt, "flow": flow}


def is_epping_standard_rtt_line(line):
    return re.match(
        "^\d{2}:\d{2}:\d{2}\.\d+ \d+\.\d+ ms .* [\d\.:]+\+[\d\.:]+$",
        line) is not None


def is_epping_ppviz_rtt_line(line):
    return re.match(
        "^\d+\.\d+ \d+\.\d+ .* [\d\.:]+\+[\d\.:]+$",
        line) is not None


def parse_ping_rtts(filename):
    data = list()

    with util.open_compressed_file(filename, mode="rt") as infile:
        for line in infile:
            parsed_info = parse_ping_rtt_line(line.rstrip())

            if parsed_info is not None:
                data.append(parsed_info)

    return pd.DataFrame(data)


def parse_ping_rtt_line(line):
    if not is_ping_rtt_line(line):
        return None

    words = line.split()
    if words[0].startswith("[") and words[0].endswith("]"):
        time = pd.to_datetime(words[0][1:-1], unit="s")
        offset = 1
    else:
        time = None
        offset = 0

    dst = words[3 + offset][:-1]
    seq = int(words[4 + offset].split("=")[1])

    rtt_str = words[-2].split("=")[1]
    rtt = float(words[-2].split("=")[1]) / 1000
    n_dec = len(rtt_str) - rtt_str.find(".") - 1 if rtt_str.find(".") >= 0 else 0
    rtt_prec = 10**(-3 - n_dec)

    return {"timestamp": time, "rtt": rtt, "rtt_prec": rtt_prec, "dst": dst,
            "seq": seq}


def is_ping_rtt_line(line):
    return re.match(
        "^(\[\d+\.\d+\] )?\d+ bytes from [\d\.:]+: icmp_seq=\d+ .* time=\d+(\.\d+)? ms$",
        line) is not None


def read_rtt_data(data_folder):
    data = dict()

    ping_file = get_file_with_unknown_suffix(data_folder, "ping.out")
    if ping_file is not None:
        data["ping"] = parse_ping_rtts(ping_file)
    else:
        print("Warning: No ping file found in {}".format(data_folder))

    epping_file = get_file_with_unknown_suffix(data_folder, "pping.out")
    if epping_file is not None:
        data["ePPing"] = parse_epping_rtts(epping_file)
    else:
        print("Warning: No ePPing file found in {}".format(data_folder))

    return data if len(data) > 0 else None


def get_file_with_unknown_suffix(folder, filename):
    files = list(pathlib.Path(folder).glob(filename + "*"))
    if len(files) > 1:
        print("Warning: Multiple files matching {}/{}*, returning first".format(
            folder, filename), file=sys.stderr)
    return files[0] if len(files) > 0 else None


def plot_rtt_dist(data, axes=None):
    if axes is None:
        fig, axes = plt.subplots(figsize=(8, 5))

    complot.plot_pergroup_histogram(data, col="rtt", axes=axes,
                                    print_stats=True,
                                    stat_kwargs={"fmt": "{:.4e}"})
    axes.set_xlabel("RTT (s)")

    return axes


def plot_rtt_diff(data, axes=None):
    if "ping" not in data and "ePPing" not in data:
        raise ValueError("Need both ping and ePPing data to cal")

    if len(data["ping"]) != len(data["ePPing"]):
        raise ValueError("ping and ePPing data of different size - cannot correlate")

    diff = data["ping"][["rtt", "rtt_prec"]].copy()
    diff["rtt"] = diff["rtt"] - data["ePPing"]["rtt"]

    diff_levels = {"overall_diff": diff}
    #if diff["rtt_prec"].nunique() > 1:
    for prec_level, prec_data in diff.groupby("rtt_prec"):
        diff_levels["prec_" + str(prec_level)] = prec_data

    if axes is None:
        fig, axes = plt.subplots(figsize=(8, 5))

    complot.plot_pergroup_histogram(diff_levels, col="rtt", axes=axes,
                                    print_stats=True, stat_kwargs={"fmt": "{:.4e}"})
    axes.set_xlabel("RTT-difference (s)")

    return axes


def plot_rtt_timeseries(data, normalize_timestamps=True, axes=None):
    data_to_use = dict()
    for key, val in data.items():
        if np.issubdtype(val["timestamp"].dtype, np.datetime64):
            data_to_use[key] = val.copy()

    if axes is None:
        _, axes = plt.subplots(figsize=(8, 5))

    if len(data_to_use) < 0:
        axes.text(0.5, 0.5, "No time data", va="center", ha="center", fontsize=20,
                  color="red", transform=axes.transAxes)
        return axes

    if normalize_timestamps:
        t_min = min([d["timestamp"].min() for d in data_to_use.values()])
        for d in data_to_use.values():
            d["timestamp"] = (d["timestamp"] - t_min) / np.timedelta64(1, "s")

    complot.plot_pergroup_timeseries(data_to_use, "rtt", print_stats=True,
                                     stat_kwargs={"fmt": "{:.4e}"}, alpha=0.5)

    rtts = [d["rtt"] for d in data_to_use.values()]
    if len(rtts) == 2 and len(rtts[0]) == len(rtts[1]) and len(rtts[0] > 1):
        r = stats.pearsonr(rtts[0], rtts[1])[0]
        axes.text(0.99, 0.01, "r={:.3f}".format(r), va="bottom", ha="right",
                  transform=axes.transAxes)

    return axes


def main():
    parser = argparse.ArgumentParser(description="Visualize result from ping_test.sh")
    parser.add_argument("-i", "--input", type=str, help="folder with (p)ping data",
                        required=True)
    args = parser.parse_args()

    data = read_rtt_data(args.input)
    if data is None:
        print("Warning: Found not valid data in {}".format(args.input),
              file=sys.stderr)
        return

    fig = plot_rtt_dist(data).get_figure()
    fig.savefig(os.path.join(args.input, "RTT_distribution.png"),
                bbox_inches="tight")

    fig = plot_rtt_diff(data).get_figure()
    fig.savefig(os.path.join(args.input, "RTT_difference.png"),
                bbox_inches="tight")

    fig = plot_rtt_timeseries(data).get_figure()
    fig.savefig(os.path.join(args.input, "RTT_timeseries.png"),
                bbox_inches="tight")

    return


if __name__ == "__main__":
    main()
