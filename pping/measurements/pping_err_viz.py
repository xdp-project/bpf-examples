#!/bin/env python3

import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import argparse
from collections import defaultdict

import util


def parse_errdata_line(line):
    values = dict()

    if line.startswith("Lost"):
        values["lost_events"] = int(line.split()[1])

    elif line.startswith("packet_ts:") or line.startswith("flow_state:"):
        bpf_map = line[:line.find(":")]

        keyval_pairs = line[line.find(":")+2:].split(", ")
        for keyval_pair in keyval_pairs:
            key, val = keyval_pair.split(":")
            values["cycle" if key == "cycle"
                   else bpf_map + "_" + key.replace(" ", "_")] = int(val)

    return values


def load_epping_errdata(file_name, compression="auto"):
    counts = defaultdict(list)
    cycle = 0

    with util.open_compressed_file(file_name, compression, mode="rt") as file:
        for line in file:
            c = parse_errdata_line(line)
            cycle = c.get("cycle", cycle)
            for key, val in c.items():
                if key != "cycle":
                    while(len(counts[key]) < cycle + 1):
                        counts[key].append(0)
                    counts[key][cycle] += val/1e9 if key.endswith("time") else val

    for key in counts.keys():
        while(len(counts[key]) < cycle + 1):
            counts[key].append(0)

    counts = pd.DataFrame(counts)
    if "lost_events" not in counts.columns:
        counts["lost_events"] = np.zeros(len(counts))

    return counts


def plot_map_cleanup(errdata, axes=None, processing_time=True, grid=True, legend=True):
    if axes is None:
        axes = plt.gca()

    if processing_time:
        ax2 = axes.twinx()
        ax2.plot(errdata.index.values, errdata["packet_ts_time"].values + errdata["flow_state_time"].values, 
                 c="C2", ls="-", alpha=0.5)
        axes.plot([], [], c="C2", ls="-", label="processing time") # Hack to get a nice legend

        ax2.set_ylim(0)
        ax2.set_ylabel("Processing time (s)")

    axes.plot(errdata.index.values, errdata["packet_ts_entries"].values, c="C0", ls="-",
              label="ts map")
    axes.plot(errdata.index.values, errdata["packet_ts_timeout"].values, c="C0", ls="--",
              label="ts timeout")

    axes.plot(errdata.index.values, errdata["flow_state_entries"].values, c="C1", ls="-",
              label="flow map")
    axes.plot(errdata.index.values, errdata["flow_state_timeout"].values, c="C1", ls="--",
              label="flow timeout")

    axes.grid(grid)
    axes.set_ylim(0)
    axes.set_xlabel("Cleaning cycles")
    axes.set_ylabel("Entries")

    if legend:
        axes.legend()

    return axes


def plot_cleanup_ratio(errdata, axes=None, grid=True, legend=True):
    if axes is None:
        axes = plt.gca()

    tot = errdata["packet_ts_selfdel"].values + errdata["packet_ts_timeout"].values
    ratio = np.divide(errdata["packet_ts_selfdel"].values, tot, out=np.zeros(len(errdata)), where=tot > 0)
    axes.plot(errdata.index.values, ratio, c="C0", linestyle="-", label="ts ratio")

    tot = errdata["packet_ts_tot_selfdel"].values + errdata["packet_ts_tot_timeout"].values
    ratio = np.divide(errdata["packet_ts_tot_selfdel"].values, tot, out=np.zeros(len(errdata)), where=tot > 0)
    axes.plot(errdata.index.values, ratio, c="C0", linestyle="--", label="ts cum. ratio")

    tot = errdata["flow_state_selfdel"].values + errdata["flow_state_timeout"].values
    ratio = np.divide(errdata["flow_state_selfdel"].values, tot, out=np.zeros(len(errdata)), where=tot > 0)
    axes.plot(errdata.index.values, ratio, c="C1", linestyle="-", label="flow ratio")

    tot = errdata["flow_state_tot_selfdel"].values + errdata["flow_state_tot_timeout"].values
    ratio = np.divide(errdata["flow_state_tot_selfdel"].values, tot, out=np.zeros(len(errdata)), where=tot > 0)
    axes.plot(errdata.index.values, ratio, c="C1", linestyle="--", label="flow cum. ratio")

    axes.grid(grid)
    axes.set_ylim(-0.01, 1.01)
    axes.set_xlabel("Cleaning cycles")
    axes.set_ylabel("Cleanup ratio (selfdel/timeout)")

    if legend:
        axes.legend()

    return axes


def plot_lost_events(errdata, axes=None, grid=True):
    if axes is None:
        axes = plt.gca()

    axes.plot(errdata.index.values, errdata["lost_events"].values)

    axes.grid(grid)
    axes.set_ylim(0)
    axes.set_xlabel("Cleaning cycles")
    axes.set_ylabel("Lost events")

    return axes


def main():
    parser = argparse.ArgumentParser(description="Visualize map cleaning and lost events")
    parser.add_argument("-i", "--input", type=str, help="error input file", required=True)
    parser.add_argument("-o", "--output", type=str, help="image output file", required=False)
    parser.add_argument("-T", "--title", type=str, help="figure title", required=False)
    args = parser.parse_args()

    errdata = load_epping_errdata(args.input)

    fig, axes = plt.subplots(3, 1, figsize=(8, 12), constrained_layout=True)
    plot_map_cleanup(errdata, axes[0])
    plot_cleanup_ratio(errdata, axes[1])
    plot_lost_events(errdata, axes[2])
    if args.title is not None:
        fig.suptitle(args.title)

    if args.output is not None:
        fig.savefig(args.output, bbox_inches="tight")
    else:
        plt.show()

    return


if __name__ == "__main__":
    main()
