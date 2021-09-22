#!/bin/env python3

import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import argparse

import util

def parse_map_line(words, counts, clean_cycle, entry_map_id, conn_map_id):
    try:
        map_id = int(words[0].split(":")[0])
    except ValueError:
        return clean_cycle, entry_map_id, conn_map_id

    if entry_map_id is None or map_id == entry_map_id:
        entry_map_id = map_id
        counts["entry_map"].append(int(words[3]))
        counts["entry_map_removed"].append(int(words[7]))
        counts["clean_time"][-1] += float(words[-2])
    elif conn_map_id is None or map_id == conn_map_id:
        conn_map = map_id
        counts["conn_map"].append(int(words[3]))
        counts["conn_map_removed"].append(int(words[7]))
        counts["clean_time"][-1] += float(words[-2])
        clean_cycle += 1
    else:
        raise ValueError("Unkown map_id: {}".format(map_id))

    return clean_cycle, entry_map_id, conn_map_id

def load_epping_errdata(file_name, compression="auto"):
    lines = []
    with util.open_compressed_file(file_name, compression, mode="rt") as file:
        lines = file.readlines()

    counts = {"clean_cycle":[0], "entry_map":[], "entry_map_removed":[], 
              "conn_map":[], "conn_map_removed":[], "clean_time":[0], "lost_events":[0]}

    entry_map = None
    conn_map = None
    clean_cycle = 0

    for line in lines:
        if clean_cycle != counts["clean_cycle"][-1]:
            counts["clean_cycle"].append(clean_cycle)
            counts["clean_time"].append(0)
            counts["lost_events"].append(0)

        words = line.split()

        # Gone through map line 
        if words[0].endswith(":"):
            clean_cycle, entry_map, conn_map = parse_map_line(words, counts, 
                                                              clean_cycle, 
                                                              entry_map,
                                                              conn_map)

        # Lost events line
        elif words[0] == "Lost":
            counts["lost_events"][-1] += int(words[1])

    for col in ("entry_map", "entry_map_removed", "conn_map", "conn_map_removed"):
        if len(counts[col]) < len(counts["clean_cycle"]):
            counts[col].append(np.nan)

    return pd.DataFrame(counts)

def plot_cleaning(errdata, axes=None, processing_time=True, grid=True):
    if axes is None:
        axes = plt.gca()

    if processing_time:
        ax2 = axes.twinx()
        ax2.plot(errdata["clean_cycle"].values, errdata["clean_time"].values, c="C2", ls="-")
        axes.plot([], [], c="C2", ls="-", label="processing time") # Hack to get a nice legend

        ax2.set_ylim(0)
        ax2.set_ylabel("Processing time (s)")

    axes.plot(errdata["clean_cycle"].values, errdata["entry_map"].values, c="C0", ls="-",
              label="entry map")
    axes.plot(errdata["clean_cycle"].values, errdata["entry_map_removed"].values, c="C0",
              ls="--", label="removed")
    axes.plot(errdata["clean_cycle"].values, errdata["conn_map"].values, c="C1", ls="-",
              label="connection map")

    axes.grid(grid)
    axes.set_ylim(0)
    axes.set_xlabel("Cleaning cycles")
    axes.set_ylabel("Entries")

    axes.legend()

    return axes

def plot_lost_events(errdata, axes=None, grid=True):
    if axes is None:
        axes = plt.gca()

    axes.plot(errdata["clean_cycle"].values, errdata["lost_events"].values)

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

    fig, axes = plt.subplots(2, 1, figsize=(8, 8), constrained_layout=True);
    plot_cleaning(errdata, axes[0]);
    plot_lost_events(errdata, axes[1])
    if args.title is not None:
        fig.suptitle(args.title)

    if args.output is not None:
        fig.savefig(args.output, bbox_inches="tight")
    else:
        plt.show()

    return


if __name__ == "__main__":
    main()
