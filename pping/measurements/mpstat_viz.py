#!/bin/env python3

import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import json
import argparse

import common_plotting as complot
import util

# Data mangling

def load_mpstat_json(filename, compression="auto"):
    with util.open_compressed_file(filename, compression, mode="rt") as file:
        stats = json.load(file)
    return stats["sysstat"]["hosts"][0]

def get_timestamps(cpu_stats):
    date = cpu_stats["date"]
    timestamps = [date + " " + entry["timestamp"] 
                  for entry in cpu_stats["statistics"]]
    return pd.to_datetime(timestamps)

def to_percpu_df(cpu_stats, norm_timestamps=True):
    n_cpus = cpu_stats["number-of-cpus"]
    ts = get_timestamps(cpu_stats)
    if norm_timestamps:
        ts = normalize_timestamps(ts)
        
    per_cpu = dict()
    for period in cpu_stats["statistics"]:
        for entry in period["cpu-load"]:
            cpu = entry["cpu"]
            mult = n_cpus if cpu == "all" else 1
            if cpu not in per_cpu:
                per_cpu[cpu] = dict()

            for loadtype, load in entry.items():
                if loadtype == "cpu":
                    continue
                if loadtype == "idle":
                    loadtype = "total"
                if loadtype not in per_cpu[cpu]:
                    per_cpu[cpu][loadtype] = []
                    
                if loadtype == "total":
                    per_cpu[cpu]["total"].append((100 - load) * mult)
                else:
                    per_cpu[cpu][loadtype].append(load * mult)
                    
    for cpu, data in per_cpu.items():
        per_cpu[cpu] = pd.DataFrame(data)
        per_cpu[cpu].insert(0, "timestamp", ts)
        
    return per_cpu


def normalize_timestamps(timestamps):
    normed = timestamps - timestamps.min()
    
    if np.issubdtype(normed.dtype, np.timedelta64):
        normed = normed.astype("timedelta64[s]").astype("float64")
        
    return normed

def trim_only_under_load(per_cpu_dfs, load_thresh=10, neighbours=1, norm_timestamps="auto"):
    cpu_load = per_cpu_dfs["all"]
    if norm_timestamps == "auto":
        norm_timestamps = not np.issubdtype(util.get_first_dict_entry(per_cpu_dfs)["timestamp"].dtype,
                                            np.datetime64)
        
    loaded_mask = per_cpu_dfs["all"]["total"].values >= load_thresh
    start = max(0, np.min(np.nonzero(loaded_mask)) - neighbours)
    end = min(len(loaded_mask), np.max(np.nonzero(loaded_mask)) + neighbours)
    
    trimmed = dict()
    for cpu, df in per_cpu_dfs.items():
        trimmed[cpu] = df.iloc[start:end+1].copy()
        if norm_timestamps:
            trimmed[cpu]["timestamp"] = normalize_timestamps(trimmed[cpu]["timestamp"])

    return trimmed

# Plotting
def plot_percpu_timeseries(per_cpu_dfs, axes=None):
    stat_kwargs = {"fmt":"{:.2f}"}
    axes = complot.plot_pergroup_timeseries(per_cpu_dfs, col="total", axes=axes, 
                                            stat_kwargs=stat_kwargs)
    axes.set_ylabel("CPU load (%)")
    axes.set_ylim(0)
    return axes

def plot_percpu_cdf(per_cpu_dfs, axes=None):
    stat_kwargs = {"fmt":"{:.2f}"}
    axes = complot.plot_pergroup_cdf(per_cpu_dfs, col="total", axes=axes, 
                                     stat_kwargs=stat_kwargs)
    axes.set_xlabel("CPU load (%)")
    return axes

def plot_perclass_timeseries(per_cpu_dfs, axes=None, print_stats=True, **kwargs):
    if axes is None:
        axes = plt.gca()
        
    load = per_cpu_dfs["all"]
    load_cols = [col for col in load.columns if col not in ("timestamp", "total")]
    x = load["timestamp"].values
    ys = load[load_cols].values.transpose()
    
    axes.stackplot(x, ys, labels=load_cols, **kwargs)
    
    axes.legend()
    axes.set_ylabel("CPU load (%)")
    axes.set_xlabel("Time")
    axes.grid()
    
    if print_stats:
        plot_perclass_table(per_cpu_dfs, axes=axes, loc="top")
        
    return axes

def plot_perclass_table(per_cpu_dfs, axes=None, **kwargs):
    if axes is None:
        axes = plt.gca()
        
    cols = ["min", "median", "mean", "max"]
    rows = []
    cells = []
    
    totload = per_cpu_dfs["all"]
    for loadclass in totload.columns:
        if loadclass == "timestamp":
            continue
        
        rows.append(loadclass)
        cells.append(["{:.2f}".format(func(totload[loadclass].values))
                      for func in (np.amin, np.median, np.mean, np.max)])
        
    axes.table(cells, rowLabels=rows, colLabels=cols, **kwargs)
    return axes

def plot_cpu_load(per_cpu_dfs, title=None):
    fig, axes = plt.subplots(3, 1, figsize=(8, 16), constrained_layout=True)
    
    plot_percpu_timeseries(per_cpu_dfs, axes=axes[0])
    plot_percpu_cdf(per_cpu_dfs, axes=axes[1])
    plot_perclass_timeseries(per_cpu_dfs, axes=axes[2])
    
    if title is not None:
        fig.suptitle(title)

    # Hack fix for it to render correctly on older matplotlib
    # https://stackoverflow.com/a/59341086
    fig.canvas.draw()
    fig.canvas.draw()


    return fig

def main():
    parser = argparse.ArgumentParser(description="Visualize CPU-load from mpstat JSON file")
    parser.add_argument("-i", "--input", type=str, help="json input file", required=True)
    parser.add_argument("-o", "--output", type=str, help="image output file", required=False)
    parser.add_argument("-T", "--title", type=str, help="figure title", required=False)
    parser.add_argument("-t", "--trim", nargs='?', type=float, help="trim to section under load",
                        required=False, default=None, const=10)
    args = parser.parse_args()

    mpstat_json = load_mpstat_json(args.input)
    data = to_percpu_df(mpstat_json)
    if args.trim is not None:
        data = trim_only_under_load(data, load_thresh=args.trim)
    fig = plot_cpu_load(data, title=args.title)

    if args.output is not None:
        fig.savefig(args.output, bbox_inches="tight")
    else:
        plt.show()

    return

if __name__ == "__main__":
    main()

