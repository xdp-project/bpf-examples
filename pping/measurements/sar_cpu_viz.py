#!/bin/env python3

import argparse
import numpy as np
import matplotlib.pyplot as plt

import util
import common_plotting as complot
import sar_data_loading as sdl


def trim_only_under_load(per_cpu_dfs, load_thresh=1, neighbours=0,
                         norm_timestamps="auto"):
    if norm_timestamps == "auto":
        norm_timestamps = not np.issubdtype(
            util.get_first_dict_entry(per_cpu_dfs)["timestamp"].dtype, np.datetime64)

    loaded_mask = per_cpu_dfs["all"]["total"].values >= load_thresh
    start = max(0, np.min(np.nonzero(loaded_mask)) - neighbours)
    end = min(len(loaded_mask), np.max(np.nonzero(loaded_mask)) + neighbours)

    trimmed = dict()
    for cpu, df in per_cpu_dfs.items():
        trimmed[cpu] = df.iloc[start:end+1].copy()
        if norm_timestamps:
            trimmed[cpu]["timestamp"] = util.normalize_timestamps(
                trimmed[cpu]["timestamp"])

    return trimmed


def plot_percpu_timeseries(per_cpu_dfs, axes=None):
    stat_kwargs = {"fmt": "{:.2f}"}
    axes = complot.plot_pergroup_timeseries(per_cpu_dfs, col="total", axes=axes,
                                            stat_kwargs=stat_kwargs)
    axes.set_ylabel("CPU load (%)")
    axes.set_ylim(0)
    return axes


def plot_percpu_cdf(per_cpu_dfs, axes=None):
    stat_kwargs = {"fmt": "{:.2f}"}
    axes = complot.plot_pergroup_cdf(per_cpu_dfs, col="total", axes=axes,
                                     stat_kwargs=stat_kwargs)
    axes.set_xlabel("CPU load (%)")
    return axes


def plot_perclass_timeseries(per_cpu_dfs, axes=None, print_stats=True,
                             **kwargs):
    if axes is None:
        axes = plt.gca()

    load = per_cpu_dfs["all"]
    load_cols = [col for col in load.columns
                 if col not in ("timestamp", "total")]
    x = load["timestamp"].values
    ys = load[load_cols].values.transpose()

    axes.stackplot(x, ys, labels=load_cols, **kwargs)

    axes.legend()
    axes.set_ylabel("CPU load (%)")
    axes.set_xlabel("Time")
    axes.grid()

    if print_stats:
        cols = [col for col in load.columns if col != "timestamp"]
        complot.plot_stats_table(load, cols, fmt="{:.2f}", loc="top")

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
    # Update: This hack no longer seems to work...
    fig.canvas.draw()
    fig.canvas.draw()

    return fig


def main():
    parser = argparse.ArgumentParser(description="Visualize CPU-load from mpstat JSON file")
    parser.add_argument("-i", "--input", type=str, help="json input file", required=True)
    parser.add_argument("-o", "--output", type=str, help="image output file", required=False)
    parser.add_argument("-T", "--title", type=str, help="figure title", required=False)
    parser.add_argument("-t", "--trim", nargs='?', type=float, help="trim to section under load",
                        required=False, default=None, const=1)
    args = parser.parse_args()

    cpu_json = sdl.load_sar_cpu_data(args.input)
    data = sdl.to_percpu_df(cpu_json)
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
