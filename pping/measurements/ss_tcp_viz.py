#!/bin/env python3

import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import argparse

import util
import common_plotting as complot


def load_ss_tcp_data(filename, filter_timerange=None, norm_timestamps=True,
                     dst=None, sum_flows=True, filter_main_flows=False,
                     **kwargs):
    """
    Parses data from ss -tiO >> filename.

    Timestamps of format %Y-%m-%dT%H:%M:%S are expected either at the
    beginning of each line, at the beginning of some lines or on
    separate lines. Any entries before the first timestamp is encountered
    will be ignored.
    """
    flow_data = dict()
    flow_bytes_history = dict()
    fields = ["throughput", "rtt", "rttvar"]
    current_ts = None

    with util.open_compressed_file(filename, mode="rt") as file:
        for line in file:
            tcp_info = parse_tcp_entry(line, flow_bytes_history)
            current_ts = tcp_info.get("timestamp", current_ts)
            if not all(f in tcp_info for f in fields) or current_ts is None:
                continue
            flow = tcp_info["flow"]
            if dst is not None and not flow.split("+")[1].startswith(dst):
                continue

            if flow not in flow_data:
                flow_data[flow] = {field: [] for field in ["timestamp"] + fields}

            flow_data[flow]["timestamp"].append(tcp_info.get("timestamp", current_ts))
            for field in fields:
                flow_data[flow][field].append(tcp_info[field])

    if len(flow_data) < 1:
        return flow_data

    # Convert to dataframe and apply filters
    flow_dfs = dict()
    if filter_main_flows:
        filt_flows = filter_likely_main_flows(flow_data, **kwargs)
        if len(filt_flows) > 0:
            flow_data = filt_flows
        else:
            print("Warning: Attempting to filter main flows yielded no valid flows. Skipping this step")

    time_ref = (min(data["timestamp"][0] for data in flow_data.values())
                if filter_timerange is None else filter_timerange[0])

    for flow, data in flow_data.items():
        df = pd.DataFrame(data)

        if filter_timerange is not None:
            df = df.loc[df["timestamp"].between(*filter_timerange)]
            df.reset_index(drop=True, inplace=True)

        if norm_timestamps:
            df["timestamp"] = util.normalize_timestamps(df["timestamp"],
                                                        time_ref)
        if len(df) > 0:
            flow_dfs[flow] = df

    if sum_flows:
        flow_dfs["all"] = summarize_flows(flow_dfs)

    return flow_dfs


def parse_tcp_entry(line, flow_bytes_history=None):
    """
    Parses a line from the output of ss -tiO.
    May optionally be prependeded by a timestamp
    """
    info = dict()
    tp = dict()
    bytes_sent = 0

    parts = line.rstrip("\n").split()
    if len(parts) < 1:
        return info

    if parts[0] != "ESTAB":
        try:
            info["timestamp"] = np.datetime64(parts[0])
        except ValueError:
            pass
        estab_idx = 1
    else:
        estab_idx = 0

    # Check if TCP line
    if len(parts) < 6 or parts[estab_idx] != "ESTAB":
        return info

    # Parse TCP fields
    info["flow"] = parts[estab_idx + 3] + "+" + parts[estab_idx + 4]

    for i, part in enumerate(parts):
        if part == "send":
            tp["send"] = bps_str_to_numeric(parts[i+1])
        if part == "delivery_rate":
            tp["delivery_rate"] = bps_str_to_numeric(parts[i+1])
        if part.startswith("rtt:"):
            rtt, rttvar = part.split("rtt:")[1].split("/")
            info["rtt"] = float(rtt)
            info["rttvar"] = float(rttvar)
        if part.startswith("bytes_sent:"):
            bytes_sent = int(part.split("bytes_sent:")[1])

    info["bytes_sent"] = bytes_sent

    # The delivery_rate provided by tcp_info seems more accurate than
    # the send rate calculated by ss, so prefer delivery_rate if available
    if len(tp) > 0:
        info["throughput"] = tp.get("delivery_rate", tp.get("send"))

    # If application doesn't send data, it apparently reuses
    # stats from when application last sent data (so these stats are
    # not really valid)
    if flow_bytes_history is not None:
        last_bytes_sent = flow_bytes_history.get(info["flow"], 0)
        if last_bytes_sent == bytes_sent:
            info.pop("throughput", None)
            info.pop("rtt", None)
            info.pop("rttvar", None)
        flow_bytes_history[info["flow"]] = bytes_sent

    return info


def bps_str_to_numeric(bps_str):
    for prefix, factor in (("M", 1e6), ("K", 1e3), ("", 1)):
        if bps_str.endswith(prefix + "bps"):
            return float(bps_str[:-3 - len(prefix)]) * factor
    raise ValueError("{} format does not appear to be a valid bps string".format(bps_str))


def filter_likely_main_flows(flow_dfs, thresh=1e6, min_entries=5,
                             agg_func=np.median):
    return {flow: data for flow, data in flow_dfs.items()
            if agg_func(data["throughput"]) > thresh and
            len(data["throughput"]) > min_entries}


def summarize_flows(flow_dfs):
    fields = ("throughput", "rtt", "rttvar")
    mean_fields = ("rtt", "rttvar")
    if len(flow_dfs) < 1:
        return None

    start = min(df["timestamp"].values[0] for df in flow_dfs.values())
    end = max(df["timestamp"].values[-1] for df in flow_dfs.values())

    step = np.timedelta64(1, "s") if np.issubdtype(start, np.datetime64) else 1.0
    ts = np.arange(start, end+1, step)

    ts_entries = {t: {field: {"sum": 0, "n": 0} for field in fields} for t in ts}

    for flow, df in flow_dfs.items():
        for row in range(len(df)):
            t = df["timestamp"].values[row]
            for field in fields:
                val = df[field].values[row]
                ts_entries[t][field]["sum"] += val
                ts_entries[t][field]["n"] += 1

    cleaned_entries = {t: dict() for t in ts_entries.keys()}
    for t, entry in ts_entries.items():
        for field, val in entry.items():
            if val["n"] < 1:
                cleaned_entries.pop(t, None)
                break
            cleaned_entries[t][field] = val["sum"]/val["n"] if field in mean_fields else val["sum"]

    sum_df = pd.DataFrame.from_dict(cleaned_entries, orient="index")
    sum_df.index.name = "timestamp"
    sum_df.reset_index(inplace=True)
    return sum_df


def plot_throughput_timeseries(flow_dfs, max_groups=0, stat_kwargs=None,
                               **kwargs):
    if "all" not in flow_dfs:
        flow_dfs["all"] = summarize_flows(flow_dfs)
    stat_kws = {"fmt": "{:.4e}"}
    if stat_kwargs is not None:
        stat_kws.update(stat_kwargs)
    axes = complot.plot_pergroup_timeseries(flow_dfs, "throughput",
                                            max_groups=max_groups,
                                            stat_kwargs=stat_kws, **kwargs)
    axes.set_ylabel("Throughput (bps)")
    _, ymax = axes.get_ylim()
    axes.set_ylim(0, 1.05*ymax)
    return axes


def plot_rtt_timeseries(flow_dfs, max_groups=0, stat_kwargs=None, **kwargs):
    if "all" not in flow_dfs:
        flow_dfs["all"] = summarize_flows(flow_dfs)

    stat_kws = {"fmt": "{:.2f}"}
    if stat_kwargs is not None:
        stat_kws.update(stat_kwargs)
    axes = complot.plot_pergroup_timeseries(flow_dfs, "rtt", normalize_all=False,
                                            max_groups=max_groups,
                                            stat_kwargs=stat_kws, **kwargs)
    axes.set_ylabel("RTT (ms)")
    axes.set_ylim(0)
    return axes


def plot_ss_tcp_data(flow_dfs, title=None, **kwargs):
    fig, axes = plt.subplots(2, 1, figsize=(8, 8), constrained_layout=True)
    plot_throughput_timeseries(flow_dfs, axes=axes[0])
    plot_rtt_timeseries(flow_dfs, axes=axes[1])

    if title is not None:
        fig.suptitle(title)

    # Hack fix for it to render correctly on older matplotlib
    # https://stackoverflow.com/a/59341086
    fig.canvas.draw()
    fig.canvas.draw()

    return fig


def main():
    parser = argparse.ArgumentParser(description="Visualize ss -tiO log")
    parser.add_argument("-i", "--input", type=str, help="ss -tiO log file",
                        required=True)
    parser.add_argument("-o", "--output", type=str, help="image output file",
                        required=False)
    parser.add_argument("-T", "--title", type=str, help="figure title",
                        required=False)
    parser.add_argument("-d", "--dst-filter", type=str, help="only include flows to dst",
                        required=False)
    parser.add_argument("-g", "--guess-flows", help="guess which flows to include",
                        action="store_true", required=False)
    args = parser.parse_args()

    data = load_ss_tcp_data(args.input, dst=args.dst_filter,
                            filter_main_flows=args.guess_flows)
    fig = plot_ss_tcp_data(data)

    if args.output is not None:
        fig.savefig(args.output, bbox_inches="tight")
    else:
        plt.show()

    return


if __name__ == "__main__":
    main()
