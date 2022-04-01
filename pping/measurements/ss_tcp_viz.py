#!/bin/env python3

import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import argparse
import sys

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

    current_ts = None

    with util.open_compressed_file(filename, mode="rt") as file:
        for line in file:
            tcp_info = parse_tcp_entry(line)
            current_ts = tcp_info.get("timestamp", current_ts)
            if "flow" not in tcp_info:
                continue
            flow = tcp_info["flow"]
            if dst is not None and not flow.split("+")[1].startswith(dst):
                continue

            if flow not in flow_data:
                fields = set(list(tcp_info.keys())) - set(["timestamp", "flow"])
                flow_data[flow] = {field: [] for field in fields.union(set(["timestamp"]))}

            flow_data[flow]["timestamp"].append(tcp_info.get("timestamp", current_ts))
            for field in fields:
                flow_data[flow][field].append(tcp_info[field])

    if len(flow_data) < 1:
        return flow_data

    # Convert to dataframe and apply filters
    flow_dfs = dict()

    time_ref = (min(data["timestamp"][0] for data in flow_data.values())
                if filter_timerange is None else filter_timerange[0])

    n_dup = max(_nr_duplicated(data["timestamp"]) for
                data in flow_data.values())
    if n_dup > 0:
        print("Warning: {} duplicated timestamps in {}".format(
            n_dup, filename), file=sys.stderr)

    for flow, data in flow_data.items():
        df = _dict_to_df(data, filter_timerange, norm_timestamps, time_ref)
        if len(df) > 0:
            flow_dfs[flow] = df

    if filter_main_flows:
        filt_flows = filter_likely_main_flows(flow_dfs, **kwargs)
        if len(filt_flows) > 0:
            flow_dfs = filt_flows
        else:
            print("Warning: Attempting to filter main flows yielded no valid flows. Skipping this step")

    if sum_flows:
        flow_dfs["all"] = summarize_flows(flow_dfs)

    return flow_dfs


def _nr_duplicated(vals):
    return len(vals) - len(pd.unique(vals))


def _dict_to_df(ss_dict, filter_timerange, norm_timestamps, time_ref=None):
    df = pd.DataFrame(ss_dict).drop_duplicates(subset="timestamp")

    interval_lengths = np.empty(len(df), dtype=float)
    interval_lengths[0] = np.inf
    interval_lengths[1:] = np.diff(df["timestamp"].values)/np.timedelta64(1, "s")

    bytes_inc = df["bytes_sent"].values.copy()
    bytes_inc[1:] = np.diff(bytes_inc)
    bytes_inc[bytes_inc < 0] = 0
    df["throughput"] = bytes_inc * 8 / interval_lengths

    retrans_inc = df["retrans_tot"].values.copy()
    retrans_inc[1:] = np.diff(retrans_inc)
    retrans_inc[retrans_inc < 0] = 0
    df["retrans/s"] = retrans_inc / interval_lengths

    invalid_mask = bytes_inc == 0
    df["rtt"].values[invalid_mask] = np.nan
    df["rttvar"].values[invalid_mask] = np.nan
    df["delivery_rate"].values[invalid_mask] = 0

    if filter_timerange is not None:
        df = df.loc[df["timestamp"].between(*filter_timerange)]
        df.reset_index(drop=True, inplace=True)

    if norm_timestamps:
        df["timestamp"] = util.normalize_timestamps(df["timestamp"], time_ref)

    return df


def summarize_flows(flow_dfs, stepsize=np.timedelta64(1, "s")):
    sum_fields = ("throughput", "delivery_rate", "retrans/s")
    mean_fields = ("rtt", "rttvar")
    fields = sum_fields + mean_fields
    if len(flow_dfs) < 1:
        return None

    start = min(df["timestamp"].values[0] for df in flow_dfs.values())
    end = max(df["timestamp"].values[-1] for df in flow_dfs.values())

    step = stepsize if np.issubdtype(start, np.datetime64) else stepsize/np.timedelta64(1, "s")
    ts = np.arange(start, end+1, step)

    ts_entries = {t: {field: {"sum": 0, "n": 0} for field in fields} for t in ts}

    for flow, df in flow_dfs.items():
        for row in range(len(df)):
            t = df["timestamp"].values[row]
            for field in fields:
                val = df[field].values[row]
                if not np.isnan(val):
                    ts_entries[t][field]["sum"] += val
                    ts_entries[t][field]["n"] += 1

    cleaned_entries = {t: dict() for t in ts_entries.keys()}
    for t, entry in ts_entries.items():
        for field, val in entry.items():
            if field in mean_fields:
                cleaned_entries[t][field] = val["sum"]/val["n"] if val["n"] > 0 else np.nan
            else:
                cleaned_entries[t][field] = val["sum"]

    sum_df = pd.DataFrame.from_dict(cleaned_entries, orient="index")
    sum_df.index.name = "timestamp"
    sum_df.reset_index(inplace=True)
    return sum_df


def filter_likely_main_flows(flow_dfs, thresh=1e6, min_entries=10,
                             agg_func=np.median):
    return {flow: data for flow, data in flow_dfs.items()
            if agg_func(data["throughput"]) > thresh and
            len(data["throughput"]) > min_entries}


def parse_tcp_entry(line):
    """
    Parses a line from the output of ss -tiO, may optionally be prepended by a timestamp.
    """
    info = dict()

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

    parts = parts[estab_idx + 4:]

    info["bytes_retrans"] = parse_bytes_retrans(parts)
    info["bytes_sent"] = parse_bytes_sent(parts) - info["bytes_retrans"]
    info["delivery_rate"] = parse_delivery_rate(parts)
    rtt, rttvar = parse_rtt(parts)
    info["rtt"] = rtt
    info["rttvar"] = rttvar
    retrans, retrans_tot = parse_retrans(parts)
    info["curr_retrans"] = retrans
    info["retrans_tot"] = retrans_tot

    return info


def find_tcp_value(keyword, words, not_found_val=None):
    colon_scheme = True if keyword.endswith(":") else False

    for i, word in enumerate(words):
        if colon_scheme:
            if word.startswith(keyword):
                return word[len(keyword):]
        else:
            if word == keyword:
                return words[i+1]
    return not_found_val


def bps_str_to_numeric(bps_str):
    for prefix, factor in (("M", 1e6), ("K", 1e3), ("", 1)):
        if bps_str.endswith(prefix + "bps"):
            return float(bps_str[:-3 - len(prefix)]) * factor
    raise ValueError("{} does not appear to be a valid bps string".format(bps_str))


def parse_bytes_retrans(words):
    return int(find_tcp_value("bytes_retrans:", words, "0"))


def parse_bytes_sent(words):
    return int(find_tcp_value("bytes_sent:", words, "0"))


def parse_rtt(words):
    rtt, rttvar = find_tcp_value("rtt:", words, "NaN/NaN").split("/")
    return float(rtt), float(rttvar)


def parse_retrans(words):
    retrans, retrans_total = find_tcp_value("retrans:", words, "0/0").split("/")
    return int(retrans), int(retrans_total)


def parse_delivery_rate(words):
    return bps_str_to_numeric(find_tcp_value("delivery_rate", words, "0bps"))


def plot_throughput_timeseries(flow_dfs, max_groups=0, stat_kwargs=None,
                               plot_retrans=True, legend=True, **kwargs):
    if "all" not in flow_dfs:
        flow_dfs["all"] = summarize_flows(flow_dfs)

    stat_kws = {"fmt": "{:.4e}"}
    if stat_kwargs is not None:
        stat_kws.update(stat_kwargs)
    axes = complot.plot_pergroup_timeseries(flow_dfs, "throughput",
                                            max_groups=max_groups,
                                            stat_kwargs=stat_kws,
                                            legend=False, **kwargs)

    if plot_retrans:
        ax2 = axes.twinx()
        ax2.plot(flow_dfs["all"]["timestamp"].values, flow_dfs["all"]["retrans/s"].values,
                 color="k", linestyle="--", zorder=2.5)
        ax2.set_ylabel("Retransmissions")
        ax2.set_ylim(0)
        axes.plot([], [], color="k", linestyle="--", label="retrans/s") # legend hack

    axes.set_ylabel("Throughput (bps)")
    _, ymax = axes.get_ylim()
    axes.set_ylim(0, 1.05*ymax)
    if legend:
        axes.legend()

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
