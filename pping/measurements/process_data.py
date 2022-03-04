#!/bin/env python3

import sys
import os
import pathlib
import time
import re
import argparse
import numpy as np
import pandas as pd

import sar_data_loading as sdl
import ss_tcp_viz
import util

label_folder_map = {"baseline": "no_pping",
                    "PPing": "k_pping", "ePPing": "e_pping"}


def get_test_interval(sub_folder, omit=0, omit_end=1):
    start, end = None, None
    with open(os.path.join(sub_folder, "test_interval.log"), "rt") as file:
        lines = file.readlines()
    start = np.datetime64(lines[0].split("Start: ")[1][:19])
    start += np.timedelta64(omit, "s")
    end = np.datetime64(lines[1].split("End: ")[1][:19])
    end -= np.timedelta64(omit_end, "s")
    return start, end


def get_sarfile(sub_folder):
    sarfiles = list(pathlib.Path(sub_folder, "M2").glob("M2_stats.sar*"))
    if len(sarfiles) > 1:
        print("Warning: Multiple sar files in {}, returning first".format(
              os.path.join(sub_folder, "M2")), file=sys.stderr)
    return sarfiles[0] if len(sarfiles) > 0 else None


def get_ss_tcp_file(subfolder):
    tcpfiles = list(pathlib.Path(subfolder, "M1").glob("ss_tcp.log*"))
    if len(tcpfiles) > 1:
        print("Warning: Multiple tcp-files in {}, returning first".format(
               os.path.join(subfolder, "M1")), file=sys.stderr)
    return tcpfiles[0] if len(tcpfiles) > 0 else None


def get_pping_file(subfolder):
    pping_files = list(pathlib.Path(subfolder, "M2").glob("pping.out*"))
    if len(pping_files) > 1:
        print("Warning: Multiple pping files in {}, returning first".format(
               os.path.join(subfolder, "M2")), file=sys.stderr)
    return pping_files[0] if len(pping_files) > 0 else None


def _parse_timestamp(date, t_str):
    """
    Returns a datetime from combining the timestring date like dateTHH:MM:SS
    """
    return np.datetime64(date + "T" + t_str, "ns")


def datetime64_truncate(dt, unit):
    return dt.astype("datetime64[{}]".format(unit)).astype(dt.dtype)


def _count_pping_messages(filename, parsing_func, keys, date=None,
                          norm_timestamps=True, filter_timerange=None,
                          **kwargs):
    """
    Count nr of rtt-events per second from some line-based output from pping.
    If passed, date should be string in YYYY-MM-DD format.
    """
    if date is None:
        date = time.strftime("%Y-%m-%d", time.gmtime())

    step_size = np.timedelta64(1, "s")
    midnight_gap_tresh = np.timedelta64(-1, "h")

    count = {"timestamp": list()}
    for key in keys:
        count[key] = [0]

    with util.open_compressed_file(filename, mode="rt") as file:
        for line in file:
            t, increments = parsing_func(line, date, **kwargs)
            if t is None:
                continue

            if len(count["timestamp"]) == 0:
                count["timestamp"].append(datetime64_truncate(t, "s"))

            t_diff = t - count["timestamp"][-1]
            if t_diff < midnight_gap_tresh:
                t += np.timedelta64(1, "D")
                t_diff = t - count["timestamp"][-1]

            if t_diff >= step_size:
                for missing_t in np.arange(count["timestamp"][-1], t+1,
                                           step_size)[1:]:
                    count["timestamp"].append(missing_t)
                    for key in keys:
                        count[key].append(0)

            for key in increments:
                count[key][-1] += 1

    if len(count["timestamp"]) == 0:
        return None

    count = pd.DataFrame(count)
    ref = None
    if filter_timerange is not None:
        count = count.loc[count["timestamp"].between(*filter_timerange)]
        count.reset_index(drop=True, inplace=True)
        ref = filter_timerange[0]
    if norm_timestamps:
        count["timestamp"] = util.normalize_timestamps(count["timestamp"], reference=ref)

    return count


def parse_epping_message(line, date, src_ip=None):
    words = line.split()
    if len(words) < 7:
        return None, None

    t = _parse_timestamp(date, words[0])

    increments = ["all_events"]
    if words[2] == "ms":
        increments.append("rtt_events")
        if src_ip is not None and words[-1].split(":")[0] == src_ip:
            increments.append("filtered_rtt_events")

    return t, increments


def parse_kpping_message(line, date, src_ip=None):
    words = line.split()
    if len(words) != 4:
        return None, None

    t = _parse_timestamp(date, words[0])

    increments = ["rtt_events"]
    if src_ip is not None and words[-1].split(":")[0] == src_ip:
        increments.append("filtered_rtt_events")

    return t, increments


def count_epping_messages(root_folder, src_ip=None, omit=0):
    """
    Count nr of rtt-events per second from the standard output of eBPF pping.
    The columns "filtered_rtt_events" is rtt-events from src_ip
    The column "all_events" includes both rtt-events and flow-events
    """

    sub_path = pathlib.Path(root_folder, "e_pping")
    test_interval = get_test_interval(sub_path, omit)
    date = str(get_test_interval(sub_path)[0])[:10]
    file = get_pping_file(sub_path)
    if file is None:
        print("Warning: No PPing file in {}".format(root_folder),
              file=sys.stderr)
        return None

    keys = ["all_events", "rtt_events"]
    if src_ip is not None:
        keys.append("filtered_rtt_events")

    return _count_pping_messages(file, parse_epping_message, keys, date=date,
                                 filter_timerange=test_interval, src_ip=src_ip)


def count_kpping_messages(root_folder, src_ip=None, omit=0):
    """
    Count nr of rtt-events per second from the standard output of Kathie's pping.
    The columns "filtered_rtt_events" is rtt-events from src_ip
    """

    sub_path = pathlib.Path(root_folder, "k_pping")
    test_interval = get_test_interval(sub_path, omit)
    date = str(get_test_interval(sub_path)[0])[:10]
    file = get_pping_file(sub_path)
    if file is None:
        print("Warning: No PPing file in {}".format(root_folder),
              file=sys.stderr)
        return None

    keys = ["rtt_events"]
    if src_ip is not None:
        keys.append("filtered_rtt_events")

    return _count_pping_messages(file, parse_kpping_message, keys, date=date,
                                 filter_timerange=test_interval, src_ip=src_ip)


def load_cpu_data(root_folder, omit=0):
    load_dict = dict()
    for label, folder in label_folder_map.items():
        subfolder = os.path.join(root_folder, folder)
        test_interval = get_test_interval(subfolder, omit)
        sarfile = get_sarfile(subfolder)
        if sarfile is None:
            continue

        j_data = sdl.load_sar_cpu_data(sarfile)
        data = sdl.to_percpu_df(j_data, filter_timerange=test_interval)

        load_dict[label] = data["all"].copy()

    return load_dict


def load_network_data(root_folder, interface="ens192", omit=0):
    net_dict = dict()
    for label, folder in label_folder_map.items():
        subfolder = os.path.join(root_folder, folder)
        test_interval = get_test_interval(subfolder, omit)
        sarfile = get_sarfile(subfolder)
        if sarfile is None:
            continue

        j_data = sdl.load_sar_network_data(get_sarfile(subfolder))
        data = sdl.to_perinterface_df(j_data, filter_timerange=test_interval)

        net_dict[label] = data[interface].copy()

    return net_dict


def load_tcp_data(root_folder, omit=0, dst=None, include_individual_flows=False):
    tcp_dict = dict()
    for label, folder in label_folder_map.items():
        subfolder = os.path.join(root_folder, folder)
        test_interval = get_test_interval(subfolder, omit=omit)
        tcpfile = get_ss_tcp_file(subfolder)
        if tcpfile is None:
            continue

        data = ss_tcp_viz.load_ss_tcp_data(tcpfile, norm_timestamps=True,
                                           filter_timerange=test_interval,
                                           sum_flows=True, dst=dst,
                                           filter_main_flows=True)
        if include_individual_flows:
            tcp_dict[label] = util.pergroup_dict_to_df(data, "flow")
        else:
            tcp_dict[label] = data["all"].copy()
    return tcp_dict


def load_pping_reports(root_folder, **kwargs):
    pping_dict = dict()

    pping_data = count_kpping_messages(root_folder, **kwargs)
    if pping_data is not None:
        pping_dict["PPing"] = pping_data

    pping_data = count_epping_messages(root_folder, **kwargs)
    if pping_data is not None:
        pping_dict["ePPing"] = pping_data

    return pping_dict


def valid_run_n(string):
    return True if re.search("^run_\d+$", string) else False


def valid_n_streams(string):
    return True if re.search("^\d+_streams$", string) else False


def _run_n_key(string):
    if valid_run_n(string):
        return int(string.split("_")[-1])
    return -1


def _n_streams_key(string):
    if valid_n_streams(string):
        return int(string.split("_")[0])
    return -1


def _load_all(root_folder, read_func, **kwargs):
    all_data = dict()
    path = root_folder
    for run in sorted(os.listdir(root_folder), key=_run_n_key):
        path = os.path.join(root_folder, run)
        if valid_run_n(run) and os.path.isdir(path):

            for n_streams in sorted(os.listdir(path), key=_n_streams_key):
                path = os.path.join(root_folder, run, n_streams)
                if valid_n_streams(n_streams) and os.path.isdir(path):
                    if n_streams not in all_data:
                        all_data[n_streams] = dict()

                    data = read_func(path, **kwargs)
                    for setup, sdata in data.items():
                        if setup not in all_data[n_streams]:
                            all_data[n_streams][setup] = dict()
                        all_data[n_streams][setup][run] = sdata

    for stream_data in all_data.values():
        for setup in list(stream_data.keys()):
            if len(stream_data[setup]) > 0:
                stream_data[setup] = util.pergroup_dict_to_df(
                    stream_data[setup], "run")
            else:
                del stream_data[setup]

    for n_streams in list(all_data.keys()):
        if len(all_data[n_streams]) < 1:
            del all_data[n_streams]
    return all_data


def load_all_cpu_data(root_folder, omit=0):
    return _load_all(root_folder, load_cpu_data, omit=omit)


def load_all_network_data(root_folder, interface="ens192", omit=0):
    return _load_all(root_folder, load_network_data, interface=interface,
                     omit=omit)


def load_all_tcp_data(root_folder, omit=0, dst=None,
                      include_individual_flows=False):
    return _load_all(root_folder, load_tcp_data, omit=omit, dst=dst,
                     include_individual_flows=include_individual_flows)


def load_all_pping_reports(root_folder, omit=0, src_ip=None):
    return _load_all(root_folder, load_pping_reports, omit=omit, src_ip=src_ip)


def load_all_data(root_folder, cpu=True, network=True, pping=True, tcp=True,
                  tcp_flows=False, omit=0, interface="ens3f1", dst="10.70.2.2"):
    data = dict()
    if cpu:
        data["cpu"] = load_all_cpu_data(root_folder, omit=omit)
    if network:
        data["network"] = load_all_network_data(root_folder, omit=omit,
                                                interface=interface)
    if pping:
        data["pping"] = load_all_pping_reports(root_folder, omit=omit,
                                               src_ip=dst)
    if tcp:
        data["tcp"] = load_all_tcp_data(root_folder, omit=omit, dst=dst,
                                        include_individual_flows=False)
    if tcp_flows:
        data["tcp_flows"] = load_all_tcp_data(root_folder, omit=omit, dst=dst,
                                              include_individual_flows=True)
    return data


def flatten_per_pping_dict(per_pping_dict):
    return util.pergroup_dict_to_df(per_pping_dict, "pping_setup")


def flatten_per_pping_reports_dict(per_pping_dict):
    per_pping_dict = per_pping_dict.copy()
    ref_df = per_pping_dict.get("PPing", per_pping_dict.get("ePPing")).copy()

    if ref_df is not None:
        if "ePPing" in per_pping_dict:
            per_pping_dict["ePPing"] = per_pping_dict["ePPing"][ref_df.columns]

        ref_df["rtt_events"] = 0
        if "filtered_rtt_events" in ref_df.columns:
            ref_df["filtered_rtt_events"] = 0
        if "all_events" in ref_df.columns:
            ref_df["all_events"] = 0

        per_pping_dict["baseline"] = ref_df

    return util.pergroup_dict_to_df(per_pping_dict, "pping_setup")


def flatten_per_flow_dict(per_flow_dict,
                          flatten_inner_func=flatten_per_pping_dict):
    flat_flow_dict = dict()
    for n_flows, data in per_flow_dict.items():
        if isinstance(data, pd.DataFrame):
            flat_flow_dict[n_flows] = data
        else:
            flat_flow_dict[n_flows] = flatten_inner_func(data)

    return util.pergroup_dict_to_df(flat_flow_dict, "n_flows")


def merge_all_data(data):
    join_cols = ["n_flows", "pping_setup", "run", "timestamp"]
    flat_data = dict()

    for data_type in data.keys():
        if data_type == "tcp_perflow":
            continue
        if len(data[data_type]) < 0:
            continue

        if not isinstance(data[data_type], pd.DataFrame):
            flat_func = (flatten_per_pping_reports_dict if data_type == "pping"
                         else flatten_per_pping_dict)
            df = flatten_per_flow_dict(data[data_type],
                                       flatten_inner_func=flat_func)
        else:
            df = data[data_type]

        flat_data[data_type] = \
            util.add_column_prefix_to_df(df, data_type + "_",
                                         exclude_cols=join_cols)

    if len(flat_data) < 1:
        raise ValueError("Cannot merge empty data")

    return util.join_dataframes([df for df in flat_data.values()], on=join_cols)


def main():
    parser = argparse.ArgumentParser("Read and merge data to singular CSV file")
    parser.add_argument("-i", "--input", type=str, required=True,
                        help="root folder of the results from run_tests.sh")
    parser.add_argument("-o", "--output", type=str, required=True,
                        help="output csv file")
    parser.add_argument("-d", "--dst", type=str,
                        help="dst ip used to filter tcp flows and pping reports",
                        required=False, default=None)
    parser.add_argument("-I", "--interface", type=str,
                        help="interface pping is running on",
                        required=False, default="ens3f1")
    parser.add_argument("-O", "--omit", type=int,
                        help="nr seconds to omit from start of test",
                        required=False, default=0)
    parser.add_argument("-A", "--all", action="store_true", required=False,
                        help="Include all types of data (except tcp-flows)")
    parser.add_argument("-C", "--cpu", action="store_true", required=False,
                        help="Include cpu data")
    parser.add_argument("-N", "--network", action="store_true", required=False,
                        help="Include network data")
    parser.add_argument("-P", "--pping", action="store_true", required=False,
                        help="Include pping data")
    parser.add_argument("-T", "--tcp", action="store_true", required=False,
                        help="Include (summarized) TCP data")
    parser.add_argument("-F", "--tcp-flows", action="store_true",
                        required=False,
                        help="Include per-flow TCP data (exclusive, cannot be merged with other types of data)")
    args = parser.parse_args()

    if not (args.cpu or args.network or args.pping or
            args.tcp or args.tcp_flows):
        args.all = True

    if args.all:
        args.cpu = True
        args.network = True
        args.pping = True
        args.tcp = True

    if args.tcp_flows and (args.cpu or args.network or args.pping or args.tcp):
        print("Error: Cannot merge tcp-flows with any other data type",
              file=sys.stderr)
        return

    if args.tcp_flows:
        data = load_all_tcp_data(args.input, omit=args.omit, dst=args.dst)
        df = flatten_per_flow_dict(data)
    else:
        data = load_all_data(args.input, cpu=args.cpu, network=args.network,
                             pping=args.pping, tcp=args.tcp, omit=args.omit,
                             interface=args.interface, dst=args.dst)
        df = merge_all_data(data)

    df.to_csv(args.output)


if __name__ == "__main__":
    main()
