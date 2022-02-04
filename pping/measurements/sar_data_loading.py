import json
import subprocess
import os

import numpy as np
import pandas as pd

import util


def _run_on_xz_file(func, filename, *args, **kwargs):
    filename = str(filename)
    orig_filename = filename

    if filename.endswith(".xz"):
        util.xz_decompress_file(filename)
        filename = filename[:-3]

    try:
        res = func(filename, *args, **kwargs)
    finally:
        if filename != orig_filename:
            os.remove(filename)

    return res


def _load_sar_network_data(filename):

    p = subprocess.run(["sadf", "-j", filename, "--", "-n", "DEV", "-n", "EDEV"],
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if p.returncode != 0:
        raise ChildProcessError("sadf failed: {}".format(p.stderr))
    return json.loads(p.stdout)["sysstat"]["hosts"][0]


def load_sar_network_data(filename):
    return _run_on_xz_file(_load_sar_network_data, filename)


def _load_sar_cpu_data(filename):

    p = subprocess.run(["sadf", "-j", filename, "--", "-P", "ALL", "-u", "ALL"],
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if p.returncode != 0:
        raise ChildProcessError("sadf failed: {}".format(p.stderr))
    return json.loads(p.stdout)["sysstat"]["hosts"][0]


def load_sar_cpu_data(filename):
    return _run_on_xz_file(_load_sar_cpu_data, filename)


def get_timestamps(sar_json):
    ts = [entry["timestamp"]["date"] + "T" + entry["timestamp"]["time"]
          for entry in sar_json["statistics"]]
    return np.array(ts, dtype="datetime64")


def to_perinterface_df(sar_json, filter_timerange=None, norm_timestamps=True):
    dev_keymap = {"rxbps": "rxkB", "txbps": "txkB", "rxpps": "rxpck", "txpps": "txpck"}
    edev_keymap = {key: key for key in ["rxdrop", "txdrop", "rxerr", "txerr"]}
    interface_data = dict()

    ts = get_timestamps(sar_json)

    for period in sar_json["statistics"]:
        for if_entry in period["network"]["net-dev"]:
            iface = if_entry["iface"]

            if iface not in interface_data:
                interface_data[iface] = {key: [] for key in
                                         (list(dev_keymap.keys())
                                          + list(edev_keymap.keys()))}
            for key1, key2 in dev_keymap.items():
                interface_data[iface][key1].append(if_entry[key2])

        for if_entry in period["network"]["net-edev"]:
            iface = if_entry["iface"]
            for key1, key2 in edev_keymap.items():
                interface_data[iface][key1].append(if_entry[key2])

    interface_data = _groupwise_dict_to_df(interface_data, ts,
                                           filter_timerange, norm_timestamps)
    for iface, df in interface_data.items():
        df["rxbps"] = df["rxbps"] * 8 * 1000
        df["txbps"] = df["txbps"] * 8 * 1000

    return interface_data


def to_percpu_df(sar_json, norm_timestamps=True, filter_timerange=None):
    n_cpus = sar_json["number-of-cpus"]
    ts = get_timestamps(sar_json)

    per_cpu = dict()
    for period in sar_json["statistics"]:
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

    return _groupwise_dict_to_df(per_cpu, ts, filter_timerange,
                                 norm_timestamps)


def _groupwise_dict_to_df(group_dict, ts, filter_timerange, norm_timestamps):
    group_df = dict()
    time_ref = None if filter_timerange is None else filter_timerange[0]

    for group, data in group_dict.items():
        df = pd.DataFrame(data)
        df.insert(0, "timestamp", ts)

        if filter_timerange is not None:
            df = df.loc[df["timestamp"].between(filter_timerange[0],
                                                filter_timerange[1])]
            df.reset_index(drop=True, inplace=True)

        if norm_timestamps:
            df["timestamp"] = util.normalize_timestamps(df["timestamp"], time_ref)

        group_df[group] = df

    return group_df
