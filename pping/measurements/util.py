import numpy as np
import pandas as pd
import gzip
import lzma
import subprocess


def guess_compression(filename):
    if str(filename).endswith(".gz"):
        return "gzip"
    elif str(filename).endswith(".xz"):
        return "xz"
    else:
        return "none"


def open_compressed_file(filename, compression="auto", **kwargs):
    open_funcs = {"none": open, "gzip": gzip.open, "xz": lzma.open}
    if compression == "auto":
        compression = guess_compression(filename)

    return open_funcs[compression](filename, **kwargs)


def xz_decompress_file(filename):
    subprocess.run(["xz", "-dk", filename], check=True)


def normalize_timestamps(timestamps, reference=None):
    if reference is None:
        reference = np.min(timestamps)
    normed = np.subtract(timestamps, reference)

    if np.issubdtype(normed.dtype, np.timedelta64):
        normed = np.divide(normed, np.timedelta64(1, "s"))

    return normed


def get_first_dict_entry(dictionary):
    if len(dictionary) < 1:
        raise ValueError("dictionary is empty")
    return next(iter(dictionary.values()))


def add_column_prefix_to_df(df, prefix="", include_cols=None,
                            exclude_cols=None):
    if include_cols is None:
        include_cols = df.columns
    if exclude_cols is None:
        exclude_cols = []
    return df.rename(columns={col: prefix + col for col in include_cols
                              if col not in exclude_cols})


def pergroup_dict_to_df(per_group_dict, group_name, reset_index=True):
    df = pd.concat([df for df in per_group_dict.values()],
                   keys=[group for group in per_group_dict.keys()],
                   names=[group_name]).reset_index(group_name)
    if reset_index:
        df.reset_index(drop=True, inplace=True)
    return df


def df_to_pergroup_dict(df, groupby_col, **kwargs):
    cols = [col for col in df.columns if col != groupby_col]
    return {group: data[cols].copy() for
            group, data in df.groupby(groupby_col, **kwargs)}


def join_dataframes(dfs, on, how="outer", multi_index=True, **kwargs):
    merged_df = None
    for df in dfs:
        df = df.set_index(on)
        merged_df = df if merged_df is None else merged_df.join(df, how=how, **kwargs)

    if not merged_df.index.is_unique:
        print("Warning: Non-unique index")
    if not multi_index:
        merged_df.reset_index(level=on, inplace=True)
    return merged_df
