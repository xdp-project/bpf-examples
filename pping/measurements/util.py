import numpy as np
import gzip
import lzma


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
