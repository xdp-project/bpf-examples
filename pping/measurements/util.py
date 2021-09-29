import os
import gzip
import lzma

def guess_compression(filename):
    if filename.endswith(".gz"):
        return "gzip"
    elif filename.endswith(".xz"):
        return "xz"
    else:
        return "none"

def open_compressed_file(filename, compression="auto", **kwargs):
    open_funcs = {"none":open, "gzip":gzip.open, "xz":lzma.open}
    if compression == "auto":
        compression = guess_compression(filename)

    return open_funcs[compression](filename, **kwargs)

def get_first_dict_entry(dictionary):
    if len(dictionary) < 1:
        raise ValueError("dictionary is empty")
    return next(iter(dictionary.values()))
