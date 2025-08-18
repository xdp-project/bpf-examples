# Practical BPF examples

This git repository contains a diverse set of **practical BPF examples** that
solve (or demonstrate) a specific use-case using BPF.

It is meant to ease doing **rapid prototyping and development**, writing C-code
BPF programs using libbpf.  The goal is to make it **easier for developers** to
get started coding.

Many developers struggle to get a working BPF build environment.  The repo
enviroment makes it easy to build/compile BPF programs by doing the necessary
libbpf setup transparently and detect missing compile dependencies (via the
[configure](configure) script). It is a declared goal to **make BPF programming
more consumable** by detecting and reporting issues (when possible).

## Missing clang errno support

If you get the following output from configure:
> clang errno support: no - some examples will fail and won't be compiled from the top-level Makefile. See README.md.

This means that you are missing a header file that is included in a 32-bit
architecture header file. Some of the examples in the repository will compile
fine without this header file. The build system will automatically exclude the
examples that require the header from the build if the header is missing.
Manually compiling the utilities excluded will fail in this case.

### To fix the error:
- On Fedora install:
  -  dnf install glibc-devel.i686
- On Debian install:"
  -  apt install libc6-dev-i386

