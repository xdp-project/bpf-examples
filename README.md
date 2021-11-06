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
