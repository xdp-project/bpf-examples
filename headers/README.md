# NOTICE

This directory contains include header files needed to compile BPF programs.

The files are either copied from the kernel source (in subdir [linux/](linux))
or "shadow" files that contain useful defines that are often used in kernel
headers.

For example [bpf/compiler.h](bpf/compiler.h) contains practical compile macros
like `READ_ONCE` and `WRITE_ONCE` with verifier workarounds via
`bpf_barrier()`.  And the `likely()` + `unlikely()` annotations.

The include file [linux/bpf.h](linux/bpf.h) is the most central file that all
BPF (kernel-side) programs include.  It is maintained in this directory,
because this project knows what BPF features it uses, which makes the update
cycle tied to the project itself.  We prefer not to depend on the OS distro
kernel headers version of this file. (Hint, due to the use of `enum` instead of
`define` the usual macro C-preprocessor define detection will not work. This is
done on purpose to discourage userspace from detecting features via header file
defines.).
