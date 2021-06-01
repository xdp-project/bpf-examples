# SPDX-License-Identifier: GPL-2.0

# The BPF tracing header (/usr/include/bpf/bpf_tracing.h) need to know
# CPU architecture due to PT_REGS_PARM resolution of ASM call convention
ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/' | sed 's/ppc64le/powerpc/' | sed 's/mips.*/mips/')

USER_TARGETS := ktrace01
BPF_TARGETS  := ktrace01_kern

LIB_DIR = ../lib

include $(LIB_DIR)/common.mk

BPF_CFLAGS += -D__TARGET_ARCH_$(ARCH)
