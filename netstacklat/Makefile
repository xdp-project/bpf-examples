# SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)

USER_TARGETS   := netstacklat
BPF_TARGETS    := netstacklat.bpf
BPF_SKEL_OBJ   := netstacklat.bpf.o

EXTRA_DEPS += netstacklat.h bits.bpf.h
LDLIBS     += -lm

LIB_DIR = ../lib

include $(LIB_DIR)/common.mk

