# SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)

USER_TARGETS   := xdq-tester
BPF_TARGETS    := $(patsubst %.c,%,$(wildcard *.bpf.c))

USER_LIBS = -llua -ldl -lm

LIB_DIR = ../lib

include $(LIB_DIR)/common.mk
