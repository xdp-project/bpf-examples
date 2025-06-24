# SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)

USER_TARGETS   := trie-free-latency
BPF_TARGETS    := trie-free-latency.bpf stats.bpf
BPF_SKEL_OBJ   := trie-free-latency.bpf.o stats.bpf.o

EXTRA_DEPS += trie.h
LDLIBS     += -lm

LIB_DIR = ../lib

include $(LIB_DIR)/common.mk

