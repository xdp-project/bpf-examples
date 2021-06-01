# SPDX-License-Identifier: GPL-2.0

USER_TARGETS := ktrace01
BPF_TARGETS  := ktrace01_kern

LIB_DIR = ../lib

include $(LIB_DIR)/common.mk

BPF_CFLAGS += -D__TARGET_ARCH_$(ARCH)
