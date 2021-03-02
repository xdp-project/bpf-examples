# SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)

USER_TARGETS   := pping
TC_BPF_TARGETS := pping_kern_tc
BPF_TARGETS    := pping_kern_xdp
BPF_TARGETS    += $(TC_BPF_TARGETS)

LDFLAGS    += -pthread
EXTRA_DEPS += pping.h pping_helpers.h

LIB_DIR = ../lib

include $(LIB_DIR)/common.mk
