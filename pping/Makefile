# SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)

USER_TARGETS   := pping
BPF_TARGETS    := pping_kern

LDLIBS     += -pthread
EXTRA_DEPS += pping.h pping_debug_cleanup.h

LIB_DIR = ../lib

include $(LIB_DIR)/common.mk
