# SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)

USER_TARGETS   := nat64
BPF_TARGETS    := nat64_kern
BPF_SKEL_OBJ := nat64_kern.o

#LDLIBS     += -pthread
USER_LIBS = -lmnl
EXTRA_DEPS += nat64.h

LIB_DIR = ../lib

include $(LIB_DIR)/common.mk
