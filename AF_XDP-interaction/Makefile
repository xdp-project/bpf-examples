# SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)

USER_TARGETS   := af_xdp_user
BPF_TARGETS    := af_xdp_kern

# Define C-code objects USER_TARGETS needs
USER_TARGETS_OBJS := common_params.o common_user_bpf_xdp.o

LDLIBS     += -pthread

LIB_DIR = ../lib

include $(LIB_DIR)/common.mk
