# SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)

USER_TARGETS   := af_xdp_user
USER_TARGETS   += btf_unit_test
BPF_TARGETS    := af_xdp_kern
BPF_TARGETS    += btf_unit_test_bpf

# Define C-code objects USER_TARGETS needs
USER_TARGETS_OBJS := common_params.o common_user_bpf_xdp.o
USER_TARGETS_OBJS += hashmap.o lib_xsk_extend.o
USER_TARGETS_OBJS += ethtool_utils.o

# The USER_TARGETS_OBJS have a dependency of this header file
USER_TARGETS_OBJS_DEPS += common_defines.h

LDLIBS     += -lpthread
LDLIBS     += -lrt

LIB_DIR = ../lib

include $(LIB_DIR)/common.mk
