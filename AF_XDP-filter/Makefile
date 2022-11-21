# SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)


STSTEM_LIBBPF := y
BPF_TARGETS  := af_xdp_kern
USER_TARGETS := af_xdp_user filter-xdp_stats
USER_TARGETS_OBJS := common_params.o common_user_bpf_xdp.o

# Note: Not using the libbpf in the examples. Instead, use the 'latest' (1.0) libbpf
LIBBPF_DIR = ../../libbpf/src/
COMMON_DIR = ../common/
LIB_DIR = ../lib/
 

include $(LIB_DIR)/common.mk
CFLAGS += -pthread
LDFLAGS += -pthread
LIBS += -lxdp -lz
