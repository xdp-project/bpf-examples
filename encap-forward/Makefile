# SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)

USER_TARGETS :=
BPF_TARGETS := xdp_encap tc_bpf_encap
EXTRA_DEPS := encap.h
EXTRA_CFLAGS := $(if $(IPV6),-DIPV6)

LIB_DIR = ../lib

include $(LIB_DIR)/common.mk
