# SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)

USER_TARGETS   := tc_txq_policy
BPF_TARGETS    := tc_txq_policy_kern

# Depend on bpftool for auto generating
# skeleton header file tc_txq_policy_kern.skel.h
#
BPF_SKEL_OBJ := tc_txq_policy_kern.o

LIB_DIR = ../lib

include $(LIB_DIR)/common.mk
