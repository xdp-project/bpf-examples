# SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)

USER_TARGETS :=
BPF_TARGETS := tc_bpf_inc_pkt_size
BPF_TARGETS += tc_mtu_enforce
EXTRA_DEPS := encap.h

LIB_DIR = ../lib

include $(LIB_DIR)/common.mk

ifndef HAVE_TC_LIBBPF
# If the iproute2 'tc' tool doesn't understand BTF debug info
# use llvm-strip to remove this debug info from object file
#
# *BUT* cannot strip everything as it removes ELF elems needed for
#  creating maps
#
.PHONY: strip_tc_obj
strip_tc_obj: tc_bpf_inc_pkt_size.o
	$(Q) llvm-strip --no-strip-all --remove-section .BTF $?

all: strip_tc_obj
endif
