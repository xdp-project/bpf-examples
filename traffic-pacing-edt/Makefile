# SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)

USER_TARGETS :=
BPF_TARGETS := edt_pacer01
BPF_TARGETS += edt_pacer02

LIB_DIR = ../lib

include $(LIB_DIR)/common.mk

# The iproute2 'tc' tool doesn't understand BTF debug info
# use llvm-strip to remove this debug info from object file
#
# *BUT* cannot strip everything as it removes ELF elems needed for
#  creating maps
#
.PHONY: strip_tc_obj
strip_tc_obj: ${BPF_TARGETS:=.o}
	$(Q) llvm-strip --no-strip-all --remove-section .BTF $?

all: strip_tc_obj
