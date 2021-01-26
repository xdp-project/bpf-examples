# SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)

USER_TARGETS   := pping
TC_BPF_TARGETS := pping_kern_tc
BPF_TARGETS    := pping_kern_xdp
BPF_TARGETS    += $(TC_BPF_TARGETS)

LDFLAGS    += -pthread
EXTRA_DEPS += config.mk pping.h pping_helpers.h

LIB_DIR = ../lib

include $(LIB_DIR)/common.mk
include config.mk

all: config.mk

config.mk: configure
	@sh configure

ifndef HAVE_TC_LIBBPF
# If the iproute2 'tc' tool doesn't understand BTF debug info
# use llvm-strip to remove this debug info from object file
#
# *BUT* cannot strip everything as it removes ELF elems needed for
#  creating maps
#
.PHONY: strip_tc_obj
strip_tc_obj: ${TC_BPF_TARGETS:=.o}
	$(Q) echo "TC don't support libbpf - strip BTF info"
	$(Q) llvm-strip --no-strip-all --remove-section .BTF $?

all: strip_tc_obj
endif
