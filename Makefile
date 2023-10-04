# SPDX-License-Identifier: GPL-2.0
# Top level Makefile for bpf-examples

ifeq ("$(origin V)", "command line")
VERBOSE = $(V)
endif
ifndef VERBOSE
VERBOSE = 0
endif

ifeq ($(VERBOSE),0)
MAKEFLAGS += --no-print-directory
Q = @
endif

SUBDIRS := encap-forward
SUBDIRS += ktrace-CO-RE
SUBDIRS += lsm-nobpf
SUBDIRS += nat64-bpf
SUBDIRS += pkt-loop-filter
SUBDIRS += pping
SUBDIRS += preserve-dscp
SUBDIRS += tc-basic-classifier
SUBDIRS += tc-policy
SUBDIRS += traffic-pacing-edt
SUBDIRS += AF_XDP-forwarding
SUBDIRS += AF_XDP-example
SUBDIRS += xdp-synproxy

.PHONY: check_submodule help clobber distclean clean $(SUBDIRS)

all: lib $(SUBDIRS)

lib: config.mk check_submodule
	@echo; echo $@; $(MAKE) -C $@

$(SUBDIRS): lib
	@echo; echo $@; $(MAKE) -C $@

help:
	@echo "Make Targets:"
	@echo " all                 - build binaries"
	@echo " clean               - remove products of build"
	@echo " distclean           - remove configuration and build"
	@echo " install             - install binaries on local machine"
	@echo " test                - run test suite"
	@echo " archive             - create tarball of all sources"
	@echo ""
	@echo "Make Arguments:"
	@echo " V=[0|1]             - set build verbosity level"

config.mk: configure
	sh configure

check_submodule:
	@if [ -d .git ] && `git submodule status lib/libbpf | grep -q '^+'`; then \
		echo "" ;\
		echo "** WARNING **: git submodule SHA-1 out-of-sync" ;\
		echo " consider running: git submodule update"  ;\
		echo "" ;\
	fi\

clobber:
	touch config.mk
	$(MAKE) clean
	rm -f config.mk cscope.* compile_commands.json

distclean: clobber

clean: check_submodule
	$(Q)for i in $(SUBDIRS); \
	do $(MAKE) -C $$i clean; done
	$(Q)$(MAKE) -C lib clean

compile_commands.json: clean
	compiledb make V=1
