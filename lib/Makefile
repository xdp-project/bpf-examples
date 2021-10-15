
LIBBPF_CFLAGS:=$(if $(CFLAGS),$(CFLAGS),-g -O2 -Werror -Wall) -fPIC

LIB_DIR = .
LIB_INSTALL := lib-install
include defines.mk

SUBDIRS=

all: $(OBJECT_LIBBPF) $(OBJECT_LIBXDP)
	@set -e; \
	for i in $(SUBDIRS); \
	do echo; echo "  $$i"; $(MAKE) -C $$i; done

.PHONY: clean
clean: libbpf_clean libxdp_clean
	@for i in $(SUBDIRS); \
	do $(MAKE) -C $$i clean; done

install:
	install -m 0755 -d $(DESTDIR)$(HDRDIR)
	$(MAKE) -C libxdp install
	$(MAKE) -C testing install


libbpf: $(OBJECT_LIBBPF)
libxdp: libbpf $(OBJECT_LIBXDP)

# Handle libbpf as git submodule
ifeq ($(SYSTEM_LIBBPF),n)
ifeq ($(VERBOSE),0)
P:= >/dev/null
endif

# Detect submodule libbpf source file changes
LIBBPF_SOURCES := $(wildcard libbpf/src/*.[ch])

libbpf/src/libbpf.a: $(LIBBPF_SOURCES)
	@echo ; echo "  libbpf"
	$(QUIET_CC)$(MAKE) -C libbpf/src CFLAGS="$(LIBBPF_CFLAGS)" $P
	$(QUIET_INSTALL)$(MAKE) -C libbpf/src DESTDIR=../../$(LIB_INSTALL) install_headers $P

.PHONY: libbpf_clean
libbpf_clean:
	$(Q)$(MAKE) -C libbpf/src clean $P
	$(Q)$(RM) -r $(LIB_INSTALL)

else

libbpf_clean:
	@echo -n
endif

# Handle libbpf as git submodule
ifeq ($(SYSTEM_LIBXDP),n)
ifeq ($(VERBOSE),0)
P:= >/dev/null
endif

# Detect submodule libbpf source file changes
LIBXDP_SOURCES := $(wildcard xdp-tools/lib/libxdp/*.[ch])


$(LIB_INSTALL)/usr/lib/libxdp.a: $(LIBXDP_SOURCES)
	@echo ; echo "  libxdp"
	$(QUIET_CC)$(MAKE) -C xdp-tools BUILD_STATIC_ONLY=1 libxdp  $P
	$(QUIET_INSTALL)$(MAKE) -C xdp-tools DESTDIR=../../../$(LIB_INSTALL) PREFIX=/usr BUILD_STATIC_ONLY=1 libxdp_install $P

.PHONY: libxdp_clean
libxdp_clean:
	$(Q)$(MAKE) -C xdp-tools clean $P
	$(Q)$(RM) -r $(LIB_INSTALL)

else

libxdp_clean:
	@echo -n
endif
