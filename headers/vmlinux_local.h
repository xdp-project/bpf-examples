/*
 * WARNING: This file shadow vmlinux.h that you can generate yourself
 *
 * Cmdline to generate vmlinux.h
 *  bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
 *
 * This vmlinux.h shadow contains kernel headers reduced to that were
 * needed in this project.
 */
#ifndef __VMLINUX_H__
#define __VMLINUX_H__

#include <linux/types.h> /* Needed for __uNN in vmlinux/vmlinux_types.h */

#ifndef BPF_NO_PRESERVE_ACCESS_INDEX
#pragma clang attribute push (__attribute__((preserve_access_index)), apply_to = record)
#endif

#include "vmlinux/vmlinux_types.h"
#include "vmlinux/vmlinux_common.h"
#include "vmlinux/vmlinux_net.h"

/*
 * Notice: Defining __VMLINUX_H__ (or __KERNEL__) cause <bpf/bpf_tracing.h>
 *         header file to define architecture specific PT_REGS_PARM's.
 *
 * When using '-target bpf' the fallback mechanism doesn't detect right arch
 * via  compiler defines.
 *
 * Makefile system in lib/common.mk detect ARCH and defines the
 * defines __TARGET_ARCH_$(ARCH) matched on below.
 */
#if defined(__TARGET_ARCH_x86)
#include "vmlinux/arch/x86/vmlinux.h"
#else
#warning "Makefile for BPF-tracing on this arch: not supported yet"
#endif

#ifndef BPF_NO_PRESERVE_ACCESS_INDEX
#pragma clang attribute pop
#endif

#endif /* __VMLINUX_H__ */
