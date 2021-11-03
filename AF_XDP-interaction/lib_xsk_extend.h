/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */

#ifndef __LIB_XSK_EXTEND_H
#define __LIB_XSK_EXTEND_H

#define LIBBPF_API ""

LIBBPF_API int xsk_umem__btf_id(void *umem_data, const struct xsk_umem *umem);

struct xsk_btf_info;

LIBBPF_API int xsk_btf__init(__u32 btf_id, struct xsk_btf_info **xbi);
LIBBPF_API int xsk_btf__read(void **dest, size_t size, const char *field, struct xsk_btf_info *xbi,
			     const void *addr);
LIBBPF_API bool xsk_btf__has_field(const char *field, struct xsk_btf_info *xbi);
LIBBPF_API void xsk_btf__free(struct xsk_btf_info *xbi);

#define XSK_BTF_READ_INTO(dest, field, xbi, addr) ({ \
	typeof(dest) *_d; \
	xsk_btf__read((void **)&_d, sizeof(dest), #field, xbi, addr); \
	dest = *_d; })

#endif /* __LIB_XSK_EXTEND_H */
