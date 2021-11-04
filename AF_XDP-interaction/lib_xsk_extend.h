/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */

#ifndef __LIB_XSK_EXTEND_H
#define __LIB_XSK_EXTEND_H

//#define LIBBPF_API ""

LIBBPF_API int xsk_umem__btf_id(void *umem_data);

struct xsk_btf_info;

struct xsk_btf_member {
	__u32 offset;
	__u32 size;
};

LIBBPF_API int xsk_btf__init_xdp_hint(struct btf *btf_obj,
				      const char *xdp_hints_name,
				      struct xsk_btf_info **xbi);

LIBBPF_API void xsk_btf__free_xdp_hint(struct xsk_btf_info *xbi);

LIBBPF_API __u32 xsk_btf__btf_type_id(struct xsk_btf_info *xbi);

LIBBPF_API int xsk_btf__read(void **dest, size_t size, const char *field, struct xsk_btf_info *xbi,
			     const void *addr);
LIBBPF_API bool xsk_btf__has_field(const char *field, struct xsk_btf_info *xbi);

/* Notice: that field must NOT be a C-string as macro will stringify it */
#define XSK_BTF_READ_INTO(dest, field, xbi, addr) ({ \
	typeof(dest) *_d; \
	xsk_btf__read((void **)&_d, sizeof(dest), #field, xbi, addr); \
	dest = *_d; })

#endif /* __LIB_XSK_EXTEND_H */
