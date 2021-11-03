/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */

/*
 * Prototyping new API for userspace xsk/AF_XDP to access XDP-hints, which is
 * BTF typed info in XDP metadata area (located just before packets headers).
 */
#include "hashmap.h"

#include <errno.h>
#include <stdlib.h>
#include <stdio.h>

#include <bpf/btf.h> /* provided by libbpf */

int xsk_umem__btf_id(void *umem_pkt_data) // , const struct xsk_umem *umem)
{
//	if (umem->config.xdp_headroom < sizeof(int))
//		return -EINVAL;
	// TODO: Need some check that know of metadata is enabled for frame

	return *(int *)(umem_pkt_data - sizeof(int));
}


struct xsk_btf_info {
	struct hashmap map;
	struct btf *btf;
	const struct btf_type *type;
	__u32 btf_type_id;
};

struct xsk_btf_entry {
	__u32 offset;
	__u32 size;
};


__u32 xsk_btf__btf_type_id(struct xsk_btf_info *xbi)
{
	return xbi->btf_type_id;
}

static void __xsk_btf_free_hash(struct xsk_btf_info *xbi)
{
	struct hashmap_entry *entry;
	int i;

	hashmap__for_each_entry((&(xbi->map)), entry, i) {
		free(entry->value);
	}
	hashmap__clear(&(xbi->map));
}

static size_t __xsk_hash_fn(const void *key, void *ctx)
{
	/* Note that, the hashmap used to speed-up offset location into the BTF
	 * doesn't use the field name as a string as key to the hashmap. It
	 * directly uses the pointer value instead, as it is expected that most
	 * of time, field names will be addressed by a shared constant string
	 * residing on read-only memory, thus saving some time. If this
	 * assumption is not entirely true, this optimisation needs to be
	 * rethought (or discarded altogether).
	 */
	return (size_t)key;
}

static bool __xsk_equal_fn(const void *k1, const void *k2, void *ctx)
{
	return k1 == k2;
}

int xsk_btf__init_xdp_hint(struct btf *btf_obj,
			   const char *xdp_hints_name,
			   struct xsk_btf_info **xbi)
{
	const struct btf_member *m;
	const struct btf_type *t;
	unsigned short vlen;
	int i, id, ret = 0;

	if (!xbi)
		return -EINVAL;

//	ret = btf__get_from_id(btf_id, &btf); // Limits lookups to kernel BTF
//	if (ret < 0)
//		return ret;

	/* Require XDP-hints is defined as a struct */
	id = btf__find_by_name_kind(btf_obj, xdp_hints_name, BTF_KIND_STRUCT);
	if (id < 0) {
		ret = id;
		goto error_btf;
	}
	printf("XXX %s() id:%d\n", __func__, id);

	t = btf__type_by_id(btf_obj, id);

//	if (!BTF_INFO_KFLAG(t->info)) {
//		ret = -EINVAL;
//		goto error_btf;
//	}

	*xbi = malloc(sizeof(**xbi));
	if (!*xbi) {
		ret = -ENOMEM;
		goto error_btf;
	}

	hashmap__init(&(*xbi)->map, __xsk_hash_fn, __xsk_equal_fn, NULL);

	/* Validate no BTF field is a bitfield */
	m = btf_members(t);
	vlen = BTF_INFO_VLEN(t->info);
	for (i = 0; i < vlen; i++, m++) {
		if (BTF_MEMBER_BITFIELD_SIZE(m->offset)) {
			ret = -ENOTSUP;
			goto error_entry;
		}
	}

	(*xbi)->btf = btf_obj;
	(*xbi)->type = t;
	(*xbi)->btf_type_id = id;

	return ret;

error_entry:
	__xsk_btf_free_hash(*xbi);
	free(*xbi);

error_btf:
//	btf__free(btf);
	return ret;
}

static int __xsk_btf_field_entry(struct xsk_btf_info *xbi, const char *field,
			  struct xsk_btf_entry **entry)
{
	const struct btf_member *m;
	unsigned short vlen;
	int i;

	m = btf_members(xbi->type);
	vlen = BTF_INFO_VLEN(xbi->type->info);
	for (i = 0; i < vlen; i++, m++) {
		const struct btf_type *member_type;
		const char *name = btf__name_by_offset(xbi->btf, m->name_off);
		printf("XXX %s() i:%d name:%s\n", __func__, i, name);

		if (strcmp(name, field))
			continue;

		if (entry) {
			member_type = btf__type_by_id(xbi->btf, m->type);
			*entry = malloc(sizeof(*entry));
			if (!entry) {
				return -ENOMEM;
			}

			/* As we bail out at init for bit fields, there should
			 * be no entries whose offset is not a multiple of byte */
			(*entry)->offset = BTF_MEMBER_BIT_OFFSET(m->offset) / 8;
			(*entry)->size = member_type->size;
		}
		return 0;
	}

	return -ENOENT;
}

bool xsk_btf__has_field(const char *field, struct xsk_btf_info *xbi)
{
	if (!xbi)
		return false;

	return __xsk_btf_field_entry(xbi, field, NULL) ? false : true;
}

void xsk_btf__free_xdp_hint(struct xsk_btf_info *xbi)
{
	if (!xbi)
		return;

	__xsk_btf_free_hash(xbi);
	btf__free(xbi->btf);
	free(xbi);
}

int xsk_btf__read(void **dest, size_t size, const char *field, struct xsk_btf_info *xbi,
		  const void *addr)
{
	struct xsk_btf_entry *entry;
	int err;

	if (!field || !xbi || !dest || !addr)
		return -EINVAL;

	if (!hashmap__find(&(xbi->map), field, (void **)&entry)) {
		err = __xsk_btf_field_entry(xbi, field, &entry);
		if (err)
			return err;

		hashmap__add(&(xbi->map), field, entry);
	}

	if (entry->size != size)
		return -EINVAL;

	// XXX should we cache size for main xdp_hints struct?
	*dest = (void *)((char *)addr - xbi->type->size + entry->offset);
	return 0;
}
