// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (c) 2022 Freysteinn Alfredsson <freysteinn@freysteinn.com> */

#ifndef XDQ_TESTER_H_
#define XDQ_TESTER_H_

#include <stddef.h>
#include <stdbool.h>
#include <linux/if_ether.h>
#include <linux/ipv6.h>
#include <linux/udp.h>
#include <lua.h>

#define BPF_PROG_TYPE_DEQUEUE 32
#define BPF_F_TEST_XDP_DO_REDIRECT	(1U << 1)

#define XDQ_LIBRARY "lib.lua"

struct packet {
	char *data;
	char *data_end;
	size_t length;
	char *cur;
};

struct xdq_state {
	struct bpf_object *xdq_bpf_obj;
	char *xdq_script;
	char *prog_name;
	int xdp_prog_fd;
	int dequeue_prog_fd;
};

struct xdq_state *get_xdq_state(lua_State *L);
void die(lua_State *L, const char *format, ...);
struct packet *packet_alloc(lua_State *L, struct packet *pkt, size_t size);
void packet_free(struct packet *pkt);

/* Lua exported functions */
int load_xdq_file(lua_State *L);
int enqueue(lua_State *L);
int dequeue(lua_State *L);
int normalize_ipv6_address(lua_State *L);
int fail_xdq(lua_State *L);

#endif // XDQ_TESTER_H_
