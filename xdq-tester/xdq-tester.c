// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (c) 2022 Freysteinn Alfredsson <freysteinn@freysteinn.com> */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <math.h>
#include <errno.h>
#include <stdbool.h>
#include <getopt.h>
#include <libgen.h>

#include <arpa/inet.h>
#include <netinet/ether.h>

#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ipv6.h>
#include <linux/udp.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include <lua.h>
#include <lualib.h>
#include <lauxlib.h>

#include "logging.h"

#include "xdq-tester.h"

#include "bpf_shared_data.h"

static const struct option long_options[] = {
	{"verbose",	no_argument,		NULL, 'v' },
	{"help",	no_argument,		NULL, 'h' },
	{}
};

static void mac_to_string(char *dst, unsigned char *mac);
static __be32 calc_ipv6_chksum_part(const struct ipv6hdr *iph);
static __be16 calc_udp_cksum(const struct udphdr *udp, __be32 chksum_part);
static struct ethhdr *lua_to_eth_header(lua_State *L, struct packet *pkt);
static struct ipv6hdr *lua_to_ipv6_header(lua_State *L, struct packet *pkt);
static struct udphdr *lua_to_udp_header(lua_State *L, struct packet *pkt, __be64 checksum_part);
static struct packet *lua_parse_packet(lua_State *L);
static void set_bpf_fd(lua_State *L, struct bpf_object *obj, const char *func_name, int *prog_fd);
static struct ethhdr *parse_eth(lua_State *L, struct packet *pkt);
static struct ipv6hdr *parse_ipv6(lua_State *L, struct packet *pkt);
static struct udphdr *parse_udp(lua_State *L, struct packet *pkt);
static int bpf_xdp(lua_State *L, struct packet *pkt);
static int bpf_dequeue(lua_State *L, struct packet *pkt);
static struct ethhdr *parse_eth_to_lua(lua_State *L, struct packet *pkt);
static struct ipv6hdr *parse_ipv6_to_lua(lua_State *L, struct packet *pkt);
static struct udphdr *parse_udp_to_lua(lua_State *L, struct packet *pkt);
static void parse_packet_to_lua(lua_State *L, struct packet *pkt);
static void initLuaFunctions(lua_State *L, char *prog_name);
static void usage(char *prog_name);


static void mac_to_string(char *dst, unsigned char *mac)
{
	snprintf(dst, 18, "%02x:%02x:%02x:%02x:%02x:%02x",
		 mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

static __be32 calc_ipv6_chksum_part(const struct ipv6hdr *iph)
{
	__u32 chksum = iph->nexthdr + ntohs(iph->payload_len);
	int i;

	for (i = 0; i < 8; i++) {
		chksum += ntohs(iph->saddr.s6_addr16[i]);
		chksum += ntohs(iph->daddr.s6_addr16[i]);
	}
	return chksum;
}

static __be16 calc_udp_cksum(const struct udphdr *udp, __be32 chksum_part)
{
	__u32 chksum = chksum_part;
	chksum += ntohs(udp->source);
	chksum += ntohs(udp->dest);
	chksum += ntohs(udp->len);

	while (chksum >> 16)
		chksum = (chksum & 0xffff) + (chksum >> 16);
	return htons(~chksum);
}

struct xdq_state *get_xdq_state(lua_State *L)
{
	struct xdq_state *state;

	lua_getglobal(L, "_xdq");
	if (!lua_isuserdata(L, -1))
		die(L, "");
	state = lua_touserdata(L, -1);
	lua_remove(L, -1);

	return state;
}

void die(lua_State *L, const char *format, ...)
{
	struct xdq_state *state;
	lua_Debug ar;
	int line;
	va_list args;

	lua_getglobal(L, "_xdq");
	if (!lua_isuserdata(L, -1)) {
		fprintf(stderr, "Missing internal XDQ state within the Lua environment\n");
		exit(EXIT_FAILURE);
	}
	state = lua_touserdata(L, -1);

	if (lua_getstack(L, 1, &ar)) {
		lua_getinfo(L, "nSl", &ar);
		line = ar.currentline;
		fprintf(stderr, "%s:%s:%d: ", state->prog_name, ar.short_src, line);
	} else {
		fprintf(stderr, "%s: ", state->prog_name);
	}

	va_start(args, format);
	vfprintf(stderr, format, args);
	va_end(args);
	fprintf(stderr, "\n");
	free(state->xdq_script);
	exit(EXIT_FAILURE);
}

struct packet *packet_alloc(lua_State *L, struct packet *pkt, size_t size)
{
	const int ALLOC_SIZE = 4096;
	size_t old_length;

	if (pkt == NULL)
		pkt = calloc(1, sizeof(struct packet));
	if (pkt->data == NULL) {
		pkt->data = malloc(ALLOC_SIZE);
		if (!pkt->data)
			die(L, "Failed to allocate memory for packet: %s", strerror(errno));
		pkt->data_end = pkt->data;
		pkt->cur = pkt->data;
		pkt->length = 0;
	}
	old_length = pkt->length;
	pkt->length += size;
	pkt->data_end += size;
	if (pkt->length > ALLOC_SIZE)
		die(L, "Packet larger than %d octets\n", ALLOC_SIZE);
	memset(pkt->data + old_length, '\0', size);
	return pkt;
}

void packet_free(struct packet *pkt)
{
	free(pkt->data);
	free(pkt);
}

static struct ethhdr *lua_to_eth_header(lua_State *L, struct packet *pkt)
{
	struct ethhdr *eth;
	const char *mac_src_str;
	const char *mac_dst_str;
	int proto;
	packet_alloc(L, pkt, sizeof(struct ethhdr));
	eth = (struct ethhdr *) pkt->cur;

	if (!lua_istable(L, -1))
		die(L, "Missing eth header\n");
	lua_getfield(L, -1, "eth");

	lua_getfield(L, -1, "source");
	if (!lua_isstring(L, -1))
		die(L, "Source MAC address is not a string\n");
	mac_src_str = lua_tostring(L, -1);
	if (!ether_aton_r(mac_src_str, (struct ether_addr *) &eth->h_source))
		die(L, "Not a valid source MAC address: '%s'\n", mac_src_str);
	lua_remove(L, -1);

	lua_getfield(L, -1, "dest");
	if (!lua_isstring(L, -1))
		die(L, "Destination MAC address is not a string\n");
	mac_dst_str = lua_tostring(L, -1);
	if (!ether_aton_r(mac_dst_str, (struct ether_addr *) &eth->h_dest))
		die(L, "Not a valid destination MAC address: '%s'\n", mac_dst_str);
	lua_remove(L, -1);

	lua_getfield(L, -1, "proto");
	if (!lua_isinteger(L, -1))
		die(L, "Ethernet protocol field must be an integer\n");
	proto = lua_tointeger(L, -1);
	if (proto < 0 || proto > 0xffff)
		die(L, "Ethernet protocol field must be an integer between 0x0 and 0xffff, but was 0x%x\n",
		    proto);
	eth->h_proto = htons((short) proto);
	lua_remove(L, -1);

	lua_remove(L, -1); // Remove eth table from the stack
	return eth;
}

static struct ipv6hdr *lua_to_ipv6_header(lua_State *L, struct packet *pkt)
{
	struct ipv6hdr *iph;
	int priority;
	int version;
	int flow_lbl_int;
	int payload_len;
	int nexthdr;
	int hop_limit;
	const char *src_ip;
	const char *dst_ip;

	packet_alloc(L, pkt, sizeof(struct ipv6hdr));

	iph = (struct ipv6hdr *) pkt->cur;

	lua_getfield(L, -1, "ip");
	if (!lua_istable(L, -1))
		die(L, "Missing eth header\n");

	lua_getfield(L, -1, "priority");
	if (!lua_isinteger(L, -1))
		die(L, "IPv6 prirotiy field must be an integer\n");
	priority = lua_tointeger(L, -1);
	if (priority < 0 || priority > 15)
		die(L, "IPv6 prirotiy must be an integer between 0 and 15, but was %d\n", priority);
	iph->priority = priority;
	lua_remove(L, -1);

	lua_getfield(L, -1, "version");
	if (!lua_isinteger(L, -1))
		die(L, "IPv6 version field must be an integer\n");
	version = lua_tointeger(L, -1);
	if (version < 0 || version > 15)
		die(L, "IPv6 version must be an integer between 0 and 15, but was %d\n", version);
	iph->version = version;
	lua_remove(L, -1);

	lua_getfield(L, -1, "flow_lbl");
	if (!lua_istable(L, -1))
		die(L, "IPv6 flow_lbl must be a table\n");
	for (int i = 0; i < 3; i++) {
		lua_rawgeti(L, -1, i + 1);
		if (!lua_isinteger(L, -1))
			die(L, "IPv6 flow_lbl[%d] field must be an integer\n", i);
		flow_lbl_int = lua_tointeger(L, -1);
		if (flow_lbl_int < 0 || flow_lbl_int > 0xff)
			die(L, "IPv6 flow_lbl[%d] field must be between 0x0 and 0xff but was 0x%x\n",
			    i, flow_lbl_int);
		iph->flow_lbl[i] = flow_lbl_int;
		lua_remove(L, -1);
	}
	lua_remove(L, -1);

	if (lua_getfield(L, -1, "payload_len") != LUA_TNIL) {
		if (!lua_isinteger(L, -1))
			die(L, "IPv6 payload_len field must be an integer\n");
		payload_len = lua_tointeger(L, -1);
		if (payload_len < 0 || payload_len > 0xffff)
			die(L, "IPv6 payload_len field must be an integer between 0x0 and 0xffff, but was 0x%x\n",
			    payload_len);
		iph->payload_len = htons((short) payload_len);
	}
	lua_remove(L, -1);

	lua_getfield(L, -1, "nexthdr");
	if (!lua_isinteger(L, -1))
		die(L, "IPv6 nexthdr field must be an integer\n");
	nexthdr = lua_tointeger(L, -1);
	if (nexthdr < 0x0 || nexthdr > 0xff)
		die(L, "IPv6 nexthdr must be an integer between 0x0 and 0xff, but was 0x%x\n",
		    nexthdr);
	iph->nexthdr = nexthdr;
	lua_remove(L, -1);

	lua_getfield(L, -1, "hop_limit");
	if (!lua_isinteger(L, -1))
		die(L, "IPv6 hop_limit field must be an integer\n");
	hop_limit = lua_tointeger(L, -1);
	if (hop_limit < 0x0 || hop_limit > 0xff)
		die(L, "IPv6 hop_limit must be an integer between 0x0 and 0xff, but was 0x%x\n",
		    hop_limit);
	iph->hop_limit = hop_limit;
	lua_remove(L, -1);

	lua_getfield(L, -1, "saddr");
	if (!lua_isstring(L, -1))
		die(L, "Source IPv6 address is not a string\n");
	src_ip = lua_tostring(L, -1);
	if (!inet_pton(AF_INET6, src_ip, &iph->saddr))
		die(L, "Failed to set source IPv6 address to %s", src_ip);
	lua_remove(L, -1);

	lua_getfield(L, -1, "daddr");
	if (!lua_isstring(L, -1))
		die(L, "Destination IPv6 address is not a string\n");
	dst_ip = lua_tostring(L, -1);
	if (!inet_pton(AF_INET6, dst_ip, &iph->daddr))
		die(L, "Failed to set destination IPv6 address to %s", dst_ip);
	lua_remove(L, -1);

	lua_remove(L, -1); // Remove ip table from the stack
	return iph;
}

static struct udphdr *lua_to_udp_header(lua_State *L, struct packet *pkt, __be64 checksum_part)
{
	struct udphdr *udp;
	int src_port;
	int dst_port;
	int len;
	int check;
	const char *payload;

	packet_alloc(L, pkt, sizeof(struct udphdr));
	udp = (struct udphdr *) pkt->cur;

	lua_getfield(L, -1, "udp");
	if (!lua_istable(L, -1))
		die(L, "Missing udp header\n");

	lua_getfield(L, -1, "source");
	if (!lua_isinteger(L, -1))
		die(L, "UDP source port must be an integer\n");
	src_port = lua_tointeger(L, -1);
	if (src_port < 0 || src_port > 65535)
		die(L, "UDP source port must be an integer between 0 and 65535, but was %d\n",
		    src_port);
	udp->source = htons((short) src_port);
	lua_remove(L, -1);

	lua_getfield(L, -1, "dest");
	if (!lua_isinteger(L, -1))
		die(L, "UDP destination port must be an integer\n");
	dst_port = lua_tointeger(L, -1);
	if (dst_port < 0 || dst_port > 0xffff)
		die(L, "UDP destination port must be an integer between 0 and 65535, but was %d\n",
		    dst_port);
	udp->dest = htons((short) dst_port);
	lua_remove(L, -1);

	if (lua_getfield(L, -1, "payload") != LUA_TNIL) {
		if (!lua_isstring(L, -1))
			die(L, "UDP payload field must be a string\n");
		len = lua_rawlen(L, -1);
		payload = lua_tostring(L, -1);
		packet_alloc(L, pkt, len);
		memcpy(pkt->cur + sizeof(struct udphdr), payload, len);
		udp->len = htons(sizeof(struct udphdr) + len);
	}
	lua_remove(L, -1);

	if (lua_getfield(L, -1, "len") != LUA_TNIL) {
		if (!lua_isinteger(L, -1))
			die(L, "UDP len field must be an integer\n");
		len = lua_tointeger(L, -1);
		if (len < 0 || len > 0xffff)
			die(L, "UDP len field must be an integer between 0 and 65535, but was %d\n",
			    len);
		udp->len = htons((short) len);
	}
	lua_remove(L, -1);

	if (lua_getfield(L, -1, "check") != LUA_TNIL) {
		if (!lua_isinteger(L, -1))
			die(L, "UDP check field must be an integer\n");
		check = lua_tointeger(L, -1);
		if (check < 0 || check > 0xffff)
			die(L, "UDP check field must be an integer between 0 and 65535, but was %d\n",
			    check);
		udp->check = htons((short) check);
	}
	lua_remove(L, -1);

	if (checksum_part != -1) {
		udp->check = calc_udp_cksum(udp, checksum_part);
	}

	lua_remove(L, -1); // Remove udp table from the stack
	return udp;
}

static struct packet *lua_parse_packet(lua_State *L)
{
	struct packet *pkt = packet_alloc(L, NULL, 0);
	struct ethhdr *eth = NULL;
	struct ipv6hdr *iph = NULL;
	struct udphdr *udp = NULL;
	int proto = -1;
	__be64 checksum_part = -1;

	eth = lua_to_eth_header(L, pkt);
	pkt->cur += sizeof(struct ethhdr);
	if (eth->h_proto == ntohs(ETH_P_IPV6)) {
		iph = lua_to_ipv6_header(L, pkt);
		proto = iph->nexthdr;
		pkt->cur += sizeof(struct ipv6hdr);
		checksum_part = calc_ipv6_chksum_part(iph);
	}
	if (proto == IPPROTO_UDP) {
		udp = lua_to_udp_header(L, pkt, checksum_part);

		if (iph && iph->payload_len == 0)
			iph->payload_len = udp->len;
	}
	pkt->cur = pkt->data; // Reset cur pointer for comparison
	return pkt;
}

static void set_bpf_fd(lua_State *L, struct bpf_object *obj, const char *func_name, int *prog_fd)
{
	struct bpf_program *prog = bpf_object__find_program_by_name(obj, func_name);
	*prog_fd = bpf_program__fd(prog);
	if (*prog_fd < 0 ) {
		bpf_object__close(obj);
		die(L, "Failed to run bpf_program__fd: %s", strerror(errno));
	}
}

int load_xdq_file(lua_State *L)
{
	struct xdq_state *state;
	const char *filename;
	struct bpf_object *xdq_bpf_obj;
	const char *xdp_func;
	const char *dequeue_func;
	struct bpf_program *prog;
	int err = 0;

	if (lua_gettop(L) != 1)
		die(L, "Incorrect number of arguments");
	if (!lua_isstring(L, 1))
		die(L, "Argument must be a string");
	filename = lua_tostring(L, 1);

	state = get_xdq_state(L);

	if (state->xdq_script)
		free(state->xdq_script);
	state->xdq_script = strdup(filename);

	lua_getglobal(L, "config");
	if (!lua_istable(L, -1))
		die(L, "Missing config table\n");

	lua_getfield(L, -1, "bpf");
	if (!lua_istable(L, -1))
		die(L, "Missing config.bpf table\n");

	lua_getfield(L, -1, "xdp_func");
	if (!lua_isstring(L, -1))
		die(L, "Missing config.bpf.xdq_func\n");
	xdp_func = lua_tostring(L, -1);
	if (strlen(xdp_func) == 0)
		die(L, "config.bpf.xdp_func can't be an empty string");
	lua_remove(L, -1);

	lua_getfield(L, -1, "dequeue_func");
	if (!lua_isstring(L, -1))
		die(L, "Missing config.bpf.dequeue_func\n");
	dequeue_func = lua_tostring(L, -1);
	if (strlen(xdp_func) == 0)
		die(L, "config.bpf.dequeue_func can't be an empty string");
	lua_remove(L, -1);

	lua_remove(L, -1); // Remove bpf table from the stack
	lua_remove(L, -1); // Remove config table from the stack

	xdq_bpf_obj = bpf_object__open_file(state->xdq_script, NULL);
	err = libbpf_get_error(xdq_bpf_obj);
	if (err)
		die(L, "Failed to run bpf_object__open: %s", strerror(errno));
	state->xdq_bpf_obj = xdq_bpf_obj;

	prog = bpf_object__find_program_by_name(xdq_bpf_obj, dequeue_func);
	if (!prog) {
		bpf_object__close(xdq_bpf_obj);
		die(L, "Failed to run bpf_object_find_program_by_name: %s", strerror(errno));
	}

	bpf_program__set_type(prog, BPF_PROG_TYPE_DEQUEUE);
	err = bpf_object__load(xdq_bpf_obj);
	if (err) {
		bpf_object__close(xdq_bpf_obj);
		die(L, "Failed to run bpf_object__load: %s", strerror(errno));
	}

	set_bpf_fd(L, xdq_bpf_obj, xdp_func, &state->xdp_prog_fd);
	set_bpf_fd(L, xdq_bpf_obj, dequeue_func, &state->dequeue_prog_fd);
	return 0;
}


static int bpf_xdp(lua_State *L, struct packet *pkt)
{
	struct xdq_state *state;
	int total_queued_packets;
	int currently_queued_packets;
	int err;
	struct xdp_md ctx_in = {
		.data_end = pkt->length,
	};
	DECLARE_LIBBPF_OPTS(bpf_test_run_opts, opts,
			    .data_in = pkt->data,
			    .data_size_in = pkt->length,
			    .ctx_in = &ctx_in,
			    .ctx_size_in = sizeof(ctx_in),
			    .repeat = 1,
			    .flags = BPF_F_TEST_XDP_DO_REDIRECT,
		);
	ctx_in.data_end = ctx_in.data + pkt->length;

	state = get_xdq_state(L);
	if (state->xdp_prog_fd <= 0)
		die(L, "No XDP hook attached");
	err = bpf_prog_test_run_opts(state->xdp_prog_fd, &opts);
	if (err)
		die(L, "Failed to run XDP hook: %s", strerror(errno));

	lua_getglobal(L, "xdq");
	if (!lua_istable(L, -1))
		die(L, "Missing xdq table\n");

	lua_getfield(L, -1, "total_queued");
	if (!lua_isinteger(L, -1))
		die(L, "xdq.total_queued is not an integer\n");
	total_queued_packets = lua_tointeger(L, -1);
	lua_remove(L, -1);
	total_queued_packets++;
	lua_pushinteger(L, total_queued_packets);
	lua_setfield(L, -2, "total_queued");

	lua_getfield(L, -1, "currently_queued");
	if (!lua_isinteger(L, -1))
		die(L, "xdq.currently_queued is not an integer\n");
	currently_queued_packets = lua_tointeger(L, -1);
	lua_remove(L, -1);
	currently_queued_packets++;
	lua_pushinteger(L, currently_queued_packets);
	lua_setfield(L, -2, "currently_queued");

	lua_remove(L, -1); // Remove xdq table from the stack

	return opts.retval;
}

static struct ethhdr *parse_eth(lua_State *L, struct packet *pkt)
{
	struct ethhdr *eth = (struct ethhdr *) pkt->cur;

	if (pkt->cur + sizeof(struct ethhdr) > pkt->data_end)
		die(L, "Missing expected eth header");
	pkt->cur += sizeof(struct ethhdr);
	return eth;
}

static struct ipv6hdr *parse_ipv6(lua_State *L, struct packet *pkt)
{
	struct ipv6hdr *iph = (struct ipv6hdr *) pkt->cur;

	if (pkt->cur + sizeof(struct ipv6hdr) > pkt->data_end)
		die(L, "Missing expected IPv6 header");
	pkt->cur += sizeof(struct ipv6hdr);
	return iph;
}

static struct udphdr *parse_udp(lua_State *L, struct packet *pkt)
{
	struct udphdr *udp = (struct udphdr *) pkt->cur;

	if (pkt->cur + sizeof(struct udphdr) > pkt->data_end)
		die(L, "Missing expected UDP header");
	pkt->cur += sizeof(struct udphdr);
	return udp;
}

int enqueue(lua_State *L)
{
	struct packet *pkt;
	int retval;

	if (lua_gettop(L) != 1)
		die(L, "Incorrect number of arguments");
	if (!lua_istable(L, 1))
		die(L, "Argument must be a table");

	pkt = lua_parse_packet(L);

	retval = bpf_xdp(L, pkt);

	packet_free(pkt);

	lua_pushinteger(L, retval);
	return 1;
}

static struct ethhdr *parse_eth_to_lua(lua_State *L, struct packet *pkt)
{
	struct ethhdr *eth = parse_eth(L, pkt);
	char src_mac[18];
	char dst_mac[18];

	// Ethernet header
	lua_createtable(L, -1, 0);

	lua_pushinteger(L, ntohs(eth->h_proto));
	lua_setfield(L, -2, "proto");


	mac_to_string(src_mac, eth->h_source);
	lua_pushstring(L, src_mac);
	lua_setfield(L, -2, "source");

	mac_to_string(dst_mac, eth->h_dest);
	lua_pushstring(L, dst_mac);
	lua_setfield(L, -2, "dest");

	lua_setfield(L, -2, "eth");
	return eth;
}

static struct ipv6hdr *parse_ipv6_to_lua(lua_State *L, struct packet *pkt)
{
	struct ipv6hdr *iph = parse_ipv6(L, pkt);
	char src_ip[INET6_ADDRSTRLEN + 1];
	char dst_ip[INET6_ADDRSTRLEN + 1];

	// IPv6 header
	lua_createtable(L, -1, 0);

	lua_pushinteger(L, (unsigned int) iph->priority);
	lua_setfield(L, -2, "priority");

	lua_pushinteger(L, (unsigned int) iph->version);
	lua_setfield(L, -2, "version");

	lua_createtable(L, -1, 0);
	for (int i = 0; i < 3; i++) {
		lua_pushinteger(L, (unsigned int) iph->flow_lbl[i]);
		lua_rawseti(L, -2, i + 1);
	}
	lua_setfield(L, -2, "flow_lbl");

	lua_pushinteger(L, (unsigned int) ntohs(iph->payload_len));
	lua_setfield(L, -2, "payload_len");

	lua_pushinteger(L, (unsigned int) iph->nexthdr);
	lua_setfield(L, -2, "nexthdr");

	lua_pushinteger(L, (unsigned int) iph->hop_limit);
	lua_setfield(L, -2, "hop_limit");

	lua_pushstring(L, inet_ntop(AF_INET6, &iph->saddr, (char *) &src_ip, sizeof(src_ip)));
	lua_setfield(L, -2, "saddr");

	lua_pushstring(L, inet_ntop(AF_INET6, &iph->daddr, (char *) &dst_ip, sizeof(dst_ip)));
	lua_setfield(L, -2, "daddr");

	lua_setfield(L, -2, "ip");
	return iph;
}

static struct udphdr *parse_udp_to_lua(lua_State *L, struct packet *pkt)
{
	struct udphdr *udp = parse_udp(L, pkt);

	// UDP header
	lua_createtable(L, -1, 0);

	lua_pushinteger(L, (unsigned int) ntohs(udp->source));
	lua_setfield(L, -2, "source");

	lua_pushinteger(L, (unsigned int) ntohs(udp->dest));
	lua_setfield(L, -2, "dest");

	lua_pushinteger(L, (unsigned int) ntohs(udp->len));
	lua_setfield(L, -2, "len");

	lua_pushinteger(L, (unsigned int) ntohs(udp->check));
	lua_setfield(L, -2, "check");

	if (udp->len - sizeof(struct udphdr) > 0) {
		lua_pushlstring(L, pkt->cur, ntohs(udp->len) - sizeof(struct udphdr));
		lua_setfield(L, -2, "payload");
	}

	lua_setfield(L, -2, "udp");

	return udp;
}

static void parse_packet_to_lua(lua_State *L, struct packet *pkt)
{
	struct ethhdr *eth = NULL;
	struct ipv6hdr *iph = NULL;
	int proto = -1;

	// Packet table
	lua_createtable(L, -1, 0);

	eth = parse_eth_to_lua(L, pkt);

	if (eth->h_proto == ntohs(ETH_P_IPV6)) {
		iph = parse_ipv6_to_lua(L, pkt);
		proto = iph->nexthdr;
	}
	if (proto == IPPROTO_UDP)
		parse_udp_to_lua(L, pkt);
}

static int bpf_dequeue(lua_State *L, struct packet *pkt)
{

	struct xdq_state *state = get_xdq_state(L);
	int err;
	int total_dequeued_packets;
	int currently_queued_packets;
	if (state->dequeue_prog_fd <= 0)
		die(L, "No DEQUEUE hook attached");
	DECLARE_LIBBPF_OPTS(bpf_test_run_opts, opts,
			    .data_out = pkt->data,
			    .data_size_out = pkt->length,
			    .repeat = 1,
		);

	err = bpf_prog_test_run_opts(state->dequeue_prog_fd, &opts);
	if (err)
		die(L, "Failed to run DEQUEUE hook: %s", strerror(errno));

	lua_getglobal(L, "xdq");
	if (!lua_istable(L, -1))
		die(L, "Missing xdq table\n");

	lua_getfield(L, -1, "total_dequeued");
	if (!lua_isinteger(L, -1))
		die(L, "xdq.total_dequeued is not an integer\n");
	total_dequeued_packets = lua_tointeger(L, -1);
	lua_remove(L, -1);
	total_dequeued_packets++;
	lua_pushinteger(L, total_dequeued_packets);
	lua_setfield(L, -2, "total_dequeued");

	lua_getfield(L, -1, "currently_queued");
	if (!lua_isinteger(L, -1))
		die(L, "xdq.currently_queued is not an integer\n");
	currently_queued_packets = lua_tointeger(L, -1);
	lua_remove(L, -1);
	currently_queued_packets--;
	lua_pushinteger(L, currently_queued_packets);
	lua_setfield(L, -2, "currently_queued");

	lua_remove(L, -1); // Remove xdq table from the stack

	return opts.retval;
}

int dequeue(lua_State *L)
{
	struct packet *pkt;
	int retval;

	if (lua_gettop(L) != 0)
		die(L, "Function takes no arguments");

	pkt = packet_alloc(L, NULL, 4096);
	retval = bpf_dequeue(L, pkt);

	parse_packet_to_lua(L, pkt);
	packet_free(pkt);

	lua_pushinteger(L, retval);
	// Return packet and DEQEUEUE hook return value
	return 2;
}

int normalize_ipv6_address(lua_State *L)
{
	char ip_str[INET6_ADDRSTRLEN + 1];
	struct in6_addr ip;
	const char *ip_param;

	if (lua_gettop(L) != 1)
		die(L, "Incorrect number of arguments");
	if (!lua_isstring(L, 1))
		die(L, "Argument must be a string");
	ip_param = lua_tostring(L, 1);

	if (!inet_pton(AF_INET6, ip_param, &ip))
		die(L, "Failed to parse IPv6 address %s", ip_param);

	lua_pushstring(L, inet_ntop(AF_INET6, &ip, ip_str, sizeof(ip_str)));
	return 1;
}

int fail_xdq(lua_State *L)
{
	const char *message = "";
	if (lua_gettop(L) == 1 && lua_isstring(L, -1))
		message = lua_tostring(L, -1);
	die(L, message);
	return -1;
}

/* Scheduler specific helpers
 *
 * The following functions are here to aid scheduling algorithms to function, such
 * as providing our Lua implementation with five-tuple flow handling. Ideally, this
 * functionality these functions would be generic and use BTF.
 * For now, we have tailored these functions for specific scheduling algorithms.
 */

int show_flow_map(lua_State *L)
{
	system("bpftool map dump name flow_states");
	return 0;
}

int set_flow_weight(lua_State *L)
{
	struct xdq_state *state = get_xdq_state(L);
	struct network_tuple nt = {0};
	struct flow_state flow = {0};
	int flow_states_fd;
	struct packet *pkt;
	struct ipv6hdr *iph;
	struct udphdr *udp;
	int weight;

	if (lua_gettop(L) != 2)
		die(L, "Incorrect number of arguments");
	if (!lua_istable(L, 1))
		die(L, "First argument must be a table");

	if (!lua_isinteger(L, -1))
		die(L, "weight parameter isn't a number\n");
	weight = lua_tointeger(L, 2);
	lua_pop(L, 1);

	pkt = lua_parse_packet(L);
	parse_eth(L, pkt);
	iph = parse_ipv6(L, pkt);
	udp = parse_udp(L, pkt);

	nt.proto = iph->nexthdr;
	nt.ipv = iph->version;
	nt.saddr.ip = iph->saddr;
	nt.daddr.ip = iph->daddr;
	nt.daddr.port = udp->dest;
	nt.saddr.port = udp->source;


	flow.pkts = 0;
	flow.finish_bytes = 0;
	flow.weight = weight;
	flow.persistent = 1;

	flow_states_fd = bpf_object__find_map_fd_by_name(state->xdq_bpf_obj, "flow_states");

	if (bpf_map_update_elem(flow_states_fd, &nt, &flow, BPF_ANY))
		die(L, "Failed to update map");

	return 0;
}

int set_time_ns(lua_State *L)
{
	struct xdq_state *state = get_xdq_state(L);
	int time_ns_fd;
	__u32 key = 0;
	__u64 time_ns;

	if (lua_gettop(L) != 1)
		die(L, "Incorrect number of arguments");
	if (!lua_isinteger(L, -1))
		die(L, "Argument must be an integer");
	time_ns = lua_tointeger(L, 1);
	lua_pop(L, 1);

	time_ns_fd = bpf_object__find_map_fd_by_name(state->xdq_bpf_obj, "xdq_time_ns");

	if (bpf_map_update_elem(time_ns_fd, &key, &time_ns, BPF_ANY))
		die(L, "Failed to update map");

	return 0;
}

int get_time_ns(lua_State *L)
{
	struct xdq_state *state = get_xdq_state(L);
	int time_ns_fd;
	__u32 key = 0;
	__u64 time_ns;

	if (lua_gettop(L) != 0)
		die(L, "Incorrect number of arguments");

	time_ns_fd = bpf_object__find_map_fd_by_name(state->xdq_bpf_obj, "xdq_time_ns");

	if (bpf_map_lookup_elem(time_ns_fd, &key, &time_ns))
		die(L, "Failed to lookup map");

	lua_pushnumber(L, time_ns);

	return 1;
}
/* End of Scheduler specific helpers */


static void initLuaFunctions(lua_State *L, char *prog_name)
{
	struct xdq_state *state = lua_newuserdatauv(L, sizeof(struct xdq_state), 0);
	state->prog_name = prog_name;
	state->xdq_script = NULL;
	state->xdp_prog_fd = -1;
	state->dequeue_prog_fd = -1;
	lua_setglobal(L, "_xdq");

	lua_pushcfunction(L, enqueue);
	lua_setglobal(L, "enqueue");

	lua_pushcfunction(L, dequeue);
	lua_setglobal(L, "dequeue");

	lua_pushcfunction(L, load_xdq_file);
	lua_setglobal(L, "load_xdq_file");

	lua_pushcfunction(L, normalize_ipv6_address);
	lua_setglobal(L, "normalize_ipv6_address");

	lua_pushcfunction(L, fail_xdq);
	lua_setglobal(L, "fail");

	/* Scheduler specific helpers */
	lua_pushcfunction(L, set_flow_weight);
	lua_setglobal(L, "set_flow_weight");

	lua_pushcfunction(L, set_time_ns);
	lua_setglobal(L, "set_time_ns");

	lua_pushcfunction(L, get_time_ns);
	lua_setglobal(L, "get_time_ns");

	lua_pushcfunction(L, show_flow_map);
	lua_setglobal(L, "show_flow_map");
}

static void usage(char *prog_name)
{
	printf("Usage: %s [OPTIONS] <xdq_object_file>\n", prog_name);
	fputs("\nTest XDP and DEQUEUE BPF hooks.\n", stdout);
	fputs("Mandatory arguments to long options are mandatory for short options too.\n", stdout);
	fputs("\
  -v, --verbose             output BPF diagnostic\n\
  -h, --help                display this help and exit\n", stdout);
}

int main(int argc, char *argv[])
{
	lua_State *L;
	struct xdq_state *state;
	char lib_file[PATH_MAX + 1] = {0};
	char *sched_file = NULL;
	int opt;

	init_lib_logging();
	L = luaL_newstate();
	luaL_openlibs(L);
	initLuaFunctions(L, argv[0]);

	if (!realpath("/proc/self/exe", lib_file))
		die(L, "Program location not found");
	dirname(lib_file);
	if (strlen(lib_file) + strlen(XDQ_LIBRARY + 1) >= PATH_MAX)
		die(L, "Path to library '%s' too long\nPath: '%s'", XDQ_LIBRARY, lib_file);
	strncat(lib_file, "/", PATH_MAX);
	strncat(lib_file, XDQ_LIBRARY, PATH_MAX);

	if (luaL_dofile(L, lib_file) != LUA_OK)
		die(L, "Failed to load LUA library\n");


	while ((opt = getopt_long(argc, argv, "f:vh", long_options, NULL)) != -1) {
		switch (opt) {
		case 'f':
			sched_file = optarg;
			break;
		case 'v':
			state = get_xdq_state(L);
			set_log_level(LOG_VERBOSE);
			break;
		case 'h':
			usage(argv[0]);
			exit(EXIT_SUCCESS);
		default:
			usage(argv[0]);
			exit(EXIT_FAILURE);
		}
	}
	if (argc - optind == 1)
		sched_file = argv[optind];
	if (!sched_file) {
		fprintf(stderr, "No XDQ object file provided. Use %s <xdq_object_file>\n", argv[0]);
		usage(argv[0]);
		exit(EXIT_FAILURE);
	}

	if (luaL_dofile(L, sched_file) != LUA_OK) {
		die(L, "%s", lua_tostring(L, -1));
	}
	state = get_xdq_state(L);
	free(state->xdq_script);
	lua_close(L);
	return EXIT_SUCCESS;
}
