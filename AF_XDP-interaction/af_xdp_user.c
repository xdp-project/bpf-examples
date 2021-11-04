/* SPDX-License-Identifier: GPL-2.0 */

#include <assert.h>
#include <errno.h>
#include <getopt.h>
#include <locale.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <sys/resource.h>

#include <bpf/bpf.h>
#include <bpf/xsk.h>

#include <arpa/inet.h>
#include <net/if.h>
#include <linux/if_link.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/icmpv6.h>

#include <bpf/btf.h> /* provided by libbpf */

#include "common_params.h"
#include "common_user_bpf_xdp.h"
// #include "common_libbpf.h"

#include "lib_xsk_extend.h"

#define NUM_FRAMES         4096
#define FRAME_SIZE         XSK_UMEM__DEFAULT_FRAME_SIZE
#define RX_BATCH_SIZE      64
#define INVALID_UMEM_FRAME UINT64_MAX

struct xsk_umem_info {
	struct xsk_ring_prod fq;
	struct xsk_ring_cons cq;
	struct xsk_umem *umem;
	void *buffer;
};

struct stats_record {
	uint64_t timestamp;
	uint64_t rx_packets;
	uint64_t rx_bytes;
	uint64_t tx_packets;
	uint64_t tx_bytes;
};

struct xsk_socket_info {
	struct xsk_ring_cons rx;
	struct xsk_ring_prod tx;
	struct xsk_umem_info *umem;
	struct xsk_socket *xsk;

	uint64_t umem_frame_addr[NUM_FRAMES];
	uint32_t umem_frame_free;

	uint32_t outstanding_tx;

	struct stats_record stats;
	struct stats_record prev_stats;
};

#define NANOSEC_PER_SEC 1000000000 /* 10^9 */
static uint64_t gettime(void)
{
	struct timespec t;
	int res;

	res = clock_gettime(CLOCK_MONOTONIC, &t);
	if (res < 0) {
		fprintf(stderr, "Error with gettimeofday! (%i)\n", res);
		exit(EXIT_FAIL);
	}
	return (uint64_t) t.tv_sec * NANOSEC_PER_SEC + t.tv_nsec;
}

static inline __u32 xsk_ring_prod__free(struct xsk_ring_prod *r)
{
	r->cached_cons = *r->consumer + r->size;
	return r->cached_cons - r->cached_prod;
}

static const char *__doc__ = "AF_XDP kernel bypass example\n";

static const struct option_wrapper long_options[] = {

	{{"help",	 no_argument,		NULL, 'h' },
	 "Show help", false},

	{{"dev",	 required_argument,	NULL, 'd' },
	 "Operate on device <ifname>", "<ifname>", true},

	{{"skb-mode",	 no_argument,		NULL, 'S' },
	 "Install XDP program in SKB (AKA generic) mode"},

	{{"native-mode", no_argument,		NULL, 'N' },
	 "Install XDP program in native mode"},

	{{"auto-mode",	 no_argument,		NULL, 'A' },
	 "Auto-detect SKB or native mode"},

	{{"force",	 no_argument,		NULL, 'F' },
	 "Force install, replacing existing program on interface"},

	{{"copy",        no_argument,		NULL, 'c' },
	 "Force copy mode"},

	{{"zero-copy",	 no_argument,		NULL, 'z' },
	 "Force zero-copy mode"},

	{{"queue",	 required_argument,	NULL, 'Q' },
	 "Configure interface receive queue for AF_XDP, default=0"},

	{{"poll-mode",	 no_argument,		NULL, 'p' },
	 "Use the poll() API waiting for packets to arrive"},

	{{"unload",      no_argument,		NULL, 'U' },
	 "Unload XDP program instead of loading"},

	{{"quiet",	 no_argument,		NULL, 'q' },
	 "Quiet mode (no output)"},

	{{"pktinfo",	 no_argument,		NULL, 'P' },
	 "Print packet info output mode (debug)"},

	{{"metainfo",	 no_argument,		NULL, 'm' },
	 "Print XDP metadata info output mode (debug)"},

	{{"debug",	 no_argument,		NULL, 'D' },
	 "Debug info output mode (debug)"},

	{{"filename",    required_argument,	NULL,  1  },
	 "Load program from <file>", "<file>"},

	{{"progsec",	 required_argument,	NULL,  2  },
	 "Load program in <section> of the ELF file", "<section>"},

	{{0, 0, NULL,  0 }, NULL, false}
};

static bool global_exit;

static struct xsk_umem_info *configure_xsk_umem(void *buffer, uint64_t size)
{
	struct xsk_umem_info *umem;
	int ret;

	struct xsk_umem_config xsk_umem_cfg = {
		/* We recommend that you set the fill ring size >= HW RX ring size +
		 * AF_XDP RX ring size. Make sure you fill up the fill ring
		 * with buffers at regular intervals, and you will with this setting
		 * avoid allocation failures in the driver. These are usually quite
		 * expensive since drivers have not been written to assume that
		 * allocation failures are common. For regular sockets, kernel
		 * allocated memory is used that only runs out in OOM situations
		 * that should be rare.
		 */
		.fill_size = XSK_RING_PROD__DEFAULT_NUM_DESCS * 2,
		.comp_size = XSK_RING_CONS__DEFAULT_NUM_DESCS,
		.frame_size = FRAME_SIZE,
		/* Notice XSK_UMEM__DEFAULT_FRAME_HEADROOM is zero */
		.frame_headroom = 256,
		//.frame_headroom = 0,
		.flags = 0
	};

	umem = calloc(1, sizeof(*umem));
	if (!umem)
		return NULL;

	ret = xsk_umem__create(&umem->umem, buffer, size, &umem->fq, &umem->cq,
			       &xsk_umem_cfg);
	if (ret) {
		errno = -ret;
		return NULL;
	}

	umem->buffer = buffer;
	return umem;
}

static uint64_t xsk_alloc_umem_frame(struct xsk_socket_info *xsk)
{
	uint64_t frame;
	if (xsk->umem_frame_free == 0)
		return INVALID_UMEM_FRAME;

	frame = xsk->umem_frame_addr[--xsk->umem_frame_free];
	xsk->umem_frame_addr[xsk->umem_frame_free] = INVALID_UMEM_FRAME;
	return frame;
}

static void xsk_free_umem_frame(struct xsk_socket_info *xsk, uint64_t frame)
{
	assert(xsk->umem_frame_free < NUM_FRAMES);

	xsk->umem_frame_addr[xsk->umem_frame_free++] = frame;
}

static uint64_t xsk_umem_free_frames(struct xsk_socket_info *xsk)
{
	return xsk->umem_frame_free;
}

static struct xsk_socket_info *xsk_configure_socket(struct config *cfg,
						    struct xsk_umem_info *umem)
{
	struct xsk_socket_config xsk_cfg;
	struct xsk_socket_info *xsk_info;
	uint32_t idx;
	uint32_t prog_id = 0;
	int i;
	int ret;

	xsk_info = calloc(1, sizeof(*xsk_info));
	if (!xsk_info)
		return NULL;

	xsk_info->umem = umem;
	xsk_cfg.rx_size = XSK_RING_CONS__DEFAULT_NUM_DESCS;
	xsk_cfg.tx_size = XSK_RING_PROD__DEFAULT_NUM_DESCS;
	xsk_cfg.libbpf_flags = 0;
	xsk_cfg.xdp_flags = cfg->xdp_flags;
	xsk_cfg.bind_flags = cfg->xsk_bind_flags;
	ret = xsk_socket__create(&xsk_info->xsk, cfg->ifname,
				 cfg->xsk_if_queue, umem->umem, &xsk_info->rx,
				 &xsk_info->tx, &xsk_cfg);

	if (ret)
		goto error_exit;

	ret = bpf_get_link_xdp_id(cfg->ifindex, &prog_id, cfg->xdp_flags);
	if (ret)
		goto error_exit;

	/* Initialize umem frame allocation */

	for (i = 0; i < NUM_FRAMES; i++)
		xsk_info->umem_frame_addr[i] = i * FRAME_SIZE;

	xsk_info->umem_frame_free = NUM_FRAMES;

	/* Stuff the receive path with buffers, we assume we have enough */
	ret = xsk_ring_prod__reserve(&xsk_info->umem->fq,
				     XSK_RING_PROD__DEFAULT_NUM_DESCS,
				     &idx);

	if (ret != XSK_RING_PROD__DEFAULT_NUM_DESCS)
		goto error_exit;

	for (i = 0; i < XSK_RING_PROD__DEFAULT_NUM_DESCS; i ++)
		*xsk_ring_prod__fill_addr(&xsk_info->umem->fq, idx++) =
			xsk_alloc_umem_frame(xsk_info);

	xsk_ring_prod__submit(&xsk_info->umem->fq,
			      XSK_RING_PROD__DEFAULT_NUM_DESCS);

	return xsk_info;

error_exit:
	errno = -ret;
	return NULL;
}

static void complete_tx(struct xsk_socket_info *xsk)
{
	unsigned int completed;
	uint32_t idx_cq;

	if (!xsk->outstanding_tx)
		return;

	sendto(xsk_socket__fd(xsk->xsk), NULL, 0, MSG_DONTWAIT, NULL, 0);


	/* Collect/free completed TX buffers */
	completed = xsk_ring_cons__peek(&xsk->umem->cq,
					XSK_RING_CONS__DEFAULT_NUM_DESCS,
					&idx_cq);

	if (completed > 0) {
		for (int i = 0; i < completed; i++)
			xsk_free_umem_frame(xsk,
					    *xsk_ring_cons__comp_addr(&xsk->umem->cq,
								      idx_cq++));

		xsk_ring_cons__release(&xsk->umem->cq, completed);
		xsk->outstanding_tx -= completed < xsk->outstanding_tx ?
			completed : xsk->outstanding_tx;
	}
}

static inline __sum16 csum16_add(__sum16 csum, __be16 addend)
{
	uint16_t res = (uint16_t)csum;

	res += (__u16)addend;
	return (__sum16)(res + (res < (__u16)addend));
}

static inline __sum16 csum16_sub(__sum16 csum, __be16 addend)
{
	return csum16_add(csum, ~addend);
}

static inline void csum_replace2(__sum16 *sum, __be16 old, __be16 new)
{
	*sum = ~csum16_add(csum16_sub(~(*sum), old), new);
}

struct xdp_hints {
	struct xsk_btf_info *xbi;
	const char *struct_name;
};

static struct xdp_hints xdp_meta_with_time = {
	.struct_name = "xdp_hints_rx_time",
};

static struct xdp_hints xdp_meta_with_mark = {
	.struct_name = "xdp_hints_mark",
};

int init_xdp_hints(struct btf *btf_obj, struct xdp_hints *xh)
{
	int err;

	err = xsk_btf__init_xdp_hint(btf_obj, xh->struct_name, &(xh->xbi));
	if (err) {
		fprintf(stderr, "ERR(%d): Cannot BTF find struct:%s\n",
			err, xh->struct_name);
		return err;
	}

	if (!xsk_btf__has_field("btf_id", xh->xbi)) {
		fprintf(stderr, "ERR: %s doesn't contain member btf_id\n",
			xh->struct_name);
		return -ENOENT;
	}
	return 0;
}

static struct xsk_btf_member member_rx_ktime;

int init_btf_info_via_bpf_object(struct bpf_object *bpf_obj)
{
	struct btf *btf = bpf_object__btf(bpf_obj);
	int err;

	if ((err = init_xdp_hints(btf, &xdp_meta_with_time)))
		return err;

	if ((err = init_xdp_hints(btf, &xdp_meta_with_mark)))
		return err;

	/* Check member with "rx_ktime" exist */
	if (!xsk_btf__has_field("rx_ktime", xdp_meta_with_time.xbi)) {
		return -EBADSLT;
	}

	/* Cache member "rx_ktime" */
	if (!xsk_btf__field_member("rx_ktime", xdp_meta_with_time.xbi,
				   &member_rx_ktime)) {
		return -EBADSLT;
	}
	// xsk_btf__read(NULL, 0, NULL, NULL, NULL);

	/* Check member with "mark" exist */
	if (!xsk_btf__has_field("mark", xdp_meta_with_mark.xbi)) {
		return -EBADSLT;
	}

	return 0;
}

struct meta_info {
	union {
		struct {
			__u32 pad;
			__u32 mark;
		};
		__u64 rx_ktime;
	};
	__u32 btf_id;
} __attribute__((aligned(4))) __attribute__((packed));

static void print_meta_info(uint8_t *pkt, uint32_t len)
{
	/* XDP data_meta is stored just before packet data.
	 * Thus, access this via a negative offset.
	 *
	 * REMEMBER: The real assignment is making this dynamic via using BTF.
	 */
	struct meta_info *meta = (void *)(pkt - sizeof(*meta));

	printf("DEBUG-meta btf_id:%d mark:%d (p:%u) or rx_time:%llu\n",
	       meta->btf_id, meta->mark, meta->pad, meta->rx_ktime);

}

static void print_meta_info_mark(uint8_t *pkt)
{
	struct xsk_btf_info *xbi = xdp_meta_with_mark.xbi;
	__u32 mark;

	XSK_BTF_READ_INTO(mark, mark, xbi, pkt);
	printf("meta-mark mark:%u\n", mark);
}

static int print_meta_info_time(uint8_t *pkt)
{
	struct xsk_btf_info *xbi = xdp_meta_with_time.xbi;
	__u64 time_now; // = gettime();
	__u64 *rx_ktime_ptr; /* Points directly to member memory */
	__u64 rx_ktime;
	__u64 diff;
	int err;

	/* Notice how rx_ktime_ptr becomes a pointer into struct memory  */
	err = xsk_btf__read((void **)&rx_ktime_ptr, sizeof(*rx_ktime_ptr),
			    "rx_ktime", xbi, pkt);
	if (err) {
		fprintf(stderr, "ERROR(%d) no rx_ktime?!\n", err);
		return err;
	}
	rx_ktime = *rx_ktime_ptr;
	/* Above same as XSK_BTF_READ_INTO(rx_ktime, rx_ktime, xbi, pkt); */

	time_now = gettime();
	diff = time_now - rx_ktime;

	printf("meta-time rx_ktime:%llu time_now:%llu diff:%llu ns\n",
	       rx_ktime, time_now, diff);

	return 0;
}

static int print_meta_info_time_faster(uint8_t *pkt)
{
	struct xsk_btf_info *xbi = xdp_meta_with_time.xbi;
	__u64 time_now; // = gettime();
	__u64 *rx_ktime_ptr; /* Points directly to member memory */
	__u64 rx_ktime;
	__u64 diff;
	int err;

	/* Use API that doesn't involve allocations to access BTF struct member */
	err = xsk_btf__read_member((void **)&rx_ktime_ptr, sizeof(*rx_ktime_ptr),
				   &member_rx_ktime, xbi, pkt);
	if (err) {
		fprintf(stderr, "ERROR(%d) no rx_ktime?!\n", err);
		return err;
	}
	rx_ktime = *rx_ktime_ptr;

	time_now = gettime();
	diff = time_now - rx_ktime;

	printf("meta-time rx_ktime:%llu time_now:%llu diff:%llu ns\n",
	       rx_ktime, time_now, diff);

	return 0;
}


static void print_meta_info_via_btf( uint8_t *pkt)
{
	__u32 btf_id = xsk_umem__btf_id(pkt);

	__u32 meta_time = xsk_btf__btf_type_id(xdp_meta_with_time.xbi);
	__u32 meta_mark = xsk_btf__btf_type_id(xdp_meta_with_mark.xbi);

	if (btf_id == meta_time) {
		//print_meta_info_time(pkt);
		print_meta_info_time_faster(pkt);
	} else if (btf_id == meta_mark) {
		print_meta_info_mark(pkt);
	}

}

/* As debug tool print some info about packet */
static void print_pkt_info(uint8_t *pkt, uint32_t len)
{
	struct ethhdr *eth = (struct ethhdr *) pkt;
	__u16 proto = ntohs(eth->h_proto);

	char *fmt = "DEBUG-pkt len=%04d Eth-proto:0x%X %s "
		"src:%s -> dst:%s\n";
	char src_str[128] = { 0 };
	char dst_str[128] = { 0 };

	if (proto == ETH_P_IP) {
		struct iphdr *ipv4 = (struct iphdr *) (eth + 1);
		inet_ntop(AF_INET, &ipv4->saddr, src_str, sizeof(src_str));
		inet_ntop(AF_INET, &ipv4->daddr, dst_str, sizeof(dst_str));
		printf(fmt, len, proto, "IPv4", src_str, dst_str);
	} else if (proto == ETH_P_ARP) {
		printf(fmt, len, proto, "ARP", "", "");
	} else if (proto == ETH_P_IPV6) {
		struct ipv6hdr *ipv6 = (struct ipv6hdr *) (eth + 1);
		inet_ntop(AF_INET6, &ipv6->saddr, src_str, sizeof(src_str));
		inet_ntop(AF_INET6, &ipv6->daddr, dst_str, sizeof(dst_str));
		printf(fmt, len, proto, "IPv6", src_str, dst_str);
	} else {
		printf(fmt, len, proto, "Unknown", "", "");
	}
}

static bool process_packet(struct xsk_socket_info *xsk,
			   uint64_t addr, uint32_t len)
{
	uint8_t *pkt = xsk_umem__get_data(xsk->umem->buffer, addr);

	if (debug_meta) {
		print_meta_info(pkt, len);
	}
	print_meta_info_via_btf(pkt);

	if (debug)
		printf("XXX addr:0x%lX pkt_ptr:0x%p\n", addr, pkt);

	if (debug_pkt)
		print_pkt_info(pkt, len);

        /* Lesson#3: Write an IPv6 ICMP ECHO parser to send responses
	 *
	 * Some assumptions to make it easier:
	 * - No VLAN handling
	 * - Only if nexthdr is ICMP
	 * - Just return all data with MAC/IP swapped, and type set to
	 *   ICMPV6_ECHO_REPLY
	 * - Recalculate the icmp checksum */

	if (false) {
		int ret;
		uint32_t tx_idx = 0;
		uint8_t tmp_mac[ETH_ALEN];
		struct in6_addr tmp_ip;
		struct ethhdr *eth = (struct ethhdr *) pkt;
		struct ipv6hdr *ipv6 = (struct ipv6hdr *) (eth + 1);
		struct icmp6hdr *icmp = (struct icmp6hdr *) (ipv6 + 1);

		if (ntohs(eth->h_proto) != ETH_P_IPV6 ||
		    len < (sizeof(*eth) + sizeof(*ipv6) + sizeof(*icmp)) ||
		    ipv6->nexthdr != IPPROTO_ICMPV6 ||
		    icmp->icmp6_type != ICMPV6_ECHO_REQUEST)
			return false;

		memcpy(tmp_mac, eth->h_dest, ETH_ALEN);
		memcpy(eth->h_dest, eth->h_source, ETH_ALEN);
		memcpy(eth->h_source, tmp_mac, ETH_ALEN);

		memcpy(&tmp_ip, &ipv6->saddr, sizeof(tmp_ip));
		memcpy(&ipv6->saddr, &ipv6->daddr, sizeof(tmp_ip));
		memcpy(&ipv6->daddr, &tmp_ip, sizeof(tmp_ip));

		icmp->icmp6_type = ICMPV6_ECHO_REPLY;

		csum_replace2(&icmp->icmp6_cksum,
			      htons(ICMPV6_ECHO_REQUEST << 8),
			      htons(ICMPV6_ECHO_REPLY << 8));

		/* Here we sent the packet out of the receive port. Note that
		 * we allocate one entry and schedule it. Your design would be
		 * faster if you do batch processing/transmission */

		ret = xsk_ring_prod__reserve(&xsk->tx, 1, &tx_idx);
		if (ret != 1) {
			/* No more transmit slots, drop the packet */
			return false;
		}

		xsk_ring_prod__tx_desc(&xsk->tx, tx_idx)->addr = addr;
		xsk_ring_prod__tx_desc(&xsk->tx, tx_idx)->len = len;
		xsk_ring_prod__submit(&xsk->tx, 1);
		xsk->outstanding_tx++;

		xsk->stats.tx_bytes += len;
		xsk->stats.tx_packets++;
		return true;
	}

	return false;
}

static void handle_receive_packets(struct xsk_socket_info *xsk)
{
	unsigned int rcvd, stock_frames, i;
	uint32_t idx_rx = 0, idx_fq = 0;
	int ret;

	rcvd = xsk_ring_cons__peek(&xsk->rx, RX_BATCH_SIZE, &idx_rx);
	if (!rcvd)
		return;

	/* Stuff the ring with as much frames as possible */
	stock_frames = xsk_prod_nb_free(&xsk->umem->fq,
					xsk_umem_free_frames(xsk));

	if (stock_frames > 0) {

		ret = xsk_ring_prod__reserve(&xsk->umem->fq, stock_frames,
					     &idx_fq);

		/* This should not happen, but just in case */
		while (ret != stock_frames)
			ret = xsk_ring_prod__reserve(&xsk->umem->fq, rcvd,
						     &idx_fq);

		for (i = 0; i < stock_frames; i++)
			*xsk_ring_prod__fill_addr(&xsk->umem->fq, idx_fq++) =
				xsk_alloc_umem_frame(xsk);

		xsk_ring_prod__submit(&xsk->umem->fq, stock_frames);
	}

	/* Process received packets */
	for (i = 0; i < rcvd; i++) {
		uint64_t addr = xsk_ring_cons__rx_desc(&xsk->rx, idx_rx)->addr;
		uint32_t len = xsk_ring_cons__rx_desc(&xsk->rx, idx_rx++)->len;

		if (!process_packet(xsk, addr, len))
			xsk_free_umem_frame(xsk, addr);

		xsk->stats.rx_bytes += len;
	}

	xsk_ring_cons__release(&xsk->rx, rcvd);
	xsk->stats.rx_packets += rcvd;

	/* Do we need to wake up the kernel for transmission */
	complete_tx(xsk);
  }

static void rx_and_process(struct config *cfg,
			   struct xsk_socket_info *xsk_socket)
{
	struct pollfd fds[2];
	int ret, nfds = 1;

	memset(fds, 0, sizeof(fds));
	fds[0].fd = xsk_socket__fd(xsk_socket->xsk);
	fds[0].events = POLLIN;

	while(!global_exit) {
		if (cfg->xsk_poll_mode) {
			ret = poll(fds, nfds, -1);
			if (ret <= 0 || ret > 1)
				continue;
		}
		handle_receive_packets(xsk_socket);
	}
}

static double calc_period(struct stats_record *r, struct stats_record *p)
{
	double period_ = 0;
	__u64 period = 0;

	period = r->timestamp - p->timestamp;
	if (period > 0)
		period_ = ((double) period / NANOSEC_PER_SEC);

	return period_;
}

static void stats_print(struct stats_record *stats_rec,
			struct stats_record *stats_prev)
{
	uint64_t packets, bytes;
	double period;
	double pps; /* packets per sec */
	double bps; /* bits per sec */

	char *fmt = "%-12s %'11lld pkts (%'10.0f pps)"
		" %'11lld Kbytes (%'6.0f Mbits/s)"
		" period:%f\n";

	period = calc_period(stats_rec, stats_prev);
	if (period == 0)
		period = 1;

	packets = stats_rec->rx_packets - stats_prev->rx_packets;
	pps     = packets / period;

	bytes   = stats_rec->rx_bytes   - stats_prev->rx_bytes;
	bps     = (bytes * 8) / period / 1000000;

	printf(fmt, "AF_XDP RX:", stats_rec->rx_packets, pps,
	       stats_rec->rx_bytes / 1000 , bps,
	       period);

	packets = stats_rec->tx_packets - stats_prev->tx_packets;
	pps     = packets / period;

	bytes   = stats_rec->tx_bytes   - stats_prev->tx_bytes;
	bps     = (bytes * 8) / period / 1000000;

	printf(fmt, "       TX:", stats_rec->tx_packets, pps,
	       stats_rec->tx_bytes / 1000 , bps,
	       period);

	printf("\n");
}

static void *stats_poll(void *arg)
{
	unsigned int interval = 2;
	struct xsk_socket_info *xsk = arg;
	static struct stats_record previous_stats = { 0 };

	previous_stats.timestamp = gettime();

	/* Trick to pretty printf with thousands separators use %' */
	setlocale(LC_NUMERIC, "en_US");

	while (!global_exit) {
		sleep(interval);
		xsk->stats.timestamp = gettime();
		stats_print(&xsk->stats, &previous_stats);
		previous_stats = xsk->stats;
	}
	return NULL;
}

static void exit_application(int signal)
{
	signal = signal;
	global_exit = true;
}

int btf_walk_struct_members(struct btf *btf_obj, __s32 btf_id)
{
	const struct btf_member *m;
	const struct btf_type *btype;
	unsigned short vlen;
	__u32 kind;
	int i;

	btype = btf__type_by_id(btf_obj, btf_id);

	kind = btf_kind(btype);
	if (kind != BTF_KIND_STRUCT) {
		fprintf(stderr, "ERROR: %s() BTF must be BTF_KIND_STRUCT",
			__func__);
		return -1;
	}
	/* BTF_KIND_STRUCT and BTF_KIND_UNION are followed
	 * by multiple "struct btf_member".  The exact number
	 * of btf_member is stored in the vlen (of the info in
	 * "struct btf_type").
	 */
	m = btf_members(btype);
	vlen = BTF_INFO_VLEN(btype->info);

	printf("XXX kind:%d members:%d\n", kind, vlen);

	for (i = 0; i < vlen; i++, m++) {
		__s64 sz = btf__resolve_size(btf_obj, m->type);

		printf("XXX [%d] member type:%d bit-offset:%u name_off:%u sz:%lld\n",
		       i, m->type, m->offset, m->name_off, sz);
	}
	return 0;
}

__s32 btf_find_struct(struct btf *btf, const char *name, __s64 *size)
{
	__s32 btf_id = btf__find_by_name_kind(btf, name, BTF_KIND_STRUCT);
	__s64 sz = btf__resolve_size(btf, btf_id);

	if (debug_meta)
		printf("XXX bpf_id:%d struct name:%s size:%lld\n",
		       btf_id, name, sz);
	*size = sz;
	btf_walk_struct_members(btf, btf_id);

	return btf_id;
}

int btf_info_via_bpf_object(struct bpf_object *bpf_obj)
{
	struct btf *btf = bpf_object__btf(bpf_obj);
	__s64 size;
	int err;

	struct xsk_btf_info *xdp_hint_rx_time = NULL;

	static const char *name1 = "xdp_hints_mark";
	static const char *name2 = "xdp_hints_rx_time";

	btf_find_struct(btf, name1, &size);
	btf_find_struct(btf, name2, &size);

	err = xsk_btf__init_xdp_hint(btf, name2, &xdp_hint_rx_time);
	if (err) {
		fprintf(stderr, "WARN(%d): Cannot xsk_btf__init_xdp_hint\n", err);
		return err;
	}
	if (!xsk_btf__has_field("rx_ktime", xdp_hint_rx_time)) {
		fprintf(stderr, "WARN: %s doesn't contain member rx_ktime\n",
			name2);
		return 1;
	}

	return 0;
}

int main(int argc, char **argv)
{
	int ret, err;
	int xsks_map_fd;
	void *packet_buffer;
	uint64_t packet_buffer_size;
	struct rlimit rlim = {RLIM_INFINITY, RLIM_INFINITY};
	struct config cfg = {
		.ifindex   = -1,
		.do_unload = false,
		.filename = "af_xdp_kern.o",
		.progsec = "xdp_sock"
	};
	struct xsk_umem_info *umem;
	struct xsk_socket_info *xsk_socket;
	pthread_t stats_poll_thread;

	struct bpf_object *bpf_obj = NULL;
	struct bpf_map *map;

	/* Global shutdown handler */
	signal(SIGINT, exit_application);

	/* Cmdline options can change progsec */
	parse_cmdline_args(argc, argv, long_options, &cfg, __doc__);

	/* Required option */
	if (cfg.ifindex == -1) {
		fprintf(stderr, "ERROR: Required option --dev missing\n\n");
		usage(argv[0], __doc__, long_options, (argc == 1));
		return EXIT_FAIL_OPTION;
	}

	/* Unload XDP program if requested */
	if (cfg.do_unload)
		return xdp_link_detach(cfg.ifindex, cfg.xdp_flags, 0);

	/* Require loading custom BPF program */
	if (cfg.filename[0] == 0) {
		fprintf(stderr, "ERROR: must load custom BPF-prog\n");
		exit(EXIT_FAILURE);
	} else {
		bpf_obj = load_bpf_and_xdp_attach(&cfg);
		if (!bpf_obj) {
			/* Error handling done in load_bpf_and_xdp_attach() */
			exit(EXIT_FAILURE);
		}

		/* We also need to load the xsks_map */
		map = bpf_object__find_map_by_name(bpf_obj, "xsks_map");
		xsks_map_fd = bpf_map__fd(map);
		if (xsks_map_fd < 0) {
			fprintf(stderr, "ERROR: no xsks map found: %s\n",
				strerror(xsks_map_fd));
			exit(EXIT_FAILURE);
		}
	}

	if (debug_meta) {
		btf_info_via_bpf_object(bpf_obj);
	}
	err = init_btf_info_via_bpf_object(bpf_obj);
	if (err) {
		fprintf(stderr, "ERROR(%d): Invalid BTF info: errno:%s\n",
			err, strerror(errno));
		return EXIT_FAILURE;
	}

	/* Allow unlimited locking of memory, so all memory needed for packet
	 * buffers can be locked.
	 */
	if (setrlimit(RLIMIT_MEMLOCK, &rlim)) {
		fprintf(stderr, "ERROR: setrlimit(RLIMIT_MEMLOCK) \"%s\"\n",
			strerror(errno));
		exit(EXIT_FAILURE);
	}

	/* Allocate memory for NUM_FRAMES of the default XDP frame size */
	packet_buffer_size = NUM_FRAMES * FRAME_SIZE;
	if (posix_memalign(&packet_buffer,
			   getpagesize(), /* PAGE_SIZE aligned */
			   packet_buffer_size)) {
		fprintf(stderr, "ERROR: Can't allocate buffer memory \"%s\"\n",
			strerror(errno));
		exit(EXIT_FAILURE);
	}

	/* Initialize shared packet_buffer for umem usage */
	umem = configure_xsk_umem(packet_buffer, packet_buffer_size);
	if (umem == NULL) {
		fprintf(stderr, "ERROR: Can't create umem \"%s\"\n",
			strerror(errno));
		exit(EXIT_FAILURE);
	}

	/* Open and configure the AF_XDP (xsk) socket */
	xsk_socket = xsk_configure_socket(&cfg, umem);
	if (xsk_socket == NULL) {
		fprintf(stderr, "ERROR: Can't setup AF_XDP socket \"%s\"\n",
			strerror(errno));
		exit(EXIT_FAILURE);
	}

	/* Start thread to do statistics display */
	if (verbose) {
		ret = pthread_create(&stats_poll_thread, NULL, stats_poll,
				     xsk_socket);
		if (ret) {
			fprintf(stderr, "ERROR: Failed creating statistics thread "
				"\"%s\"\n", strerror(errno));
			exit(EXIT_FAILURE);
		}
	}

	/* Receive and count packets than drop them */
	rx_and_process(&cfg, xsk_socket);

	/* Cleanup */
	xsk_socket__delete(xsk_socket->xsk);
	xsk_umem__delete(umem->umem);
	xdp_link_detach(cfg.ifindex, cfg.xdp_flags, 0);

	return EXIT_OK;
}
