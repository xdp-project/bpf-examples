/* SPDX-License-Identifier: GPL-2.0 */

#define _GNU_SOURCE  /* Needed by sched_getcpu */
#include <sched.h>

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
#include <netinet/ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/icmpv6.h>
#include <linux/udp.h>

#include <bpf/btf.h> /* provided by libbpf */

#include "common_params.h"
#include "common_user_bpf_xdp.h"
// #include "common_libbpf.h"
#include "af_xdp_kern_shared.h"

#include "lib_xsk_extend.h"
#include "ethtool_utils.h"
#include "lib_checksum.h"

#define NUM_FRAMES         4096 /* Frames per queue */
#define FRAME_SIZE         XSK_UMEM__DEFAULT_FRAME_SIZE /* 4096 */
#define RX_BATCH_SIZE      64
#define INVALID_UMEM_FRAME UINT64_MAX

struct mem_frame_allocator {
	uint32_t umem_frame_free;
	uint32_t umem_frame_max;
	uint64_t *umem_frame_addr; /* array */
};

struct xsk_umem_info {
	struct xsk_ring_prod init_fq;
	struct xsk_ring_cons init_cq;
	struct xsk_umem *umem;
	void *buffer;
	struct mem_frame_allocator mem;
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
	struct xsk_ring_prod fq;
	struct xsk_ring_cons cq;

	uint32_t outstanding_tx;
	int queue_id;

	struct stats_record stats;
	struct stats_record prev_stats;
};

struct xsk_container {
	struct xsk_socket_info *sockets[MAX_AF_SOCKS];
	int num; /* Number of xsk_sockets configured */
};

/**
 * BTF setup XDP-hints
 * -------------------
 * Setup the data structures for accessing the XDP-hints provided by
 * kernel side BPF-prog via decoding BTF-info provided in BPF
 * ELF-object file.
 */

/* This struct BTF mirrors kernel-side struct xdp_hints_rx_time */
struct xdp_hints_rx_time {
	__u32 btf_type_id; /* cached xsk_btf__btf_type_id(xbi) */
	struct xsk_btf_info *xbi;
	struct xsk_btf_member rx_ktime;
	struct xsk_btf_member xdp_rx_cpu;
} xdp_hints_rx_time = { 0 };

/* This struct BTF mirrors kernel-side struct xdp_hints_mark */
struct xdp_hints_mark {
	__u32 btf_type_id; /* cached xsk_btf__btf_type_id(xbi) */
	struct xsk_btf_info *xbi;
	struct xsk_btf_member mark;
} xdp_hints_mark = { 0 };

struct xsk_btf_info *setup_btf_info(struct btf *btf,
				    const char *struct_name)
{
	struct xsk_btf_info *xbi = NULL;
	int err;

	err = xsk_btf__init_xdp_hint(btf, struct_name, &xbi);
	if (err) {
		fprintf(stderr, "WARN(%d): Cannot BTF find struct:%s\n",
			err, struct_name);
		return NULL;
	}

	if (!xsk_btf__has_field("btf_id", xbi)) {
		fprintf(stderr, "ERR: %s doesn't contain member btf_id\n",
			struct_name);
		xsk_btf__free_xdp_hint(xbi);
		return NULL;
	}

	if (debug_meta)
		printf("Setup BTF based XDP hints for struct: %s\n",
		       struct_name);

	return xbi;
}

int init_btf_info_via_bpf_object(struct bpf_object *bpf_obj)
{
	struct btf *btf = bpf_object__btf(bpf_obj);
	struct xsk_btf_info *xbi;

	xbi = setup_btf_info(btf, "xdp_hints_rx_time");
	if (xbi) {
		/* Lookup info on required member "rx_ktime" */
		if (!xsk_btf__field_member("rx_ktime", xbi,
					   &xdp_hints_rx_time.rx_ktime))
			return -EBADSLT;
		if (!xsk_btf__field_member("xdp_rx_cpu", xbi,
					   &xdp_hints_rx_time.xdp_rx_cpu))
			return -EBADSLT;
		xdp_hints_rx_time.btf_type_id = xsk_btf__btf_type_id(xbi);
		xdp_hints_rx_time.xbi = xbi;
	}

	xbi = setup_btf_info(btf, "xdp_hints_mark");
	if (xbi) {
		if (!xsk_btf__field_member("mark", xbi, &xdp_hints_mark.mark))
			return -EBADSLT;
		xdp_hints_mark.btf_type_id = xsk_btf__btf_type_id(xbi);
		xdp_hints_mark.xbi = xbi;
	}

	return 0;
}

void pr_addr_info(const char *msg, uint64_t pkt_addr, struct xsk_umem_info *umem)
{
	uint64_t pkt_nr = pkt_addr / FRAME_SIZE; /* Integer div round off */
	uint32_t offset = pkt_addr - (pkt_nr * FRAME_SIZE); /* what got rounded off */
	uint8_t *pkt_ptr = NULL;

	if (!debug)
		return;

	if (umem)
		pkt_ptr = xsk_umem__get_data(umem->buffer, pkt_addr);

	printf(" - Addr-info: %s pkt_nr:%lu offset:%u (addr:0x%lX) ptr:%p\n",
	       msg, pkt_nr, offset, pkt_addr, pkt_ptr);
}

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
	 "Configure single interface receive queue for AF_XDP"},

	{{"priority",	 required_argument,	NULL, 'p' },
	 "Setup real-time priority for process"},

	{{"wakeup-mode", no_argument,		NULL, 'w' },
	 "Use poll() API waiting for packets to arrive via wakeup from kernel"},

	{{"spin-mode", no_argument,		NULL, 's' },
	 "Let userspace process spin checking for packets (disable --wakeup-mode)"},

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

/**
 * Simple memory allocator for umem frames
 */

static uint64_t mem_alloc_umem_frame(struct mem_frame_allocator *mem)
{
	uint64_t frame;
	if (mem->umem_frame_free == 0)
		return INVALID_UMEM_FRAME;

	frame = mem->umem_frame_addr[--mem->umem_frame_free];
	mem->umem_frame_addr[mem->umem_frame_free] = INVALID_UMEM_FRAME;
	return frame;
}

static void mem_free_umem_frame(struct mem_frame_allocator *mem, uint64_t frame)
{
	assert(mem->umem_frame_free < mem->umem_frame_max);

	mem->umem_frame_addr[mem->umem_frame_free++] = frame;
}

static uint64_t mem_avail_umem_frames(struct mem_frame_allocator *mem)
{
	return mem->umem_frame_free;
}

static void mem_init_umem_frame_allocator(struct mem_frame_allocator *mem,
					  uint32_t nr_frames)
{
	/* Initialize umem frame allocator */
	int i;

	mem->umem_frame_addr = calloc(nr_frames, sizeof(*mem->umem_frame_addr));
	if (!mem->umem_frame_addr) {
		fprintf(stderr,
			"ERROR: Cannot allocate umem_frame_addr array sz:%u\n",
			nr_frames);
		exit(EXIT_FAILURE);
	}
	mem->umem_frame_max = nr_frames;

	/* The umem_frame_addr is basically index into umem->buffer memory area */
	for (i = 0; i < nr_frames; i++)
		mem->umem_frame_addr[i] = i * FRAME_SIZE;

	mem->umem_frame_free = nr_frames;
}

static struct xsk_umem_info *configure_xsk_umem(void *buffer, uint64_t size,
						uint32_t frame_size, uint32_t nr_frames)
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
//		.fill_size = XSK_RING_PROD__DEFAULT_NUM_DESCS * 2,
		.fill_size = XSK_RING_PROD__DEFAULT_NUM_DESCS, /* Fix later */
		.comp_size = XSK_RING_CONS__DEFAULT_NUM_DESCS,
		.frame_size = frame_size,
		/* Notice XSK_UMEM__DEFAULT_FRAME_HEADROOM is zero */
		.frame_headroom = 256,
		//.frame_headroom = 0,
		.flags = 0
	};

	umem = calloc(1, sizeof(*umem));
	if (!umem)
		return NULL;

	ret = xsk_umem__create(&umem->umem, buffer, size,
			       &umem->init_fq, &umem->init_cq,
			       &xsk_umem_cfg);

	if (ret) {
		errno = -ret;
		return NULL;
	}

	umem->buffer = buffer;

	/* Setup our own umem frame allocator system */
	mem_init_umem_frame_allocator(&umem->mem, nr_frames);

	return umem;
}

static int xsk_populate_fill_ring(struct xsk_ring_prod *fq,
				  struct xsk_umem_info *umem,
				  int nr_frames)
{
	uint32_t idx;
	int ret, i;

	/* Stuff the receive path with buffers, we assume we have enough */
	ret = xsk_ring_prod__reserve(fq, nr_frames, &idx);

	if (ret != nr_frames)
		goto error_exit;

	for (i = 0; i < nr_frames; i++)
		*xsk_ring_prod__fill_addr(fq, idx++) =
			mem_alloc_umem_frame(&umem->mem);

	xsk_ring_prod__submit(fq, nr_frames);
	return 0;
error_exit:
	return -EINVAL;
}


static struct xsk_socket_info *xsk_configure_socket(struct config *cfg,
						    struct xsk_umem_info *umem,
						    int queue_id,
						    int xsks_map_fd)
{
	struct xsk_socket_config xsk_cfg;
	struct xsk_socket_info *xsk_info;
	int _queue_id = queue_id;
	uint32_t prog_id = 0;
	int ret;

	xsk_info = calloc(1, sizeof(*xsk_info));
	if (!xsk_info)
		return NULL;

	/* If user specified explicit --queue number then use that */
	if (cfg->xsk_if_queue >= 0)
		_queue_id = cfg->xsk_if_queue;
	xsk_info->queue_id = _queue_id;

	xsk_info->umem = umem;
	xsk_cfg.rx_size = XSK_RING_CONS__DEFAULT_NUM_DESCS;
	xsk_cfg.tx_size = XSK_RING_PROD__DEFAULT_NUM_DESCS;
	xsk_cfg.libbpf_flags = XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD;
	xsk_cfg.xdp_flags = cfg->xdp_flags;
	xsk_cfg.bind_flags = cfg->xsk_bind_flags;

//	ret = xsk_socket__create(&xsk_info->xsk, cfg->ifname,
//				 _queue_id, umem->umem, &xsk_info->rx,
//				 &xsk_info->tx, &xsk_cfg);

	ret = xsk_socket__create_shared(&xsk_info->xsk, cfg->ifname,
					_queue_id, umem->umem,
					&xsk_info->rx,
					&xsk_info->tx,
					&xsk_info->fq,
					&xsk_info->cq,
					&xsk_cfg);

	if (ret)
		goto error_exit;

	ret = bpf_get_link_xdp_id(cfg->ifindex, &prog_id, cfg->xdp_flags);
	if (ret)
		goto error_exit;

	/* Due to XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD manually update map */
	//  xsk_socket__update_xskmap(xsk_info->xsk, xsks_map_fd);
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
	completed = xsk_ring_cons__peek(&xsk->cq,
					XSK_RING_CONS__DEFAULT_NUM_DESCS,
					&idx_cq);

	if (completed > 0) {
		for (int i = 0; i < completed; i++)
			mem_free_umem_frame(&xsk->umem->mem,
					    *xsk_ring_cons__comp_addr(&xsk->cq,
								      idx_cq++));

		xsk_ring_cons__release(&xsk->cq, completed);
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

/**
 * Packet fill helpers
 */
static uint8_t base_pkt_data[FRAME_SIZE];

static struct ether_addr opt_tx_smac =
{{ 0x24, 0x5e, 0xbe, 0x57, 0xf1, 0x64 }};
static struct ether_addr opt_tx_dmac =
{{ 0x00, 0x1b, 0x21, 0xbb, 0x9a, 0x82 }};

#define MIN_PKT_SIZE 64
static uint16_t opt_pkt_size = MIN_PKT_SIZE;

#define PKT_HDR_SIZE (sizeof(struct ethhdr) + sizeof(struct iphdr) + \
		      sizeof(struct udphdr))

#define ETH_FCS_SIZE 4
#define PKT_SIZE		(opt_pkt_size - ETH_FCS_SIZE)
#define IP_PKT_SIZE		(PKT_SIZE - sizeof(struct ethhdr))
#define UDP_PKT_SIZE		(IP_PKT_SIZE - sizeof(struct iphdr))
#define UDP_PKT_DATA_SIZE	(UDP_PKT_SIZE - sizeof(struct udphdr))

static void gen_eth_hdr(struct ethhdr *eth_hdr)
{
	/* Ethernet header */
	memcpy(eth_hdr->h_dest  , &opt_tx_dmac, ETH_ALEN);
	memcpy(eth_hdr->h_source, &opt_tx_smac, ETH_ALEN);
	eth_hdr->h_proto = htons(ETH_P_IP);
}

static bool get_ipv4_u32(char *ip_str, uint32_t *ip_addr)
{
	int res;

	res = inet_pton(AF_INET, ip_str, ip_addr);
	if (res <= 0) {
		if (res == 0)
			fprintf(stderr,	"ERROR: IP%s \"%s\" not in presentation format\n",
				"v4", ip_str);
		else
			perror("inet_pton");
		return false;
	}
	return true;
}

static char *opt_ip_str_src = "192.168.44.2";
static char *opt_ip_str_dst = "192.168.44.3";

static void gen_ip_hdr(struct iphdr *ip_hdr)
{
	uint32_t saddr;
	uint32_t daddr;

	get_ipv4_u32(opt_ip_str_src, &saddr);
	get_ipv4_u32(opt_ip_str_dst, &daddr);

	/* IP header */
	ip_hdr->version = IPVERSION;
	ip_hdr->ihl = 0x5; /* 20 byte header */
	ip_hdr->tos = 0x0;
	ip_hdr->tot_len = htons(IP_PKT_SIZE);
	ip_hdr->id = 0;
	ip_hdr->frag_off = 0;
	ip_hdr->ttl = IPDEFTTL;
	ip_hdr->protocol = IPPROTO_UDP;
	ip_hdr->saddr = saddr;
	ip_hdr->daddr = daddr;

	/* IP header checksum */
	ip_hdr->check = 0;
	ip_hdr->check = ip_fast_csum((const void *)ip_hdr, ip_hdr->ihl);
}

static uint32_t opt_pkt_fill_pattern = 0x41424344;

static void gen_udp_hdr(struct udphdr *udp_hdr, struct iphdr *ip_hdr)
{
	/* UDP header */
	udp_hdr->source = htons(0x1000);
	udp_hdr->dest = htons(0x1000);
	udp_hdr->len = htons(UDP_PKT_SIZE);

	/* UDP data */
	memset32_htonl(udp_hdr + sizeof(struct udphdr),
		       opt_pkt_fill_pattern,
		       UDP_PKT_DATA_SIZE);

	if (0) {
		uint8_t *p = udp_hdr + sizeof(struct udphdr);
		int i;

		for (i = 0; i < UDP_PKT_DATA_SIZE; i++) {
			printf("i[%d] = %c\n", i, p[i]);
		}
	}

	/* UDP header checksum */
	udp_hdr->check = 0;
	udp_hdr->check = udp_csum(ip_hdr->saddr, ip_hdr->daddr, UDP_PKT_SIZE,
				  IPPROTO_UDP, (__u16 *)udp_hdr);
}

static void gen_base_pkt(uint8_t *pkt_ptr)
{
	struct ethhdr *eth_hdr = (struct ethhdr *)pkt_ptr;
	struct iphdr *ip_hdr = (struct iphdr *)(pkt_ptr +
						sizeof(struct ethhdr));
	struct udphdr *udp_hdr = (struct udphdr *)(pkt_ptr +
						   sizeof(struct ethhdr) +
						   sizeof(struct iphdr));

	gen_eth_hdr(eth_hdr);
	gen_ip_hdr(ip_hdr);
	gen_udp_hdr(udp_hdr, ip_hdr);
}


/**
 * BTF accessing XDP-hints
 * -----------------------
 * Accessing the XDP-hints via BTF requires setup done earlier.  As our target
 * application have real-time requirements, it is preferred that the setup can
 * happen outside the packet processing path.  E.g. avoid doing the setup first
 * time a packet with a new BTF-ID is seen.
 */

static int print_meta_info_time(uint8_t *pkt, struct xdp_hints_rx_time *meta,
				__u32 qid)
{
	__u64 time_now; // = gettime();
	__u32 xdp_rx_cpu = 0xffff;
	__u32 cpu_running;
	__u64 *rx_ktime_ptr; /* Points directly to member memory */
	__u64 rx_ktime;
	__u64 diff;
	int err;

	/* Quick stats */
	static bool first = true;
	static unsigned int max = 0;
	static unsigned int min = -1;
	static double tot = 0;
	static __u64 cnt = 0;

	/* API doesn't involve allocations to access BTF struct member */
	err = xsk_btf__read((void **)&rx_ktime_ptr, sizeof(*rx_ktime_ptr),
			    &meta->rx_ktime, meta->xbi, pkt);
	if (err) {
		fprintf(stderr, "ERROR(%d) no rx_ktime?!\n", err);
		return err;
	}
	/* Notice how rx_ktime_ptr becomes a pointer into struct memory */
	rx_ktime = *rx_ktime_ptr;

	time_now = gettime();
	diff = time_now - rx_ktime;

	/* Quick stats, exclude first measurement */
	if (!first) {
		min = (min < diff) ? min : diff;
		max = (max > diff) ? max : diff;
		cnt++;
		tot += diff;
	}
	first = false;

	cpu_running = sched_getcpu();
	XSK_BTF_READ_INTO(xdp_rx_cpu,  &meta->xdp_rx_cpu, meta->xbi, pkt);

	if (debug_meta)
		printf("Q[%u] CPU[rx:%d/run:%d]:%s"
		       " meta-time rx_ktime:%llu time_now:%llu diff:%llu ns"
		       "(avg:%.0f min:%u max:%u )\n",
		       qid, xdp_rx_cpu, cpu_running,
		       (xdp_rx_cpu == cpu_running) ? "same" : "remote",
		       rx_ktime, time_now, diff,
		       tot / cnt, min , max);

	return 0;
}

/* Demo API xsk_btf__read_field() that use string for BTF lookup */
static int print_meta_info_time_api2(uint8_t *pkt, __u32 qid)
{
	struct xsk_btf_info *xbi = xdp_hints_rx_time.xbi;
	__u64 time_now; // = gettime();
	__u64 *rx_ktime_ptr; /* Points directly to member memory */
	__u64 rx_ktime;
	__u64 diff;
	int err;

	/* This API cache string lookup (in hashmap), which cause an
	 * allocation first time this is called. Something to consider
	 * for real-time use-cases.
	 */
	err = xsk_btf__read_field((void **)&rx_ktime_ptr, sizeof(*rx_ktime_ptr),
				  "rx_ktime", xbi, pkt);
	if (err) {
		fprintf(stderr, "ERROR(%d) no rx_ktime?!\n", err);
		return err;
	}
	rx_ktime = *rx_ktime_ptr;
	/* same as XSK_BTF_READ_FIELD_INTO(rx_ktime, rx_ktime, xbi, pkt); */

	time_now = gettime();
	diff = time_now - rx_ktime;

	if (debug_meta)
		printf("Q[%u] meta-time rx_ktime:%llu time_now:%llu diff:%llu ns\n",
		       qid, rx_ktime, time_now, diff);

	return 0;
}

static void print_meta_info_mark(uint8_t *pkt, struct xdp_hints_mark *meta,
				 __u32 qid)
{
	struct xsk_btf_info *xbi = meta->xbi;
	__u32 mark = 0;

	/* The 'mark' value is not updated in case of errors */
	XSK_BTF_READ_INTO(mark, &meta->mark, xbi, pkt);
	if (debug_meta)
		printf("Q[%u] meta-mark mark:%u\n", qid, mark);
}

static void print_meta_info_via_btf(uint8_t *pkt, struct xsk_socket_info *xsk)
{
	__u32 btf_id = xsk_umem__btf_id(pkt);
	__u32 qid = xsk->queue_id;

	if (btf_id == 0) {
		if (debug_meta)
			printf("No meta BTF info (btf_id zero)\n");
		return;
	}

	if (btf_id == xdp_hints_rx_time.btf_type_id) {
		print_meta_info_time(pkt, &xdp_hints_rx_time, qid);

	} else if (btf_id == xdp_hints_mark.btf_type_id) {
		print_meta_info_mark(pkt, &xdp_hints_mark, qid);
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

static void tx_pkt(struct config *cfg,
		   struct xsk_socket_info *xsk);

static bool process_packet(struct xsk_socket_info *xsk,
			   uint64_t addr, uint32_t len)
{
	uint8_t *pkt = xsk_umem__get_data(xsk->umem->buffer, addr);

	print_meta_info_via_btf(pkt, xsk);

	//if (debug)
	//	printf("XXX addr:0x%lX pkt_ptr:0x%p\n", addr, pkt);

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

	if (true) {
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

void restock_receive_fill_queue(struct xsk_socket_info *xsk)
{
	unsigned int i, stock_frames;
	uint32_t idx_fq = 0;
	int ret;

	int free_frames = mem_avail_umem_frames(&xsk->umem->mem);
	__u64 start = gettime();

	/* Stuff the ring with as much frames as possible */
	stock_frames = xsk_prod_nb_free(&xsk->fq,
					mem_avail_umem_frames(&xsk->umem->mem));

	if (stock_frames > 0) {

		ret = xsk_ring_prod__reserve(&xsk->fq, stock_frames,
					     &idx_fq);

		/* This should not happen, but just in case */
		if (ret != stock_frames) {
			printf("XXX %s() should not happen (%d vs %d)\n", __func__,
			       stock_frames, ret);
			stock_frames = ret;
		}

		for (i = 0; i < stock_frames; i++)
			*xsk_ring_prod__fill_addr(&xsk->fq, idx_fq++) =
				mem_alloc_umem_frame(&xsk->umem->mem);

		xsk_ring_prod__submit(&xsk->fq, stock_frames);
	}
	__u64 now = gettime();
	if (debug && (stock_frames || free_frames))
		printf("XXX stock_frame:%d free_frames:%d cost of xsk_prod_nb_free() %llu ns\n",
		       stock_frames, free_frames, now - start);
}

static void handle_receive_packets(struct xsk_socket_info *xsk)
{
	unsigned int rcvd, i;
	uint32_t idx_rx = 0;

	rcvd = xsk_ring_cons__peek(&xsk->rx, RX_BATCH_SIZE, &idx_rx);
	if (!rcvd)
		return;

	/* Process received packets */
	for (i = 0; i < rcvd; i++) {
		uint64_t addr = xsk_ring_cons__rx_desc(&xsk->rx, idx_rx)->addr;
		uint32_t len = xsk_ring_cons__rx_desc(&xsk->rx, idx_rx++)->len;

		pr_addr_info(__func__, addr, xsk->umem);

		if (!process_packet(xsk, addr, len))
			mem_free_umem_frame(&xsk->umem->mem, addr);

		xsk->stats.rx_bytes += len;
	}
	xsk->stats.rx_packets += rcvd;

	restock_receive_fill_queue(xsk);
	xsk_ring_cons__release(&xsk->rx, rcvd);

	/* Do we need to wake up the kernel for transmission */
	complete_tx(xsk);

	if (verbose && rcvd > 1)
		printf("%s(): RX batch %d packets (i:%d)\n", __func__, rcvd, i);
  }

static void rx_and_process(struct config *cfg,
			   struct xsk_container *xsks)
{
	struct pollfd fds[MAX_AF_SOCKS] = { 0 };
	int ret, n_fds, i;
	// struct xsk_socket_info *xsk_socket = xsks->sockets[0]; // FIXME

	n_fds = xsks->num;

	for (i = 0; i < n_fds; i++) {
		struct xsk_socket_info *xsk_info = xsks->sockets[i];

		fds[i].fd = xsk_socket__fd(xsk_info->xsk);
		fds[i].events = POLLIN;
	}

	while(!global_exit) {
		if (cfg->xsk_wakeup_mode) {
			/* poll will wait for events on file descriptors */
			ret = poll(fds, n_fds, -1);
			if (ret <= 0 || ret > 1)
				continue;
		}

		for (i = 0; i < n_fds; i++) {
			struct xsk_socket_info *xsk_info = xsks->sockets[i];

			//printf("XXX i[%d] queue:%d xsk_info:%p \n",
			//	i, xsk_info->queue_id, xsk_info);

			tx_pkt(cfg, xsk_info);
			handle_receive_packets(xsk_info);
		}
	}
}

/* Use-case: Accurate cyclic Tx and lazy RX-processing
 *
 * This processing loop is simulating a Time-Triggered schedule, where
 * transmitting packets within a small time-window is the most
 * important task.  Picking up frames in RX-queue is less time
 * critical, as the PCF synchronization packets will have been
 * timestamped (rx_ktime) by XDP before they got enqueued.
 */
static void tx_and_rx_batch_process(struct config *cfg,
				    struct xsk_container *xsks)
{


}

static void tx_pkt(struct config *cfg,
		   struct xsk_socket_info *xsk)
{
	struct xsk_umem_info *umem = xsk->umem;
	uint64_t pkt_addr = mem_alloc_umem_frame(&umem->mem);
	uint8_t *pkt = NULL;
	uint32_t offset = 0; // 256;

	pkt_addr += offset;
	pr_addr_info(__func__, pkt_addr, umem);

	pkt = xsk_umem__get_data(umem->buffer, pkt_addr);
	gen_base_pkt(pkt);

	{
		uint32_t tx_idx = 0;
		int ret;

		ret = xsk_ring_prod__reserve(&xsk->tx, 1, &tx_idx);
		if (ret != 1) {
			/* No more transmit slots, drop the packet */
			mem_free_umem_frame(&umem->mem, pkt_addr);
		}

		xsk_ring_prod__tx_desc(&xsk->tx, tx_idx)->addr = pkt_addr;
		xsk_ring_prod__tx_desc(&xsk->tx, tx_idx)->len = 64;
		xsk_ring_prod__submit(&xsk->tx, 1);
		xsk->outstanding_tx++;
	}
	//complete_tx(xsk);
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
	struct xsk_container *xsks = arg;
	struct xsk_socket_info *xsk = xsks->sockets[0]; // FIXME
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

static void enter_xsks_into_map(int xsks_map, struct xsk_container *xsks)
{
	int i;

	if (xsks_map < 0) {
		fprintf(stderr, "ERROR: no xsks map found: %s\n",
			strerror(xsks_map));
		exit(EXIT_FAILURE);
	}

	for (i = 0; i < xsks->num; i++) {
		int fd = xsk_socket__fd(xsks->sockets[i]->xsk);
		int key, ret;

		key = i;
		/* When entering XSK socket into map redirect have effect */
		ret = bpf_map_update_elem(xsks_map, &key, &fd, 0);
		if (ret) {
			fprintf(stderr, "ERROR: bpf_map_update_elem %d\n", i);
			exit(EXIT_FAILURE);
		}
		if (debug)
			printf("%s() enable redir for xsks_map_fd:%d Key:%d fd:%d\n",
			       __func__, xsks_map, key, fd);

	}
}

static void exit_application(int signal)
{
	signal = signal;
	global_exit = true;
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
		.progsec = "xdp_sock",
		.xsk_wakeup_mode = true, /* Default, change via --spin */
		.xsk_if_queue = -1,
	};
	pthread_t stats_poll_thread;
	struct xsk_umem_info *umem;
	struct xsk_container xsks;
	int queues_max, queues_set;
	int total_nr_frames, nr_frames;
	struct sched_param schedp;
	int i;

	/* Default to AF_XDP copy mode.
	 *
	 * It seems counter intuitive to not-use Zero-Copy mode, but there is an
	 * explaination.  Our application don't consume EVERY packet, e.g
	 * letting netstack handle ARP/NDP packets via returning XDP_PASS in
	 * bpf-prog.
	 *
	 * XDP_PASS in Zero-Copy mode results in the kernel allocating a new
	 * memory page (and SKB) and copying over packet contents, before giving
	 * packet to netstack.
	 *
	 * For our Real-Time use-case, we want to avoid allocations more than
	 * cost of copying over packet data to our preallocated AF_XDP umem
	 * area.
	 */
	cfg.xsk_bind_flags = XDP_COPY;

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

	queues_max = ethtool_get_max_channels(cfg.ifname);
	queues_set = ethtool_get_channels(cfg.ifname);
	if (verbose || debug_meta)
		printf("Interface: %s - queues max:%d set:%d\n",
		       cfg.ifname, queues_max, queues_set);
	xsks.num = queues_set;

	/* Allocate frames according to how many queues are handled */
	nr_frames = NUM_FRAMES;
	total_nr_frames = nr_frames * xsks.num;
	if (verbose || debug_meta)
		printf("For XSK queues:%d alloc total:%d frames (per-q:%d)\n",
		       xsks.num, total_nr_frames, nr_frames);

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

	/* Allocate memory for total_nr_frames of the default XDP frame size */
	packet_buffer_size = total_nr_frames * FRAME_SIZE;
	if (posix_memalign(&packet_buffer,
			   getpagesize(), /* PAGE_SIZE aligned */
			   packet_buffer_size)) {
		fprintf(stderr, "ERROR: Can't allocate buffer memory \"%s\"\n",
			strerror(errno));
		exit(EXIT_FAILURE);
	}

	/* Initialize shared packet_buffer for umem usage */
	umem = configure_xsk_umem(packet_buffer, packet_buffer_size,
				  FRAME_SIZE, total_nr_frames);
	if (umem == NULL) {
		fprintf(stderr, "ERROR: Can't create umem \"%s\"\n",
			strerror(errno));
		exit(EXIT_FAILURE);
	}

	/* Generate packets to TX */
	gen_base_pkt((uint8_t*)&base_pkt_data);

	/* Open and configure the AF_XDP (xsk) socket(s) */
	for (i = 0; i < xsks.num; i++) {
		struct xsk_socket_info *xski;

		xski = xsk_configure_socket(&cfg, umem, i, xsks_map_fd);
		if (xski == NULL) {
			fprintf(stderr, "ERROR(%d): Can't setup AF_XDP socket "
				"\"%s\"\n", errno, strerror(errno));
			exit(EXIT_FAILURE);
		}
		xsks.sockets[i] = xski;

		if (xsk_populate_fill_ring(&xski->fq, umem, nr_frames / 2)) {
			fprintf(stderr, "ERROR: Can't populate fill ring\n");
			exit(EXIT_FAILURE);
		}
	}
	enter_xsks_into_map(xsks_map_fd, &xsks);

	/* Start thread to do statistics display */
	if (0 && verbose) { // FIXME disabled as currently broken
		ret = pthread_create(&stats_poll_thread, NULL,
				     stats_poll, &xsks);
		if (ret) {
			fprintf(stderr, "ERROR: Failed creating statistics thread "
				"\"%s\"\n", strerror(errno));
			exit(EXIT_FAILURE);
		}
	}

	if (cfg.sched_prio) {
		/* Setup sched priority: Have impact on wakeup accuracy */
		memset(&schedp, 0, sizeof(schedp));
		schedp.sched_priority = cfg.sched_prio;
		err = sched_setscheduler(0, cfg.sched_policy, &schedp);
		if (err) {
			fprintf(stderr, "ERROR(%d): failed to set priority(%d): %s\n",
				errno, cfg.sched_prio, strerror(errno));
			if (errno != EPERM)
				return EXIT_FAILURE;
		}
		if (debug)
			printf("Setup RT prio %d - policy SCHED_FIFO(%d)\n ",
			       cfg.sched_prio, cfg.sched_policy);
	}

	//sleep(3);
	// tx_pkt(&cfg, xsks.sockets[0]);

	/* Receive and count packets than drop them */
	rx_and_process(&cfg, &xsks);

	/* Cleanup */
	for (i = 0; i < xsks.num; i++)
		xsk_socket__delete(xsks.sockets[i]->xsk);
	xsk_umem__delete(umem->umem);
	xdp_link_detach(cfg.ifindex, cfg.xdp_flags, 0);

	return EXIT_OK;
}
