#include <errno.h>
#include <getopt.h>
#include <libgen.h>
#include <linux/bpf.h>
#include <linux/err.h>
#include <linux/if_link.h>
#include <linux/if_xdp.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/limits.h>
#include <linux/udp.h>
#include <arpa/inet.h>
#include <locale.h>
#include <net/ethernet.h>
#include <netinet/ether.h>
#include <net/if.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/capability.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>
#include <sched.h>
#include <assert.h>
#include <fcntl.h>
#include <unistd.h>

#include <sys/epoll.h>

#include <xdp/xsk.h>
#include <xdp/libxdp.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "mxsk.h"

#define exit_with_error(error) __exit_with_error(error, __FILE__, __func__, __LINE__)

/* helper structures */
struct xsk_umem_info {
	struct xsk_ring_prod fq;
	struct xsk_ring_cons cq;
	struct xsk_umem *umem;
	void *buffer;
};
typedef __u64 u64;
typedef __u32 u32;
typedef __u16 u16;
typedef __u8  u8;

struct xsk_ring_stats {
	unsigned long rx_npkts;
	unsigned long tx_npkts;
	unsigned long rx_dropped_npkts;
	unsigned long rx_invalid_npkts;
	unsigned long tx_invalid_npkts;
	unsigned long rx_full_npkts;
	unsigned long rx_fill_empty_npkts;
	unsigned long tx_empty_npkts;
	unsigned long prev_rx_npkts;
	unsigned long prev_tx_npkts;
	unsigned long prev_rx_dropped_npkts;
	unsigned long prev_rx_invalid_npkts;
	unsigned long prev_tx_invalid_npkts;
	unsigned long prev_rx_full_npkts;
	unsigned long prev_rx_fill_empty_npkts;
	unsigned long prev_tx_empty_npkts;
};

int tbl[1024];

struct xsk_socket_info {
    unsigned int xsk_id;
    int master_fd;
	struct xsk_ring_cons rx;
	struct xsk_ring_prod tx;
	struct xsk_umem_info *umem;
	struct xsk_socket *xsk;
	u32 outstanding_tx;

    struct xsk_ring_stats ring_stats;
};

struct xdp_program * xdp_prog;

volatile bool done = false;

int uds_fds[MAX_SOCKS][2];

/* master management */
pthread_spinlock_t spinlock;

static void remove_xdp_program(void)
{
	int err;

	err = xdp_program__detach(xdp_prog, if_nametoindex(IF_NAME), XDP_MODE_NATIVE, 0);
	if (err)
		fprintf(stderr, "Could not detach XDP program. Error: %s\n", strerror(-err));
}

static void load_xdp_program(void)
{
	char errmsg[STRERR_BUFSIZE];
	int err;

	xdp_prog = xdp_program__open_file("mxsk_kern.o", NULL, NULL);
	err = libxdp_get_error(xdp_prog);
	if (err) {
		libxdp_strerror(err, errmsg, sizeof(errmsg));
		fprintf(stderr, "ERROR: program loading failed: %s\n", errmsg);
		exit(EXIT_FAILURE);
	}

	err = xdp_program__attach(xdp_prog, if_nametoindex(IF_NAME), XDP_MODE_NATIVE, 0);
	if (err) {
		libxdp_strerror(err, errmsg, sizeof(errmsg));
		fprintf(stderr, "ERROR: attaching program failed: %s\n", errmsg);
		exit(EXIT_FAILURE);
	}
}

static void __exit_with_error(int error, const char *file, const char *func,
			      int line)
{
	fprintf(stderr, "%s:%s:%i: errno: %d/\"%s\"\n", file, func,
		line, error, strerror(error));

	if (MAX_SOCKS > 1)
		remove_xdp_program();
	exit(EXIT_FAILURE);
}

static void enable_bp(struct xsk_socket_info *xsk)
{
	int sock_opt;

	sock_opt = 1;
	if (setsockopt(xsk_socket__fd(xsk->xsk), SOL_SOCKET, SO_PREFER_BUSY_POLL,
		       (void *)&sock_opt, sizeof(sock_opt)) < 0)
		exit_with_error(errno);

	sock_opt = 20;
	if (setsockopt(xsk_socket__fd(xsk->xsk), SOL_SOCKET, SO_BUSY_POLL,
		       (void *)&sock_opt, sizeof(sock_opt)) < 0)
		exit_with_error(errno);

	sock_opt = BATCH_SIZE;
	if (setsockopt(xsk_socket__fd(xsk->xsk), SOL_SOCKET, SO_BUSY_POLL_BUDGET,
		       (void *)&sock_opt, sizeof(sock_opt)) < 0)
		exit_with_error(errno);

    char path[PATH_MAX];
    snprintf(path, PATH_MAX, "/sys/class/net/%s/napi_defer_hard_irqs", IF_NAME);
    FILE *fp = fopen(path, "w");
    if(!fp)
    {
        printf("fopen failed\n");
        exit_with_error(errno);
    }
    fprintf(fp, "%d", 20000);
    fclose(fp);
    
    snprintf(path, PATH_MAX, "/sys/class/net/%s/gro_flush_timeout", IF_NAME);
    fp = fopen(path, "w");
    if(!fp)
    {
        printf("fopen failed\n");
        exit_with_error(errno);
    }
    fprintf(fp, "%d", 10);
    fclose(fp);

}

static struct xsk_umem_info * xsk_configure_umem(void * buffer, u64 size)
{
    struct xsk_umem_info *umem;
    int ret;
    struct xsk_umem_config cfg = {
        .fill_size = XSK_RING_PROD__DEFAULT_NUM_DESCS * 2,
        .comp_size = XSK_RING_CONS__DEFAULT_NUM_DESCS,
        .frame_size = FRAME_SIZE,
        .frame_headroom = XSK_UMEM__DEFAULT_FRAME_HEADROOM,
        .flags = 0,
    };
    umem = calloc(1, sizeof(struct xsk_umem_info));
    if(!umem)
    {
        printf("calloc failed\n");
        exit_with_error(errno);
    }

    ret = xsk_umem__create(&umem->umem, buffer, size, &umem->fq, &umem->cq, &cfg);
    
    if(ret)
    {
        printf("xsk_umem__create failed\n");
        exit_with_error(-ret);
    }

    umem->buffer = buffer;
    return umem;
}   

static struct xsk_socket_info * xsk_configure_socket(struct xsk_umem_info * umem,
                                    bool rx, bool tx)
{
    struct xsk_socket_info * xsk;
    int ret;

    struct xsk_ring_cons * rx_ring;
    struct xsk_ring_prod * tx_ring;

    struct xsk_socket_config cfg = {
        .rx_size = XSK_RING_CONS__DEFAULT_NUM_DESCS,
        .tx_size = XSK_RING_PROD__DEFAULT_NUM_DESCS,
        .libbpf_flags = MAX_SOCKS > 1 ? XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD : 0,
        .xdp_flags = XDP_FLAGS_DRV_MODE | XDP_FLAGS_REPLACE,
        .bind_flags = XDP_USE_NEED_WAKEUP,
    };

    xsk = calloc(1, sizeof(struct xsk_socket_info));

    xsk->umem = umem;

    if(!xsk)
    {
        printf("calloc failed\n");
        exit_with_error(errno);
    }
    
    rx_ring = rx ? &xsk->rx : NULL;
    tx_ring = tx ? &xsk->tx : NULL;

    ret = xsk_socket__create(&xsk->xsk, IF_NAME, QUEUE_ID, umem->umem, rx_ring, tx_ring, &cfg);

    if(ret)
    {
        printf("xsk_socket__create failed\n");
        exit_with_error(-ret);
    }

    return xsk;

}

static void xsk_populate_fill_ring(struct xsk_umem_info *umem)
{
    int ret;
    unsigned int prod_idx;
    int nb = XSK_RING_PROD__DEFAULT_NUM_DESCS * 2;

    pthread_spin_lock(&spinlock);
    /* I want to produce some elements, reserve them for me */
    ret = xsk_ring_prod__reserve(&umem->fq, 
            nb, &prod_idx);

    if(ret != nb)
    {
        pthread_spin_unlock(&spinlock);
        printf("xsk_ring_prod__reserve failed\n");
        exit_with_error(-ret);
    }
    /* produce from prod_idx */
    for(int i=0;i<nb;i++)
    {
        *xsk_ring_prod__fill_addr(&umem->fq, prod_idx++) = i * FRAME_SIZE;
    }
    /* submit results of production */
    xsk_ring_prod__submit(&umem->fq, nb);
    pthread_spin_unlock(&spinlock);
}

static void xsk_cleanup(struct xsk_socket_info **xsks, void *buffer)
{
    struct xsk_umem * umem = xsks[0]->umem->umem;

    for(int i=0;i<MAX_SOCKS;i++)
        xsk_socket__delete(xsks[i]->xsk);
    (void)xsk_umem__delete(umem);

    if(MAX_SOCKS > 1)
        remove_xdp_program();
    
    munmap(buffer, NUM_FRAMES * FRAME_SIZE);

    if(opt_busy_poll)
    {
        char path[PATH_MAX];
        snprintf(path, PATH_MAX, "/sys/class/net/%s/napi_defer_hard_irqs", IF_NAME);
        FILE *fp = fopen(path, "w");
        if(!fp)
        {
            printf("fopen failed\n");
            exit_with_error(errno);
        }
        fprintf(fp, "%d", 0);
        fclose(fp);
        
        snprintf(path, PATH_MAX, "/sys/class/net/%s/gro_flush_timeout", IF_NAME);
        fp = fopen(path, "w");
        if(!fp)
        {
            printf("fopen failed\n");
            exit_with_error(errno);
        }
        fprintf(fp, "%d", 0);
        fclose(fp);
    }

}

static int lookup_bpf_map(int prog_fd)
{
	__u32 i, *map_ids, num_maps, prog_len = sizeof(struct bpf_prog_info);
	__u32 map_len = sizeof(struct bpf_map_info);
	struct bpf_prog_info prog_info = {};
	int fd, err, xsks_map_fd = -ENOENT;
	struct bpf_map_info map_info;

	err = bpf_obj_get_info_by_fd(prog_fd, &prog_info, &prog_len);
	if (err)
		return err;

	num_maps = prog_info.nr_map_ids;

	map_ids = calloc(prog_info.nr_map_ids, sizeof(*map_ids));
	if (!map_ids)
		return -ENOMEM;

	memset(&prog_info, 0, prog_len);
	prog_info.nr_map_ids = num_maps;
	prog_info.map_ids = (__u64)(unsigned long)map_ids;

	err = bpf_obj_get_info_by_fd(prog_fd, &prog_info, &prog_len);
	if (err) {
		free(map_ids);
		return err;
	}

	for (i = 0; i < prog_info.nr_map_ids; i++) {
		fd = bpf_map_get_fd_by_id(map_ids[i]);
		if (fd < 0)
			continue;

		memset(&map_info, 0, map_len);
		err = bpf_obj_get_info_by_fd(fd, &map_info, &map_len);
		if (err) {
			close(fd);
			continue;
		}

		if (!strncmp(map_info.name, "xsks_map", sizeof(map_info.name)) &&
		    map_info.key_size == 4 && map_info.value_size == 4) {
			xsks_map_fd = fd;
			break;
		}

		close(fd);
	}

	free(map_ids);
	return xsks_map_fd;
}


static void enter_xsks_into_map(struct xsk_socket_info **xsks)
{
	int i, xsks_map;

	xsks_map = lookup_bpf_map(xdp_program__fd(xdp_prog));
	if (xsks_map < 0) {
		fprintf(stderr, "ERROR: no xsks map found: %s\n",
			strerror(xsks_map));
			exit(EXIT_FAILURE);
	}

	for (i = 0; i < MAX_SOCKS; i++) {
		int fd = xsk_socket__fd(xsks[i]->xsk);
		int key, ret;

		key = i;
		ret = bpf_map_update_elem(xsks_map, &key, &fd, 0);
		if (ret) {
			fprintf(stderr, "ERROR: bpf_map_update_elem %d\n", i);
			exit(EXIT_FAILURE);
		}
	}
}

void (* dp_loop)(struct xsk_socket_info ** xsks);

void* _rx_drop(void *data)
{
    unsigned int cons_idx;
    unsigned int nr;
    int ret;
    u64 origs[BATCH_SIZE];

    struct xsk_socket_info * xsk = (struct xsk_socket_info *)data;

    struct pollfd fds[1] = {0};
    fds[0].fd = xsk_socket__fd(xsk->xsk);
    fds[0].events = POLLIN;
    printf("worker#%d thread started\n", xsk->xsk_id);
    while(!done)
    {
        if(opt_use_poll)
        {
            ret = poll(fds, 1, opt_timeout);
            if(ret <= 0 || !(fds[0].revents & POLLIN))
            {
                if(ret == -1 && errno == EINTR)
                    done = true;
                continue;
            }
        }
        /* try to receive BATCH_SIZE packets from rx_ring */
        nr = xsk_ring_cons__peek(&xsk->rx, BATCH_SIZE, &cons_idx);
        if(!nr)
            continue;

        for(int i=0;i<nr;i++)
        {
            u64 addr = xsk_ring_cons__rx_desc(&xsk->rx, cons_idx)->addr;
            u32 len = xsk_ring_cons__rx_desc(&xsk->rx, cons_idx)->len;

            // move to next slot
            cons_idx++;

            origs[i] = xsk_umem__extract_addr(addr);

            addr = xsk_umem__add_offset_to_addr(addr);

            char *pkt = xsk_umem__get_data(xsk->umem->buffer, addr);

            (void)pkt;
            (void)len;

        }
        xsk_ring_cons__release(&xsk->rx, nr);

        int write_size = nr * sizeof(uint64_t);        
        ret = write(uds_fds[xsk->xsk_id][0], origs, write_size);
        while(ret < write_size)
        {
            ret += write(uds_fds[xsk->xsk_id][0], origs + ret, write_size - ret);
        }
        
        xsk->ring_stats.rx_npkts += nr;

    }
    printf("worker %u exit\n", xsk->xsk_id);
    return NULL;
}

void set_nonblock(int fd)
{
    int opts = fcntl(fd, F_GETFL);
    if(opts < 0)
    {
        printf("fcntl failed\n");
        exit_with_error(errno);
    }
    opts |= O_NONBLOCK;
    if(fcntl(fd, F_SETFL, opts) < 0)
    {
        printf("fcntl failed\n");
        exit_with_error(errno);
    }
}

void rx_drop(struct xsk_socket_info ** xsks)
{
    pthread_t workers[MAX_SOCKS];
    int ret;
    int nr;
    u64 addrs[MAX_SOCKS*BATCH_SIZE];
    
    struct epoll_event ev, evs[MAX_SOCKS];
    int epfd = epoll_create(256);
    for(int i=0;i<MAX_SOCKS;i++)
    {
        set_nonblock(uds_fds[i][1]);
        ev.data.fd = uds_fds[i][1];
        ev.events = EPOLLIN;
        epoll_ctl(epfd, EPOLL_CTL_ADD, uds_fds[i][1], &ev);
    }

    for(int i=0;i<MAX_SOCKS;i++)
    {
        ret = pthread_create(&workers[i], NULL, _rx_drop, xsks[i]);
        if(ret)
        {
            printf("pthread_create failed\n");
            exit_with_error(ret);
        }
    }
   
    /* master loop */
    while(!done)
    {
        int nfds = epoll_wait(epfd, evs, MAX_SOCKS, opt_timeout);
        if(!nfds)
        {
            if(opt_busy_poll || xsk_ring_prod__needs_wakeup(&xsks[0]->umem->fq)) {
                recvfrom(xsk_socket__fd(xsks[0]->xsk), NULL, 0, MSG_DONTWAIT, NULL, NULL);
            }
            continue;
        }
        for(int i=0;i<nfds;i++)
        {
            if(evs[i].events & EPOLLIN)
            {
                int fd = evs[i].data.fd;
                nr = read(fd, addrs, sizeof(uint64_t) * MAX_SOCKS * BATCH_SIZE);
                nr/= sizeof(uint64_t);

                int xsk_id = tbl[fd];

                // reserver nr packets in fill ring for future receiving
                unsigned int prod_idx;
                ret = xsk_ring_prod__reserve(&xsks[xsk_id]->umem->fq, nr, &prod_idx);
                while(ret < nr)
                {
                    ret = xsk_ring_prod__reserve(&xsks[xsk_id]->umem->fq, nr, &prod_idx);
                }

                for(int j=0;j<nr;j++)
                {
                    *xsk_ring_prod__fill_addr(&xsks[xsk_id]->umem->fq, prod_idx++) = addrs[j];
                }
                xsk_ring_prod__submit(&xsks[xsk_id]->umem->fq, nr);
            }
        }
    }

    for(int i=0;i<MAX_SOCKS;i++)
        pthread_join(workers[i], NULL);
}

#define ETH_FCS_SIZE 4

#define ETH_HDR_SIZE sizeof(struct ethhdr)
#define PKTGEN_HDR_SIZE sizeof(struct pktgen_hdr)
#define PKT_HDR_SIZE (ETH_HDR_SIZE + sizeof(struct iphdr) + \
		      sizeof(struct udphdr) + PKTGEN_HDR_SIZE)
#define PKTGEN_HDR_OFFSET (ETH_HDR_SIZE + sizeof(struct iphdr) + \
			   sizeof(struct udphdr))
#define PKTGEN_SIZE_MIN (PKTGEN_HDR_OFFSET + sizeof(struct pktgen_hdr) + \
			 ETH_FCS_SIZE)

#define PKT_SIZE		(opt_pkt_size - ETH_FCS_SIZE)
#define IP_PKT_SIZE		(PKT_SIZE - ETH_HDR_SIZE)
#define UDP_PKT_SIZE		(IP_PKT_SIZE - sizeof(struct iphdr))
#define UDP_PKT_DATA_SIZE	(UDP_PKT_SIZE - \
				 (sizeof(struct udphdr) + PKTGEN_HDR_SIZE))

static void *memset32_htonl(void *dest, u32 val, u32 size)
{
	u32 *ptr = (u32 *)dest;
	int i;

	val = htonl(val);

	for (i = 0; i < (size & (~0x3)); i += 4)
		ptr[i >> 2] = val;

	for (; i < size; i++)
		((char *)dest)[i] = ((char *)&val)[i & 3];

	return dest;
}

/*
 * This function code has been taken from
 * Linux kernel lib/checksum.c
 */
static inline unsigned short from32to16(unsigned int x)
{
	/* add up 16-bit and 16-bit for 16+c bit */
	x = (x & 0xffff) + (x >> 16);
	/* add up carry.. */
	x = (x & 0xffff) + (x >> 16);
	return x;
}

/*
 * This function code has been taken from
 * Linux kernel lib/checksum.c
 */
static unsigned int do_csum(const unsigned char *buff, int len)
{
	unsigned int result = 0;
	int odd;

	if (len <= 0)
		goto out;
	odd = 1 & (unsigned long)buff;
	if (odd) {
#ifdef __LITTLE_ENDIAN
		result += (*buff << 8);
#else
		result = *buff;
#endif
		len--;
		buff++;
	}
	if (len >= 2) {
		if (2 & (unsigned long)buff) {
			result += *(unsigned short *)buff;
			len -= 2;
			buff += 2;
		}
		if (len >= 4) {
			const unsigned char *end = buff +
						   ((unsigned int)len & ~3);
			unsigned int carry = 0;

			do {
				unsigned int w = *(unsigned int *)buff;

				buff += 4;
				result += carry;
				result += w;
				carry = (w > result);
			} while (buff < end);
			result += carry;
			result = (result & 0xffff) + (result >> 16);
		}
		if (len & 2) {
			result += *(unsigned short *)buff;
			buff += 2;
		}
	}
	if (len & 1)
#ifdef __LITTLE_ENDIAN
		result += *buff;
#else
		result += (*buff << 8);
#endif
	result = from32to16(result);
	if (odd)
		result = ((result >> 8) & 0xff) | ((result & 0xff) << 8);
out:
	return result;
}

/*
 *	This is a version of ip_compute_csum() optimized for IP headers,
 *	which always checksum on 4 octet boundaries.
 *	This function code has been taken from
 *	Linux kernel lib/checksum.c
 */
static inline __sum16 ip_fast_csum(const void *iph, unsigned int ihl)
{
	return (__sum16)~do_csum(iph, ihl * 4);
}

/*
 * Fold a partial checksum
 * This function code has been taken from
 * Linux kernel include/asm-generic/checksum.h
 */
static inline __sum16 csum_fold(__wsum csum)
{
	u32 sum = (u32)csum;

	sum = (sum & 0xffff) + (sum >> 16);
	sum = (sum & 0xffff) + (sum >> 16);
	return (__sum16)~sum;
}

/*
 * This function code has been taken from
 * Linux kernel lib/checksum.c
 */
static inline u32 from64to32(u64 x)
{
	/* add up 32-bit and 32-bit for 32+c bit */
	x = (x & 0xffffffff) + (x >> 32);
	/* add up carry.. */
	x = (x & 0xffffffff) + (x >> 32);
	return (u32)x;
}

__wsum csum_tcpudp_nofold(__be32 saddr, __be32 daddr,
			  __u32 len, __u8 proto, __wsum sum);

/*
 * This function code has been taken from
 * Linux kernel lib/checksum.c
 */
__wsum csum_tcpudp_nofold(__be32 saddr, __be32 daddr,
			  __u32 len, __u8 proto, __wsum sum)
{
	unsigned long long s = (u32)sum;

	s += (u32)saddr;
	s += (u32)daddr;
#ifdef __BIG_ENDIAN__
	s += proto + len;
#else
	s += (proto + len) << 8;
#endif
	return (__wsum)from64to32(s);
}

/*
 * This function has been taken from
 * Linux kernel include/asm-generic/checksum.h
 */
static inline __sum16
csum_tcpudp_magic(__be32 saddr, __be32 daddr, __u32 len,
		  __u8 proto, __wsum sum)
{
	return csum_fold(csum_tcpudp_nofold(saddr, daddr, len, proto, sum));
}

static inline u16 udp_csum(u32 saddr, u32 daddr, u32 len,
			   u8 proto, u16 *udp_pkt)
{
	u32 csum = 0;
	u32 cnt = 0;

	/* udp hdr and data */
	for (; cnt < len; cnt += 2)
		csum += udp_pkt[cnt >> 1];

	return csum_tcpudp_magic(saddr, daddr, len, proto, csum);
}

static u8 pkt_template[XSK_UMEM__DEFAULT_FRAME_SIZE];

struct pktgen_hdr {
	__be32 pgh_magic;
	__be32 seq_num;
	__be32 tv_sec;
	__be32 tv_usec;
};

static struct ether_addr opt_txdmac = {{ 0xb8, 0xce, 0xf6,
					 0x0a, 0x10, 0xdc }};
static struct ether_addr opt_txsmac = {{ 0xb8, 0xce, 0xf6,
					 0x0a, 0x3d, 0x78 }};

uint32_t opt_pkt_fill_pattern = 0x12345678;

static void gen_eth_hdr_data(void)
{
	struct pktgen_hdr *pktgen_hdr;
	struct udphdr *udp_hdr;
	struct iphdr *ip_hdr;

    struct ethhdr *eth_hdr = (struct ethhdr *)pkt_template;

    udp_hdr = (struct udphdr *)(pkt_template +
                    sizeof(struct ethhdr) +
                    sizeof(struct iphdr));
    ip_hdr = (struct iphdr *)(pkt_template +
                    sizeof(struct ethhdr));
    pktgen_hdr = (struct pktgen_hdr *)(pkt_template +
                        sizeof(struct ethhdr) +
                        sizeof(struct iphdr) +
                        sizeof(struct udphdr));
    /* ethernet header */
    memcpy(eth_hdr->h_dest, &opt_txdmac, ETH_ALEN);
    memcpy(eth_hdr->h_source, &opt_txsmac, ETH_ALEN);
    eth_hdr->h_proto = htons(ETH_P_IP);

	/* IP header */
	ip_hdr->version = IPVERSION;
	ip_hdr->ihl = 0x5; /* 20 byte header */
	ip_hdr->tos = 0x0;
	ip_hdr->tot_len = htons(IP_PKT_SIZE);
	ip_hdr->id = 0;
	ip_hdr->frag_off = 0;
	ip_hdr->ttl = IPDEFTTL;
	ip_hdr->protocol = IPPROTO_UDP;
	ip_hdr->saddr = htonl(0x0a0a0a10);
	ip_hdr->daddr = htonl(0x0a0a0a20);

	/* IP header checksum */
	ip_hdr->check = 0;
	ip_hdr->check = ip_fast_csum((const void *)ip_hdr, ip_hdr->ihl);

	/* UDP header */
	udp_hdr->source = htons(0x1000);
	udp_hdr->dest = htons(0x1000);
	udp_hdr->len = htons(UDP_PKT_SIZE);

	/* UDP data */
	memset32_htonl(pkt_template + PKT_HDR_SIZE, opt_pkt_fill_pattern,
		       UDP_PKT_DATA_SIZE);

	/* UDP header checksum */
	udp_hdr->check = 0;
	udp_hdr->check = udp_csum(ip_hdr->saddr, ip_hdr->daddr, UDP_PKT_SIZE,
				  IPPROTO_UDP, (u16 *)udp_hdr);

    (void)pktgen_hdr;
}

static void gen_eth_frame(struct xsk_umem_info *umem, u64 addr)
{
	memcpy(xsk_umem__get_data(umem->buffer, addr), pkt_template,
	       PKT_SIZE);
}

static void kick_tx(struct xsk_socket_info *xsk)
{
	int ret;

	ret = sendto(xsk_socket__fd(xsk->xsk), NULL, 0, MSG_DONTWAIT, NULL, 0);
	if (ret >= 0 || errno == ENOBUFS || errno == EAGAIN ||
	    errno == EBUSY || errno == ENETDOWN)
		return;
	exit_with_error(errno);
}

void complete_tx_only(struct xsk_socket_info *xsk)
{
    unsigned int cons_idx = 0;
    if(!xsk->outstanding_tx)
        return;
    
    if(xsk_ring_prod__needs_wakeup(&xsk->tx))
        kick_tx(xsk);

    int nr = xsk_ring_cons__peek(&xsk->umem->cq, BATCH_SIZE, &cons_idx);
    if(nr)
    {
        xsk_ring_cons__release(&xsk->umem->cq, nr);
        xsk->outstanding_tx -= nr;
    }
}

void * _tx_only(void * data)
{
    struct xsk_socket_info *xsk = (struct xsk_socket_info *)data;
    int ret;
    unsigned int prod_idx = 0;
    u32 frame_nb = 0;
    while(!done)
    {
        ret = xsk_ring_prod__reserve(&xsk->tx, BATCH_SIZE, &prod_idx);
        while(ret < BATCH_SIZE && !done)
        {
            complete_tx_only(xsk);
            ret = xsk_ring_prod__reserve(&xsk->tx, BATCH_SIZE, &prod_idx);
        }
        for(int i=0;i<BATCH_SIZE;i++)
        {
            struct xdp_desc * tx_desc = xsk_ring_prod__tx_desc(&xsk->tx,
                prod_idx + i);
            tx_desc->addr = (frame_nb + i) * FRAME_SIZE;
            tx_desc->len = PKT_SIZE;
        }
        xsk_ring_prod__submit(&xsk->tx, BATCH_SIZE);
        xsk->ring_stats.tx_npkts += BATCH_SIZE;
        xsk->outstanding_tx += BATCH_SIZE;
        frame_nb = (frame_nb + BATCH_SIZE) % NUM_FRAMES;

        complete_tx_only(xsk);
    }
    return NULL;
}

void tx_only(struct xsk_socket_info ** xsks)
{
    pthread_t workers[MAX_SOCKS];
    int ret;
    for(int i=0;i<MAX_SOCKS;i++)
    {
        ret = pthread_create(&workers[i], NULL, _tx_only, xsks[i]);
        if(ret)
        {
            printf("pthread_create failed\n");
            exit_with_error(ret);
        }
    }
    for(int i=0;i<MAX_SOCKS;i++)
        pthread_join(workers[i], NULL);
}

static void int_exit(int sig)
{
	done = true;
}

static unsigned long get_nsecs(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec * 1000000000UL + ts.tv_nsec;
}

unsigned long prev_time;

void dump_stats(struct xsk_socket_info ** xsks)
{
    unsigned long now = get_nsecs();
	long dt = now - prev_time;
	int i;

	prev_time = now;

    int total_rx_pps = 0;
    int total_tx_pps = 0;
    char *fmt = "%-18s %'-14.0f %'-14lu\n";

	for (i = 0; i < MAX_SOCKS && xsks[i]; i++) {
		
		double rx_pps, tx_pps;

		rx_pps = (xsks[i]->ring_stats.rx_npkts - xsks[i]->ring_stats.prev_rx_npkts) *
			 1000000000. / dt;
		tx_pps = (xsks[i]->ring_stats.tx_npkts - xsks[i]->ring_stats.prev_tx_npkts) *
			 1000000000. / dt;

		printf("\n sock%d@", i);
		printf("\n");

		printf("%-18s %-14s %-14s %-14.2f\n", "", "pps", "pkts",
		       dt / 1000000000.);
		printf(fmt, "rx", rx_pps, xsks[i]->ring_stats.rx_npkts);
		printf(fmt, "tx", tx_pps, xsks[i]->ring_stats.tx_npkts);

        total_rx_pps += rx_pps;
        total_tx_pps += tx_pps;

		xsks[i]->ring_stats.prev_rx_npkts = xsks[i]->ring_stats.rx_npkts;
		xsks[i]->ring_stats.prev_tx_npkts = xsks[i]->ring_stats.tx_npkts;
	}
    printf("\n total@");
    printf("\n");
    printf("rx_pps = %d\n", total_rx_pps);
}

static void * dumper(void *data)
{
    struct xsk_socket_info ** xsks = (struct xsk_socket_info **)data;
    prev_time = get_nsecs();
    while(!done)
    {
        sleep(1);
        dump_stats(xsks);
    }
    return NULL;
}

int main()
{
    void *buffer;
    struct xsk_umem_info * umem;
    struct xsk_socket_info * xsks[MAX_SOCKS];
    int ret;

    signal(SIGINT, int_exit);
	signal(SIGTERM, int_exit);
	signal(SIGABRT, int_exit);

    /* 0. load customized xdp program */
    if(MAX_SOCKS > 1)
        load_xdp_program();

    /* 1. reserve memory for umem */
    buffer = mmap(NULL, NUM_FRAMES * FRAME_SIZE, PROT_READ | PROT_WRITE,
                MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE, -1, 0);
    if(buffer == MAP_FAILED)
    {
        printf("mmap failed\n");
        exit(EXIT_FAILURE);
    }

    /* 2. configure umem with a helper function */
    umem = xsk_configure_umem(buffer, NUM_FRAMES * FRAME_SIZE);

    /* 3. configure socket */
    for(int i=0;i<MAX_SOCKS;i++)
    {
        xsks[i] = xsk_configure_socket(umem, true, true);
        xsks[i]->xsk_id = i;
    }
    
    if(MAX_SOCKS > 1)
        enter_xsks_into_map(xsks);
    
    if(opt_busy_poll)
    {
        for(int i = 0;i<MAX_SOCKS;i++)
            enable_bp(xsks[i]);
    }

    /* 4. (Rx) populate fill ring */
    if(opt_mode == RX)
    {
        pthread_spin_init(&spinlock, PTHREAD_PROCESS_PRIVATE);
        xsk_populate_fill_ring(umem);
        dp_loop = rx_drop;
    }
    else    /* 4. (Tx) pre-generate packets */
    {
        gen_eth_hdr_data();
        for(int i=0;i<NUM_FRAMES;i++)
            gen_eth_frame(umem, i * FRAME_SIZE);
        dp_loop = tx_only;
    }

    /* dump */
    pthread_t dump_thread;
    ret = pthread_create(&dump_thread, NULL, dumper, xsks);
    if(ret)
        exit_with_error(ret);
    
    for(int i=0;i<MAX_SOCKS;i++)
    {
        if(socketpair(AF_UNIX, SOCK_DGRAM, 0, uds_fds[i]) == -1)
        {
            printf("socketpair failed\n");
            exit_with_error(errno);
        }
        xsks[i]->master_fd = uds_fds[i][1];  
        tbl[uds_fds[i][1]] = xsks[i]->xsk_id;
    }

    /* 5. datapath */
    dp_loop(xsks);

    /* 6. clean up */
    xsk_cleanup(xsks, buffer);

    for(int i=0;i<MAX_SOCKS;i++)
    {
        close(uds_fds[i][0]);
        close(uds_fds[i][1]);
    }

    pthread_join(dump_thread, NULL);

    printf("Done\n");

    return 0;
}