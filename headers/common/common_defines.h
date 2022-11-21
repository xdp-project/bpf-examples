#ifndef __COMMON_DEFINES_H
#define __COMMON_DEFINES_H

#include <net/if.h>
#include <linux/types.h>
#include <stdbool.h>
#include <netinet/ether.h> /* struct ether_addr */

struct config {
	__u32 xdp_flags;
	int ifindex;
	char *ifname;
	char ifname_buf[IF_NAMESIZE];
	int redirect_ifindex;
	char *redirect_ifname;
	char redirect_ifname_buf[IF_NAMESIZE];
	bool do_unload;
	bool reuse_maps;
	char pin_dir[512];
	char filename[512];
	char progsec[32];
	char src_mac[18];
	char dest_mac[18];
	__u16 xsk_bind_flags;
	int xsk_if_queue;
	bool xsk_wakeup_mode;
	/* Real-Time scheduler setting */
	int sched_prio;
	int sched_policy;
	bool opt_busy_poll;
	struct ether_addr opt_tx_smac;
	struct ether_addr opt_tx_dmac;
	__u64 interval;
	__u32 batch_pkts;
	__u32 opt_ip_src;
	__u32 opt_ip_dst;
};

#define BATCH_PKTS_MAX		64
#define BATCH_PKTS_DEFAULT	4

/* Defined in common_params.o */
extern int verbose;
extern int debug;
extern int debug_pkt;
extern int debug_meta;
extern int debug_time;

/* Exit return codes */
#define EXIT_OK 		 0 /* == EXIT_SUCCESS (stdlib.h) man exit(3) */
#define EXIT_FAIL		 1 /* == EXIT_FAILURE (stdlib.h) man exit(3) */
#define EXIT_FAIL_OPTION	 2
#define EXIT_FAIL_XDP		30
#define EXIT_FAIL_BPF		40

#endif /* __COMMON_DEFINES_H */
