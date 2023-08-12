#ifndef XSK_LAT_H
#define XSK_LAT_H

#define MAX_SOCKS 4
int opt_busy_poll = 0;
int opt_use_poll = 0;
int opt_timeout = 1000;
int opt_pkt_size = 64;

enum {
    RX,
    TX
};
int opt_mode = RX;

#ifndef SOL_XDP
#define SOL_XDP 283
#endif

#ifndef AF_XDP
#define AF_XDP 44
#endif

#ifndef PF_XDP
#define PF_XDP AF_XDP
#endif

#ifndef SO_PREFER_BUSY_POLL
#define SO_PREFER_BUSY_POLL     69
#endif

#ifndef SO_BUSY_POLL_BUDGET
#define SO_BUSY_POLL_BUDGET     70
#endif

#define NUM_FRAMES 4096
#define FRAME_SIZE XSK_UMEM__DEFAULT_FRAME_SIZE
#define BATCH_SIZE 64

#define IF_NAME "enp12s0f0"
#define QUEUE_ID 0

/* load xdp program */
#define STRERR_BUFSIZE 1024


#endif