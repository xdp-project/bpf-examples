/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <linux/bpf.h>
#include <linux/types.h>

#define XDP_PROG_SEC "xdp"

#define DHCP_SNAME_LEN 64
#define DHCP_FILE_LEN 128

#define DHO_DHCP_AGENT_OPTIONS 82
#define RAI_CIRCUIT_ID 1
#define RAI_REMOTE_ID 2
#define RAI_OPTION_LEN 2

#define DEST_PORT 67  /* UDP destination port for dhcp */
#define MAX_BYTES 280 /* Max bytes supported by xdp load/store apis */

/* structure for sub-options in option 82*/
struct sub_option {
	__u8 option_id;
	__u8 len;
	__u16 val;
};

/*structure for dhcp option 82 */
struct dhcp_option_82 {
	__u8 t;
	__u8 len;
	struct sub_option circuit_id;
	struct sub_option remote_id;
};

struct dhcp_packet {
	__u8 op; /* 0: Message opcode/type */
	__u8 htype; /* 1: Hardware addr type (net/if_types.h) */
	__u8 hlen; /* 2: Hardware addr length */
	__u8 hops; /* 3: Number of relay agent hops from client */
	__u32 xid; /* 4: Transaction ID */
	__u16 secs; /* 8: Seconds since client started looking */
	__u16 flags; /* 10: Flag bits */
	struct in_addr ciaddr; /* 12: Client IP address (if already in use) */
	struct in_addr yiaddr; /* 16: Client IP address */
	struct in_addr siaddr; /* 18: IP address of next server to talk to */
	struct in_addr giaddr; /* 20: DHCP relay agent IP address */
	unsigned char chaddr[16]; /* 24: Client hardware address */
	char sname[DHCP_SNAME_LEN]; /* 40: Server name */
	char file[DHCP_FILE_LEN]; /* 104: Boot filename */
	__u32 cookie; /* 232: Magic cookie */
	unsigned char options[0];
	/* 236: Optional parameters
              (actual length dependent on MTU). */
};
