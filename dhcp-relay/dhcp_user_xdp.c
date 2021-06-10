/* SPDX-License-Identifier: GPL-2.0 */
static const char *__doc__ = "DHCP relay program to add Option 82\n";

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include <net/if.h>
#include <linux/if_link.h> /* depend on kernel-headers installed */
#include <arpa/inet.h>

#define SERVER_MAP "dhcp_server"
#define XDP_OBJ "dhcp_kern_xdp.o"

static int xdp_link_detach(int ifindex, __u32 xdp_flags)
{
	int err;

	if ((err = bpf_set_link_xdp_fd(ifindex, -1, xdp_flags)) < 0) {
		fprintf(stderr, "ERR: link set xdp unload failed (err=%d):%s\n",
			err, strerror(-err));
		return -1;
	}
	return 0;
}

int xdp_link_attach(int ifindex, __u32 xdp_flags, int prog_fd)
{
	int err;

	/* libbpf provide the XDP net_device link-level hook attach helper */
	err = bpf_set_link_xdp_fd(ifindex, prog_fd, xdp_flags);
  
  	if (err < 0) {
		fprintf(stderr, "ERR: "
			"ifindex(%d) link set xdp fd failed (%d): %s\n",
			ifindex, -err, strerror(-err));

		switch (-err) {
		case EBUSY:
		case EEXIST:
			fprintf(stderr, "Hint: XDP already loaded on device"
				" use --force to swap/replace\n");
			break;
		case EOPNOTSUPP:
			fprintf(stderr, "Hint: Native-XDP not supported"
				" use --skb-mode or --auto-mode\n");
			break;
		default:
			break;
		}
		return -1;
	}

	return 0;
}

/* User program takes two  or three arguments
 * interface name, relay server IP and prog 
 * unload flag
*/
int main(int argc, char **argv)
{
  	char filename[256] = "dhcp_kern_xdp.o";
	int prog_fd, err;

	__u32 xdp_flags = XDP_FLAGS_SKB_MODE;
  	char dev[12] = "";
	bool do_unload = 0;
	struct bpf_map *map = NULL;
	struct bpf_obj *obj = NULL;
	int map_fd;
	int key = 0;
	char server[15] = "";
	struct in_addr addr;
	
 	strcpy( dev,argv[1]);
	strcpy(server,argv[2]);
	if(inet_aton(argv[2], &addr) == 0) {
		fprintf(stderr,"Invalid IP address\n");
	}
	if(argc > 3)
		do_unload = argv[3];

  	__u16 ifindex;
  	ifindex = if_nametoindex(dev);
  	if(ifindex < 0)
    		printf("ifindex error\n");
	  
  	if (do_unload)
		  return xdp_link_detach(ifindex, xdp_flags);
      
  /* Load the BPF-ELF object file and get back first BPF_prog FD */
	err = bpf_prog_load(filename, BPF_PROG_TYPE_XDP, &obj, &prog_fd);
	if (err) {
		fprintf(stderr, "ERR: loading BPF-OBJ file(%s) (%d): %s\n",
			filename, err, strerror(-err));
		return -1;
	}
	if (prog_fd <= 0) {
		printf( "ERR: loading file: %s\n" );
		return -1;
	}
  

  	err = xdp_link_attach(ifindex, xdp_flags, prog_fd);
	if (err)
		return err;
/* read the map from prog object file and update the realy
 * server IP to the map
*/
	map = bpf_object__find_map_by_name(obj, SERVER_MAP);
	err = libbpf_get_error(map);
	if (err) {
		fprintf(stderr, "Could not find map %s in %s: %s\n", SERVER_MAP,
			XDP_OBJ, strerror(err));
		map = NULL;
	}
	map_fd = bpf_map__fd(map);
	if(map_fd < 0) {
		fprintf(stderr, "Could not get map fd\n");
	}
	
	err = bpf_map_update_elem(map_fd,&key,&addr.s_addr,BPF_ANY);
	if(err) {
		fprintf(stderr, "Could not update map %s in %s\n",SERVER_MAP, XDP_OBJ);
	}
    
 	printf("Success: Loading xdp program\n");
	return 0;
}
