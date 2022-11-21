#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <getopt.h>
#include <errno.h>

#include <net/if.h>
#include <linux/if_link.h> /* XDP_FLAGS_* depend on kernel-headers installed */
#include <linux/if_xdp.h>
#include <sched.h>

#include <arpa/inet.h> /* inet_pton */

#include "common_params.h"

int verbose = 1;
int debug = 0;
int debug_pkt = 0;
int debug_meta = 0;
int debug_time = 0;

#define BUFSIZE 30

void _print_options(const struct option_wrapper *long_options, bool required)
{
	int i, pos;
	char buf[BUFSIZE];

	for (i = 0; long_options[i].option.name != 0; i++) {
		if (long_options[i].required != required)
			continue;

		if (long_options[i].option.val > 64) /* ord('A') = 65 = 0x41 */
			printf(" -%c,", long_options[i].option.val);
		else
			printf("    ");
		pos = snprintf(buf, BUFSIZE, " --%s", long_options[i].option.name);
		if (long_options[i].metavar)
			snprintf(&buf[pos], BUFSIZE-pos, " %s", long_options[i].metavar);
		printf("%-22s", buf);
		printf("  %s", long_options[i].help);
		printf("\n");
	}
}

void usage(const char *prog_name, const char *doc,
           const struct option_wrapper *long_options, bool full)
{
	printf("Usage: %s [options]\n", prog_name);

	if (!full) {
		printf("Use --help (or -h) to see full option list.\n");
		return;
	}

	printf("\nDOCUMENTATION:\n %s\n", doc);
	printf("Required options:\n");
	_print_options(long_options, true);
	printf("\n");
	printf("Other options:\n");
	_print_options(long_options, false);
	printf("\n");
}

/* Helper for convert IPv4 address from text to binary form */
bool get_ipv4_u32(char *ip_str, uint32_t *ip_addr)
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

int option_wrappers_to_options(const struct option_wrapper *wrapper,
				struct option **options)
{
	int i, num;
	struct option *new_options;
	for (i = 0; wrapper[i].option.name != 0; i++) {}
	num = i;

	new_options = malloc(sizeof(struct option) * num);
	if (!new_options)
		return -1;
	for (i = 0; i < num; i++) {
		memcpy(&new_options[i], &wrapper[i], sizeof(struct option));
	}

	*options = new_options;
	return 0;
}

void parse_cmdline_args(int argc, char **argv,
			const struct option_wrapper *options_wrapper,
                        struct config *cfg, const char *doc)
{
	struct option *long_options;
	bool full_help = false;
	uint32_t ipv4_tmp = 0;
	int longindex = 0;
	char *dest;
	int opt;

	if (option_wrappers_to_options(options_wrapper, &long_options)) {
		fprintf(stderr, "Unable to malloc()\n");
		exit(EXIT_FAIL_OPTION);
	}

	/* Parse commands line args */
	while ((opt = getopt_long(argc, argv,
				  "hd:r:L:R:BASNFUMQ:G:H:czqp:ti:b:",
				  long_options, &longindex)) != -1) {
		switch (opt) {
		case 'd':
			if (strlen(optarg) >= IF_NAMESIZE) {
				fprintf(stderr, "ERR: --dev name too long\n");
				goto error;
			}
			cfg->ifname = (char *)&cfg->ifname_buf;
			strncpy(cfg->ifname, optarg, IF_NAMESIZE);
			cfg->ifindex = if_nametoindex(cfg->ifname);
			if (cfg->ifindex == 0) {
				fprintf(stderr,
					"ERR: --dev name unknown err(%d):%s\n",
					errno, strerror(errno));
				goto error;
			}
			break;
		case 'r':
			if (strlen(optarg) >= IF_NAMESIZE) {
				fprintf(stderr, "ERR: --redirect-dev name too long\n");
				goto error;
			}
			cfg->redirect_ifname = (char *)&cfg->redirect_ifname_buf;
			strncpy(cfg->redirect_ifname, optarg, IF_NAMESIZE);
			cfg->redirect_ifindex = if_nametoindex(cfg->redirect_ifname);
			if (cfg->redirect_ifindex == 0) {
				fprintf(stderr,
						"ERR: --redirect-dev name unknown err(%d):%s\n",
						errno, strerror(errno));
				goto error;
			}
			break;
		case 'G':
			if (!ether_aton_r(optarg,
					  (struct ether_addr *)&cfg->opt_tx_dmac)) {
				fprintf(stderr, "Invalid dest MAC address:%s\n",
					optarg);
				goto error;
			}
			break;
		case 'H':
			if (!ether_aton_r(optarg,
					  (struct ether_addr *)&cfg->opt_tx_smac)) {
				fprintf(stderr, "Invalid src MAC address:%s\n",
					optarg);
				goto error;
			}
			break;
		case 'b':
			cfg->batch_pkts = atoi(optarg);
			if (cfg->batch_pkts > BATCH_PKTS_MAX) {
				fprintf(stderr, "ERROR: "
					" batch (%u) pkts limited to %u\n",
					cfg->batch_pkts, BATCH_PKTS_MAX);
				goto error;
			}
			break;
		case 'B':
			cfg->opt_busy_poll = true;
			break;
		case 'A':
			cfg->xdp_flags &= ~XDP_FLAGS_MODES;    /* Clear flags */
			break;
		case 'S':
			cfg->xdp_flags &= ~XDP_FLAGS_MODES;    /* Clear flags */
			cfg->xdp_flags |= XDP_FLAGS_SKB_MODE;  /* Set   flag */
			cfg->xsk_bind_flags &= ~XDP_ZEROCOPY;  /* Clear flag */
			cfg->xsk_bind_flags |= XDP_COPY;       /* Set   flag */
			break;
		case 'N':
			cfg->xdp_flags &= ~XDP_FLAGS_MODES;    /* Clear flags */
			cfg->xdp_flags |= XDP_FLAGS_DRV_MODE;  /* Set   flag */
			break;
		case 3: /* --offload-mode */
			cfg->xdp_flags &= ~XDP_FLAGS_MODES;    /* Clear flags */
			cfg->xdp_flags |= XDP_FLAGS_HW_MODE;   /* Set   flag */
			break;
		case 'F':
			cfg->xdp_flags &= ~XDP_FLAGS_UPDATE_IF_NOEXIST;
			break;
		case 'M':
			cfg->reuse_maps = true;
			break;
		case 'U':
			cfg->do_unload = true;
			break;
		case 'w':
			cfg->xsk_wakeup_mode = true;
			break;
		case 's':
			cfg->xsk_wakeup_mode = false;
			break;
		case 'q':
			verbose = false;
			break;
		case 'D':
			debug = true;
			break;
		case 'P':
			debug_pkt = true;
			break;
		case 'p':
			cfg->sched_prio = atoi(optarg);
			cfg->sched_policy = SCHED_FIFO;
			break;
		case 'm':
			debug_meta = true;
			break;
		case 't':
			debug_time = true;
			break;
		case 'Q':
			cfg->xsk_if_queue = atoi(optarg);
			break;
		case 1: /* --filename */
			dest  = (char *)&cfg->filename;
			strncpy(dest, optarg, sizeof(cfg->filename));
			break;
		case 2: /* --progsec */
			dest  = (char *)&cfg->progsec;
			strncpy(dest, optarg, sizeof(cfg->progsec));
			break;
		case 4: /* --src-ip */
			if (!get_ipv4_u32(optarg, &ipv4_tmp))
				goto error;
			cfg->opt_ip_src = ipv4_tmp;
			break;
		case 5: /* --dst-ip */
			if (!get_ipv4_u32(optarg, &ipv4_tmp))
				goto error;
			cfg->opt_ip_dst = ipv4_tmp;
			break;
		case 'L': /* --src-mac */
			dest  = (char *)&cfg->src_mac;
			strncpy(dest, optarg, sizeof(cfg->src_mac));
			break;
		case 'R': /* --dest-mac */
			dest  = (char *)&cfg->dest_mac;
			strncpy(dest, optarg, sizeof(cfg->dest_mac));
			break;
		case 'i':
			cfg->interval = atoi(optarg);
			break;
		case 'c':
			cfg->xsk_bind_flags &= ~XDP_ZEROCOPY;	/* Clear flag */
			cfg->xsk_bind_flags |= XDP_COPY;	/* Set   flag */
			break;
		case 'z':
			cfg->xsk_bind_flags &= ~XDP_COPY;	/* Clear flag */
			cfg->xsk_bind_flags |= XDP_ZEROCOPY;	/* Set   flag */
			break;
		case 'h':
			full_help = true;
			/* fall-through */
		error:
		default:
			usage(argv[0], doc, options_wrapper, full_help);
			free(long_options);
			exit(EXIT_FAIL_OPTION);
		}
	}
	free(long_options);
}
