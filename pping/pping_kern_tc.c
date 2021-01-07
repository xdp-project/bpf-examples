#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <xdp/parsing_helpers.h>

#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>

#include <string.h>

#include "pping.h"
#include "pping_helpers.h"


char _license[] SEC("license") = "GPL";

struct bpf_map_def SEC("maps") ts_start = {
  .type = BPF_MAP_TYPE_HASH,
  .key_size = sizeof(struct ts_key),
  .value_size = sizeof(struct ts_timestamp),
  .max_entries = 16384,
};

// TC-BFP for parsing TSVAL from egress traffic and add to map
SEC("pping_egress")
int tc_bpf_prog_egress(struct __sk_buff *skb)
{
  void *data     = (void *)(long)skb->data;
  void *data_end = (void *)(long)skb->data_end;

  bpf_printk("Sent packet of size %d bytes\n", data_end - data);
  
  int proto = -1;
  struct hdr_cursor nh = {.pos = data};
  struct ethhdr *eth;
  struct iphdr *iph;
  struct tcphdr *tcph;

  proto = parse_ethhdr(&nh, data_end, &eth);
  if (bpf_ntohs(proto) != ETH_P_IP)
    goto end; // Not IPv4 packet (or failed to parse ethernet header)
  proto = parse_iphdr(&nh, data_end, &iph);
  if (proto != IPPROTO_TCP)
    goto end; // Not a TCP packet (or failed to parse ethernet header)
  proto = parse_tcphdr(&nh, data_end, &tcph);
  if (proto < 0)
    goto end; // Failed parsing TCP-header

  bpf_printk("TCP-packet with %d byte header and %lu bytes of data\n", proto, data_end - nh.pos);

    __u32 tsval, tsecr;
  if (parse_tcp_ts(tcph, data_end, &tsval, &tsecr) < 0) // No TCP timestamp
    goto end;
  // We have a TCP-timestamp - now we can check if it's in the map
  bpf_printk("TCP-packet with timestap. TSval: %u, TSecr: %u\n", bpf_ntohl(tsval), bpf_ntohl(tsecr));
  struct ts_key key;
  fill_ipv4_flow(&(key.flow), iph->saddr, iph->daddr, tcph->source, tcph->dest);
  key.tsval = tsval;

  // Should only look up map (filling done on egress), but temporarily add to map before I get the TC-BPF part working
  struct ts_timestamp ts = {0};
  ts.timestamp = bpf_ktime_get_ns(); //Verifier was unhappy when using bpf_ktime_get_boot_ns
  bpf_map_update_elem(&ts_start, &key, &ts, BPF_NOEXIST);

 end:
  return BPF_OK;
}
