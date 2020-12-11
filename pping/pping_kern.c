#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <xdp/parsing_helpers.h>

#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>

#include "timestamp_map.h"

#define MAX_TCP_OPTIONS 10
#define BILLION 1000000000UL

char _license[] SEC("license") = "GPL";

struct bpf_map_def SEC("maps") ts_start = {
  .type = BPF_MAP_TYPE_HASH,
  .key_size = sizeof(struct ts_key),
  .value_size = sizeof(struct ts_timestamp),
  .max_entries = 4096,
};

static __always_inline int fill_ipv4_flow(struct ipv4_flow *flow, __u32 saddr, __u32 daddr, __u16 sport, __u16 dport)
{
  flow->saddr = saddr;
  flow->daddr = daddr;
  flow->sport = sport;
  flow->dport = dport;
  return 0;
}

// Parses the TSval and TSecr values from the TCP options field - returns 0 if sucessful and -1 on failure
static __always_inline int parse_tcp_ts(struct tcphdr *tcph, void *data_end, __u32 *tsval, __u32 *tsecr)
{
  if (tcph + 1 > data_end) // To hopefully please verifier
    return -1;
  int len = tcph->doff << 2;
  if (len <= sizeof(struct tcphdr)) // No TCP options
    return -1;
  void *pos = (void *)(tcph + 1);
  void *opt_end = ((void *)tcph + len);
  __u8 i, opt, opt_size;
  #pragma unroll
  for (i = 0; i < MAX_TCP_OPTIONS; i++) {
    if (pos+1 > opt_end || pos+1 > data_end)
      return -1;
    opt = *(__u8 *)pos; // Save value to variable so I don't have to perform any more data_end checks on the option kind
    if (opt == 0) // Reached end of TCP options
      return -1;
    if (opt == 1) {// TCP NOP option - advance one byte
	pos++;
	continue;
      }
    // Option > 1, should have option size
    if (pos+2 > opt_end || pos+2 > data_end)
      return -1;
    opt_size = *(__u8 *)(pos+1); // Save value to variable so I don't have to perform any more data_end checks on option size

    if (opt == 8 && opt_size == 10) { // Option-kind is TCP timestap (yey!)
      if (pos + opt_size > opt_end ||pos + opt_size > data_end)
	return -1;
      *tsval = bpf_ntohl(*(__u32 *)(pos + 2));
      *tsecr = bpf_ntohl(*(__u32 *)(pos + 6));
      return 0;
    }

    // Some other TCP option - advance option-length bytes
    pos += opt_size;
  }
  return -1;
}
  
// XDP for parsing TSECR-val from ingress traffic and check for match in map
SEC("pping_ingress")
int xdp_prog_ingress(struct xdp_md *ctx)
{
  void *data = (void *)(long)ctx->data, *data_end = (void *)(long)ctx->data_end;
  int proto = -1;
  struct hdr_cursor nh = {.pos = data };
  struct ethhdr *eth;
  struct iphdr *iph;
  struct tcphdr *tcph;

  bpf_printk("Received packet of length %d\n", (int)(data_end - data));
  proto = parse_ethhdr(&nh, data_end, &eth);
  if (bpf_ntohs(proto) != ETH_P_IP)
    return XDP_PASS; // Not IPv4 packet (or failed to parse ethernet header)
  proto = parse_iphdr(&nh, data_end, &iph);
  if (proto != IPPROTO_TCP)
    return XDP_PASS; // Not a TCP packet (or failed to parse ethernet header)
  proto = parse_tcphdr(&nh, data_end, &tcph);
  if (proto < 0)
    return XDP_PASS; // Failed parsing TCP-header

  bpf_printk("TCP-packet with %d byte header and %lu bytes of data\n", proto, data_end - nh.pos);

  __u32 tsval, tsecr;
  if (parse_tcp_ts(tcph, data_end, &tsval, &tsecr) < 0) // No TCP timestamp
    return XDP_PASS;
  // We have a TCP-timestamp - now we can check if it's in the map
  bpf_printk("TCP-packet with timestap. TSval: %u, TSecr: %u\n", tsval, tsecr);
  struct ts_key key;
  fill_ipv4_flow(&(key.flow), iph->daddr, iph->saddr, tcph->dest, tcph->source); // Fill in reverse order of egress (dest <--> source)
  key.tsval = tsecr;

  // Should look up map map (filling done on egress), but temporarily add to map before I get the TC-BPF part working
  struct ts_timestamp wrong_value = {0};
  wrong_value.timestamp = bpf_ktime_get_ns(); //Verifier was unhappy when using bpf_ktime_get_boot_ns
  bpf_map_update_elem(&ts_start, &key, &wrong_value, BPF_NOEXIST);


  struct ts_timestamp *ts = bpf_map_lookup_elem(&ts_start, &key);
  if (ts && ts->used == 0) {
    ts->used = 1;
    __u64 rtt = bpf_ktime_get_ns() - ts->timestamp;
    // TODO: Push RTT + flow to userspace through perf buffer
    bpf_printk("RTT: %llu\n", rtt);
  }
  
  return XDP_PASS;
}

// TC-BFP for parsing TSVAL from egress traffic and add to map
SEC("pping_egress")
int tc_bpf_prog_egress(struct __skbuff *skb)
{
  return BPF_OK;
}
