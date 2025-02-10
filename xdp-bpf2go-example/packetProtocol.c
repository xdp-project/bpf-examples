// go:build ignore

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

struct{
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __type(key, __u32);
  __type(value, __u64);
  __uint(max_entries, 255);
} protocol_count SEC(".maps");

SEC("xdp")
int get_packet_protocol(struct xdp_md *ctx) {

  void *data_end = (void *)(long)ctx->data_end;
  void *data = (void *)(long)ctx->data;

  // Parse Ethernet header
  struct ethhdr *eth = data;
  if ((void *)(eth + 1) > data_end) {
    return XDP_PASS;
  }

  // Check if the packet is an IP packet
  if (eth->h_proto != __constant_htons(ETH_P_IP)) {
    return XDP_PASS;
  }

  // Parse IP header
  struct iphdr *ip = data + sizeof(struct ethhdr);
  if ((void *)(ip + 1) > data_end) {
    return XDP_PASS;
  }

  __u32 key = ip->protocol; // Using IP protocol as the key
  __u64 *count = bpf_map_lookup_elem(&protocol_count, &key);
  if (count) {
    __sync_fetch_and_add(count, 1);
  }

  return XDP_PASS;
}

char __license[] SEC("license") = "GPL";