#ifndef __VMLINUX_NET_H__
#define __VMLINUX_NET_H__

typedef __u32 __wsum;

typedef unsigned int sk_buff_data_t; // Assumes 64-bit. FIXME see below
/*
// BITS_PER_LONG can be wrong with -target bpf
#if BITS_PER_LONG > 32
#define NET_SKBUFF_DATA_USES_OFFSET 1
#endif

#ifdef NET_SKBUFF_DATA_USES_OFFSET
typedef unsigned int sk_buff_data_t;
#else
typedef unsigned char *sk_buff_data_t;
#endif
*/
struct llist_node {
	struct llist_node *next;
};

struct sk_buff {
	union {
		struct {
			struct sk_buff *next;
			struct sk_buff *prev;
			union {
				struct net_device *dev;
				long unsigned int dev_scratch;
			};
		};
		struct rb_node rbnode;
		struct list_head list;
		struct llist_node ll_node;
	};
	union {
		struct sock *sk;
		int ip_defrag_offset;
	};
	union {
		ktime_t tstamp;
		u64 skb_mstamp_ns;
	};
	char cb[48];
	union {
		struct {
			long unsigned int _skb_refdst;
			void (*destructor)(struct sk_buff *);
		};
		struct list_head tcp_tsorted_anchor;
		long unsigned int _sk_redir;
	};
	long unsigned int _nfct;
	unsigned int len;
	unsigned int data_len;
	__u16 mac_len;
	__u16 hdr_len;
	__u16 queue_mapping;
	__u8 __cloned_offset[0];
	__u8 cloned: 1;
	__u8 nohdr: 1;
	__u8 fclone: 2;
	__u8 peeked: 1;
	__u8 head_frag: 1;
	__u8 pfmemalloc: 1;
	__u8 pp_recycle: 1;
	__u8 active_extensions;
	union {
		struct {
			__u8 __pkt_type_offset[0];
			__u8 pkt_type: 3;
			__u8 ignore_df: 1;
			__u8 dst_pending_confirm: 1;
			__u8 ip_summed: 2;
			__u8 ooo_okay: 1;
			__u8 __mono_tc_offset[0];
			__u8 mono_delivery_time: 1;
			__u8 tc_at_ingress: 1;
			__u8 tc_skip_classify: 1;
			__u8 remcsum_offload: 1;
			__u8 csum_complete_sw: 1;
			__u8 csum_level: 2;
			__u8 inner_protocol_type: 1;
			__u8 l4_hash: 1;
			__u8 sw_hash: 1;
			__u8 wifi_acked_valid: 1;
			__u8 wifi_acked: 1;
			__u8 no_fcs: 1;
			__u8 encapsulation: 1;
			__u8 encap_hdr_csum: 1;
			__u8 csum_valid: 1;
			__u8 ndisc_nodetype: 2;
			__u8 ipvs_property: 1;
			__u8 nf_trace: 1;
			__u8 redirected: 1;
			__u8 from_ingress: 1;
			__u8 nf_skip_egress: 1;
			__u8 slow_gro: 1;
			__u8 csum_not_inet: 1;
			__u16 tc_index;
			u16 alloc_cpu;
			union {
				__wsum csum;
				struct {
					__u16 csum_start;
					__u16 csum_offset;
				};
			};
			__u32 priority;
			int skb_iif;
			__u32 hash;
			union {
				u32 vlan_all;
				struct {
					__be16 vlan_proto;
					__u16 vlan_tci;
				};
			};
			union {
				unsigned int napi_id;
				unsigned int sender_cpu;
			};
			__u32 secmark;
			union {
				__u32 mark;
				__u32 reserved_tailroom;
			};
			union {
				__be16 inner_protocol;
				__u8 inner_ipproto;
			};
			__u16 inner_transport_header;
			__u16 inner_network_header;
			__u16 inner_mac_header;
			__be16 protocol;
			__u16 transport_header;
			__u16 network_header;
			__u16 mac_header;
		};
		struct {
			__u8 __pkt_type_offset[0];
			__u8 pkt_type: 3;
			__u8 ignore_df: 1;
			__u8 dst_pending_confirm: 1;
			__u8 ip_summed: 2;
			__u8 ooo_okay: 1;
			__u8 __mono_tc_offset[0];
			__u8 mono_delivery_time: 1;
			__u8 tc_at_ingress: 1;
			__u8 tc_skip_classify: 1;
			__u8 remcsum_offload: 1;
			__u8 csum_complete_sw: 1;
			__u8 csum_level: 2;
			__u8 inner_protocol_type: 1;
			__u8 l4_hash: 1;
			__u8 sw_hash: 1;
			__u8 wifi_acked_valid: 1;
			__u8 wifi_acked: 1;
			__u8 no_fcs: 1;
			__u8 encapsulation: 1;
			__u8 encap_hdr_csum: 1;
			__u8 csum_valid: 1;
			__u8 ndisc_nodetype: 2;
			__u8 ipvs_property: 1;
			__u8 nf_trace: 1;
			__u8 redirected: 1;
			__u8 from_ingress: 1;
			__u8 nf_skip_egress: 1;
			__u8 slow_gro: 1;
			__u8 csum_not_inet: 1;
			__u16 tc_index;
			u16 alloc_cpu;
			union {
				__wsum csum;
				struct {
					__u16 csum_start;
					__u16 csum_offset;
				};
			};
			__u32 priority;
			int skb_iif;
			__u32 hash;
			union {
				u32 vlan_all;
				struct {
					__be16 vlan_proto;
					__u16 vlan_tci;
				};
			};
			union {
				unsigned int napi_id;
				unsigned int sender_cpu;
			};
			__u32 secmark;
			union {
				__u32 mark;
				__u32 reserved_tailroom;
			};
			union {
				__be16 inner_protocol;
				__u8 inner_ipproto;
			};
			__u16 inner_transport_header;
			__u16 inner_network_header;
			__u16 inner_mac_header;
			__be16 protocol;
			__u16 transport_header;
			__u16 network_header;
			__u16 mac_header;
		} headers;
	};
	sk_buff_data_t tail;
	sk_buff_data_t end;
	unsigned char *head;
	unsigned char *data;
	unsigned int truesize;
	refcount_t users;
	struct skb_ext *extensions;
};



struct iphdr {
	__u8 ihl: 4;
	__u8 version: 4;
	__u8 tos;
	__be16 tot_len;
	__be16 id;
	__be16 frag_off;
	__u8 ttl;
	__u8 protocol;
	__sum16 check;
	union {
		struct {
			__be32 saddr;
			__be32 daddr;
		};
		struct {
			__be32 saddr;
			__be32 daddr;
		} addrs;
	};
};

struct bpf_nf_ctx {
	const struct nf_hook_state *state;
	struct sk_buff *skb;
};


#endif /* __VMLINUX_NET_H__ */
