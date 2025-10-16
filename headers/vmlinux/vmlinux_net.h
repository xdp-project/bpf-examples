#ifndef __VMLINUX_NET_H__
#define __VMLINUX_NET_H__

typedef __u32 __wsum;

typedef struct {
	struct net *net;
} possible_net_t;

struct net_device {
	int ifindex;
	possible_net_t nd_net;
};

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

struct sk_buff_list {
	struct sk_buff *next;
	struct sk_buff *prev;
};

struct sk_buff_head {
	union {
		struct {
			struct sk_buff *next;
			struct sk_buff *prev;
		};
		struct sk_buff_list list;
	};
	__u32 qlen;
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
	__u8 active_extensions;
	__u32 headers_start[0];
	__u8 __pkt_type_offset[0];
	__u8 pkt_type: 3;
	__u8 ignore_df: 1;
	__u8 nf_trace: 1;
	__u8 ip_summed: 2;
	__u8 ooo_okay: 1;
	__u8 tstamp_type: 2;
	__u8 l4_hash: 1;
	__u8 sw_hash: 1;
	__u8 wifi_acked_valid: 1;
	__u8 wifi_acked: 1;
	__u8 no_fcs: 1;
	__u8 encapsulation: 1;
	__u8 encap_hdr_csum: 1;
	__u8 csum_valid: 1;
	__u8 __pkt_vlan_present_offset[0];
	__u8 vlan_present: 1;
	__u8 csum_complete_sw: 1;
	__u8 csum_level: 2;
	__u8 csum_not_inet: 1;
	__u8 dst_pending_confirm: 1;
	__u8 ndisc_nodetype: 2;
	__u8 ipvs_property: 1;
	__u8 inner_protocol_type: 1;
	__u8 remcsum_offload: 1;
	__u8 offload_fwd_mark: 1;
	__u8 offload_l3_fwd_mark: 1;
	__u8 tc_skip_classify: 1;
	__u8 tc_at_ingress: 1;
	__u8 redirected: 1;
	__u8 from_ingress: 1;
	__u8 decrypted: 1;
	__u16 tc_index;
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
	__be16 vlan_proto;
	__u16 vlan_tci;
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
	__u32 headers_end[0];
	sk_buff_data_t tail;
	sk_buff_data_t end;
	unsigned char *head;
	unsigned char *data;
	unsigned int truesize;
	refcount_t users;
	struct skb_ext *extensions;
};

struct tcp_skb_cb {
	__u32 seq;
	__u32 end_seq;
	union {
		struct {
			u16 tcp_gso_segs;
			u16 tcp_gso_size;
		};
	};
	__u8 tcp_flags;
	__u8 sacked;
	__u8 ip_dsfield;
	__u8 txstamp_ack : 1;
	__u8 eor : 1;
	__u8 has_rxtstamp : 1;
	__u8 unused : 5;
	__u32 ack_seq;
	union {
		struct {
			__u32 is_app_limited : 1;
			__u32 delivered_ce : 20;
			__u32 unused : 11;
			__u32 delivered;
			u64 first_tx_mstamp;
			u64 delivered_mstamp;
		} tx;
	};
};

struct nf_conn {
	unsigned long status;
};

enum ip_conntrack_status {
	/* Connection is confirmed: originating packet has left box */
	IPS_CONFIRMED_BIT = 3,
	IPS_CONFIRMED = (1 << IPS_CONFIRMED_BIT),
};

struct scm_timestamping_internal {
	struct timespec64 ts[3];
};

struct ns_common {
	struct dentry *stashed;
	unsigned int inum;
};

struct net {
	struct ns_common ns;
};

struct sock_common {
	possible_net_t skc_net;
};

struct sock {
	struct sock_common __sk_common;
	struct sk_buff_head sk_receive_queue;
	struct {
		atomic_t rmem_alloc;
		int len;
		struct sk_buff *head;
		struct sk_buff *tail;
	} sk_backlog;
	struct dst_entry *sk_rx_dst;
	int sk_rx_dst_ifindex;
	u32 sk_rx_dst_cookie;
};

struct inet_sock {
	struct sock sk;
};

struct inet_connection_sock {
	struct inet_sock icsk_inet;
};

struct tcp_sock {
	struct inet_connection_sock inet_conn;
	__u8 __cacheline_group_begin__tcp_sock_read_tx[0];
	u32 max_window;
	u32 rcv_ssthresh;
	u32 reordering;
	u32 notsent_lowat;
	u16 gso_segs;
	struct sk_buff *lost_skb_hint;
	struct sk_buff *retransmit_skb_hint;
	__u8 __cacheline_group_end__tcp_sock_read_tx[0];
	__u8 __cacheline_group_begin__tcp_sock_read_txrx[0];
	u32 tsoffset;
	u32 snd_wnd;
	u32 mss_cache;
	u32 snd_cwnd;
	u32 prr_out;
	u32 lost_out;
	u32 sacked_out;
	u16 tcp_header_len;
	u8 scaling_ratio;
	u8 chrono_type: 2;
	u8 repair: 1;
	u8 tcp_usec_ts: 1;
	u8 is_sack_reneg: 1;
	u8 is_cwnd_limited: 1;
	__u8 __cacheline_group_end__tcp_sock_read_txrx[0];
	__u8 __cacheline_group_begin__tcp_sock_read_rx[0];
	u32 copied_seq;
	u32 rcv_tstamp;
	u32 snd_wl1;
	u32 tlp_high_seq;
	u32 rttvar_us;
	u32 retrans_out;
	u16 advmss;
	u16 urg_data;
	u32 lost;
	/* struct minmax rtt_min; */
	struct rb_root out_of_order_queue;
	u32 snd_ssthresh;
	u8 recvmsg_inq: 1;
	__u8 __cacheline_group_end__tcp_sock_read_rx[0];
	long: 0;
	__u8 __cacheline_group_begin__tcp_sock_write_tx[0];
	u32 segs_out;
	u32 data_segs_out;
	u64 bytes_sent;
	u32 snd_sml;
	u32 chrono_start;
	u32 chrono_stat[3];
	u32 write_seq;
	u32 pushed_seq;
	u32 lsndtime;
	u32 mdev_us;
	u32 rtt_seq;
	u64 tcp_wstamp_ns;
	struct list_head tsorted_sent_queue;
	struct sk_buff *highest_sack;
	u8 ecn_flags;
	__u8 __cacheline_group_end__tcp_sock_write_tx[0];
	__u8 __cacheline_group_begin__tcp_sock_write_txrx[0];
	__be32 pred_flags;
	u64 tcp_clock_cache;
	u64 tcp_mstamp;
	u32 rcv_nxt;
	u32 snd_nxt;
	u32 snd_una;
	u32 window_clamp;
	u32 srtt_us;
	u32 packets_out;
	u32 snd_up;
	u32 delivered;
	u32 delivered_ce;
	u32 app_limited;
	u32 rcv_wnd;
	/* struct tcp_options_received rx_opt; */
	u8 nonagle: 4;
	u8 rate_app_limited: 1;
	__u8 __cacheline_group_end__tcp_sock_write_txrx[0];
	long: 0;
	__u8 __cacheline_group_begin__tcp_sock_write_rx[0];
	u64 bytes_received;
	u32 segs_in;
	u32 data_segs_in;
	u32 rcv_wup;
	u32 max_packets_out;
	u32 cwnd_usage_seq;
	u32 rate_delivered;
	u32 rate_interval_us;
	u32 rcv_rtt_last_tsecr;
	u64 first_tx_mstamp;
	u64 delivered_mstamp;
	u64 bytes_acked;
	struct {
		u32 rtt_us;
		u32 seq;
		u64 time;
	} rcv_rtt_est;
	struct {
		u32 space;
		u32 seq;
		u64 time;
	} rcvq_space;
	__u8 __cacheline_group_end__tcp_sock_write_rx[0];
	u32 dsack_dups;
	u32 compressed_ack_rcv_nxt;
	struct list_head tsq_node;
	/* struct tcp_rack rack; */
	u8 compressed_ack;
	u8 dup_ack_counter: 2;
	u8 tlp_retrans: 1;
	u8 unused: 5;
	u8 thin_lto: 1;
	u8 fastopen_connect: 1;
	u8 fastopen_no_cookie: 1;
	u8 fastopen_client_fail: 2;
	u8 frto: 1;
	u8 repair_queue;
	u8 save_syn: 2;
	u8 syn_data: 1;
	u8 syn_fastopen: 1;
	u8 syn_fastopen_exp: 1;
	u8 syn_fastopen_ch: 1;
	u8 syn_data_acked: 1;
	u8 keepalive_probes;
	u32 tcp_tx_delay;
	u32 mdev_max_us;
	u32 reord_seen;
	u32 snd_cwnd_cnt;
	u32 snd_cwnd_clamp;
	u32 snd_cwnd_used;
	u32 snd_cwnd_stamp;
	u32 prior_cwnd;
	u32 prr_delivered;
	u32 last_oow_ack_time;
	/* struct hrtimer pacing_timer; */
	/* struct hrtimer compressed_ack_timer; */
	struct sk_buff *ooo_last_skb;
	/* struct tcp_sack_block duplicate_sack[1]; */
	/* struct tcp_sack_block selective_acks[4]; */
	/* struct tcp_sack_block recv_sack_cache[4]; */
	int lost_cnt_hint;
	u32 prior_ssthresh;
	u32 high_seq;
	u32 retrans_stamp;
	u32 undo_marker;
	int undo_retrans;
	u64 bytes_retrans;
	u32 total_retrans;
	u32 rto_stamp;
	u16 total_rto;
	u16 total_rto_recoveries;
	u32 total_rto_time;
	u32 urg_seq;
	unsigned int keepalive_time;
	unsigned int keepalive_intvl;
	int linger2;
	u8 bpf_sock_ops_cb_flags;
	u8 bpf_chg_cc_inprogress: 1;
	u16 timeout_rehash;
	u32 rcv_ooopack;
	struct {
		u32 probe_seq_start;
		u32 probe_seq_end;
	} mtu_probe;
	u32 plb_rehash;
	u32 mtu_info;
	bool is_mptcp;
};


#endif /* __VMLINUX_NET_H__ */
