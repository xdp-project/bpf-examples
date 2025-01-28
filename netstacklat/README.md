# Netstacklat - Monitor latency within the network stack
Netstacklat is a simple tool for monitoring latency within the Linux
network stack for ingress traffic. The tool relies on the kernel time
stamping received packets (`SOF_TIMESTAMPING_RX_SOFTWARE`),
specifically setting `sk_buff->tstamp`. It then reports when packets
arrive at various hooks relative to this timestamp, i.e. the time
between the packet being timestamped by the kernel and reaching a
specific hook.

The tool is based on the following bpftrace script from Jesper
Dangaard Brouer:
```console
sudo bpftrace -e '
	kfunc:tcp_v4_do_rcv,
	kfunc:tcp_data_queue,
	kfunc:udp_queue_rcv_one_skb
	{
		$tai_offset=37000000000;
		$now=nsecs(tai)-$tai_offset; @cnt[probe]=count(); @total[probe]=count();
		$ts=args->skb->tstamp; $delta=$now-(uint64)$ts;
		@hist_ns[probe]=hist($delta);
		@stats[probe]=stats($delta);
		//printf("now:%llu - ts:%llu = delta:%llu\n", $now, $ts, $delta);
	}
	interval:s:10 {time("\n%H:%M:%S\n");
		print(@cnt); clear(@cnt);
		print(@total);
		print(@stats);
		print(@hist_ns);
	}'
```

The eBPF part of the tool (`netstacklat.bpf.c`) is designed to be
compatible with
[ebpf_exporter](https://github.com/cloudflare/ebpf_exporter), so that
the data can easily be exported to Prometheus. The easiest way to use
netstacklat together with ebpf-exporter is simply to point it to this
directory, i.e.
```console
$ ebpf_exporter --config.dir=<path>/bpf-examples/netstacklat --config.names=netstacklat
```

Alternatively, you can copy over the files to ebpf-exporter's example
repository.
```console
$ cp netstacklat.{bpf.c,h,yaml} -t <path>/ebpf_exporter/examples/
# Fix up some header includes (e.g. "vmlinux_local.h" -> <vmlinux.h>
$ make -C <path>/ebpf_exporter/examples build
$ ebpf_exporter --config.dir=<path>/ebpf_exporter/examples --config.names
```

Note that when using together with ebpf-exporter, some of the
functionality handled by netstacklat's userspace program will not be
available. This includes setting the `TAI_OFFSET` constant in
`netstacklat.bpf.c` to match your system's TAI offset (you can do this
manually instead), and enabling RX timestamping by the kernel (see the
`enable_sw_rx_tstamps()` function in `netstacklat.c` for an example of
how to do this).
