This test case facilitates filtration of inbound flows.
The idea is that userland code should determine for each 5-tuple
(source IP, source port, destination IP, destination port, protocol) whether the flow
is to be allowed. Only the first packet of the flow is redirected to the user space
code. User space code does its determination and sets an entry appropriately in an
eBPF map. For the second and subsequent packets of the flow, the eBPF kernel
looks up the decision in the map and returns with XDP_PASS or XDP_DROP appropriately.

The example is currently functional, except that the user space code needs to do
something useful with the first packet. At the moment it injects the packet to the
kernel via a TUN/TAP interface, and the kernel drops the packet because it thinks it
is a 'martian'. So if you try an inbound 'ping' the first ping packet is lost but
subsequent packets are replied to, and if you try an inbound 'ssh' session there is
a short delay while the TCP protocol times out and retries the SYN packet.

For this example, all flows are permitted. This code

     static bool filter_pass_tcp(int accept_map_fd, __u32 saddr, __u32 daddr, __u16 sport, __u16 dport) {
     	struct fivetuple f ;
    	enum xdp_action a=0;
    	f.saddr=htonl(saddr);
    	f.daddr=htonl(daddr);
    	f.sport=htons(sport);
    	f.dport=htons(dport);
    	f.protocol=IPPROTO_TCP;
    	f.padding = 0;
    	show_fivetuple(&f) ;
    	int ret = bpf_map_lookup_elem(accept_map_fd, &f, &a);
    	if ( ret == 0 ) {
    		if(k_verbose) fprintf(stdout, "Value %d found in map\n", a) ;
    		return a == XDP_PASS;
    	}
    	a = XDP_PASS;
    	if(k_verbose) fprintf(stdout, "No value in map, setting to %d\n", a) ;
    	ret = bpf_map_update_elem(accept_map_fd,&f, &a, BPF_ANY) ;
    	return true ;
    }

can be changed to deny TCP flows, and there is similar code for UDP and ICMP flows.
ICMP flows do not have a port number so this is set to zero for the purposes of
constructing the 5-tuple.

Packets for protocols other than UDP, TCP, and ICMP are always passed; this enables
ARP to work.

To check out this code and verify that something runs, run these commands. Note that running the testcase requires root privileges.
```
      mkdir workspace
      cd workspace
      git clone git@github.com:tjcw/bpf-examples.git
      cd bpf-examples
      git checkout tjcw-integration-1.2
      git submodule update --init
      cd bpf-examples
      cd AF_XDP-filter
      make
      cd netperf-namespace 
      sudo FILTER=af_xdp_kern PORT=50000 ./run.sh 2>&1|tee logfile.txt
```


To build this code, type 'make' in this directory. Built artifacts are
- af_xdp_kern.o -- eBPF object file for filtration
- af_xdp_kern_passall.o -- eBPF object file which just returns XDP_PASS for performace comparisons
- af_xdp_user -- user space executable to do the filtering
- filter-xdp_stats -- tool to display traffic statsistics from the map maintained by af_xdp_kern.o

There are a number of  directories which contain run scripts
-      run/run.sh -- run a server on a local machine with a Pensando (16 channel) card that you can ping or ssh to from a client machine.
-      run/runvm.sh -- run a server in a virtual machine that you can ping or ssh to from another virtual machine.
-      run/runnest.sh -- run a server in a nested virtual machine, I run 2 VMs within another VM on my laptop. Ping or ssh from the client nested VM to the server nested VM.
-      run/runns.sh -- standalone test case which sets up 2 namespaces and pings between them
-      iperf3-namespace/run.sh -- run iperf3 between 2 namespaces
-      iperf3-real/run.sh  -- run iperf3 between 2 real machines with 16-channel NICs
-      netperf-namespace/run.sh  -- run netperf between 2 namespaces
-      netperf3-real/run.sh -- run netperf between 2 real machines
-      netperf3-vm/run.sh -- run netperf between 2 real machines
    
