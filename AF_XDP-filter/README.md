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