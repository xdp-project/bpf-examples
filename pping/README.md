# PPing using XDP and TC-BPF
A re-implementation of [Kathie Nichols' passive ping
(pping)](https://github.com/pollere/pping) utility using XDP (on ingress) and
TC-BPF (on egress) for the packet capture logic.

## Simple description
Passive Ping (PPing) is a simple tool for passively measuring per-flow RTTs. It
can be used on endhosts as well as any (BPF-capable Linux) device which can see
both directions of the traffic (ex router or middlebox). Currently it only works
for TCP traffic which uses the TCP timestamp option, but could be extended to
also work with for example TCP seq/ACK numbers, the QUIC spinbit and ICMP
echo-reply messages. See the [TODO-list](./TODO.md) for more potential features
(which may or may not ever get implemented).

The fundamental logic of pping is to timestamp a pseudo-unique identifier for
outgoing packets, and then look for matches in the incoming packets. If a match
is found, the RTT is simply calculated as the time difference between the
current time and the stored timestamp.

This tool, just as Kathie's original pping implementation, uses TCP timestamps
as identifiers. For outgoing packets, the TSval (which is a timestamp in and off
itself) is timestamped. Incoming packets are then parsed for the TSecr, which
are the echoed TSval values from the receiver. The TCP timestamps are not
necessarily unique for every packet (they have a limited update frequency,
appears to be 1000 Hz for modern Linux systems), so only the first instance of
an identifier is timestamped, and matched against the first incoming packet with
the identifier. The mechanism to ensure only the first packet is timestamped and
matched differs from the one in Kathie's pping, and is further described in
[SAMPLING_DESIGN](./SAMPLING_DESIGN.md).

## Output formats
pping currently supports 3 different formats, *standard*, *ppviz* and *json*. In
general, the output consists of two different types of events, flow-events which
gives information that a flow has started/ended, and RTT-events which provides
information on a computed RTT within a flow.

### Standard format
The standard format is quite similar to the Kathie's pping default output, and
is generally intended to be an easily understood human-readable format writing a
single line per event.

An example of the format is provided below:
```shell
16:00:46.142279766 10.11.1.1:5201+10.11.1.2:59528 opening due to SYN-ACK from src
16:00:46.147705205 5.425439 ms 5.425439 ms 10.11.1.1:5201+10.11.1.2:59528
16:00:47.148905125 5.261430 ms 5.261430 ms 10.11.1.1:5201+10.11.1.2:59528
16:00:48.151666385 5.972284 ms 5.261430 ms 10.11.1.1:5201+10.11.1.2:59528
16:00:49.152489316 6.017589 ms 5.261430 ms 10.11.1.1:5201+10.11.1.2:59528
16:00:49.878508114 10.11.1.1:5201+10.11.1.2:59528 closing due to RST from dest
```

### ppviz format
The ppviz format is primarily intended to be used to generate data that can be
visualized by Kathie's [ppviz](https://github.com/pollere/ppviz) tool. The
format is essentially a CSV format, using a single space as the separator, and
is further described [here](http://www.pollere.net/ppviz.html).

Note that the optional *FBytes*, *DBytes* and *PBytes* from the format
specification have not been included here, and do not appear to be used by
ppviz. Furthermore, flow events are not included in the output, as the those are
not used by ppviz.

An example of the format is provided below:
```shell
1623420121.483727575 0.005298909 0.005298909 10.11.1.1:5201+10.11.1.2:59532
1623420122.484530934 0.006016639 0.005298909 10.11.1.1:5201+10.11.1.2:59532
1623420123.485899736 0.005590783 0.005298909 10.11.1.1:5201+10.11.1.2:59532
1623420124.490584753 0.006123511 0.005298909 10.11.1.1:5201+10.11.1.2:59532
1623420125.492190751 0.005624835 0.005298909 10.11.1.1:5201+10.11.1.2:59532
```
### JSON format
The JSON format is primarily intended to be machine-readable, and thus uses no
spacing or newlines between entries to reduce the overhead. External tools such
as [jq](https://stedolan.github.io/jq/) can be used to pretty-print the format.

The format consists of an array at the root-level, and each flow or RTT even is
added as an object to the root-array. The events contain some additional fields
in the JSON format which is not displayed by the other formats. All times
(*timestamp*, *rtt* and *min_rtt*) are provided as integers in nanoseconds.

An example of a (pretty-printed) flow-event is provided below:
```json
{
    "timestamp": 1623420837244545000,
    "src_ip": "10.11.1.1",
    "src_port": 5201,
    "dest_ip": "10.11.1.2",
    "dest_port": 59572,
    "protocol": "TCP",
    "flow_event": "opening",
    "reason": "SYN-ACK",
    "triggered_by": "src"
}
```

An example of a (pretty-printed) RTT-even is provided below:
```json
{
    "timestamp": 1623420838254558500,
    "src_ip": "10.11.1.1",
    "src_port": 5201,
    "dest_ip": "10.11.1.2",
    "dest_port": 59572,
    "protocol": "TCP",
    "rtt": 5977708,
    "min_rtt": 5441848,
    "sent_packets": 9393,
    "sent_bytes": 492457296,
    "rec_packets": 5922,
    "rec_bytes": 37
}
```

## Design and technical description
!["Design of eBPF pping](./eBPF_pping_design.png)

### Files:
- **pping.c:** Userspace program that loads and attaches the BPF programs, pulls
  the perf-buffer `rtt_events` to print out RTT messages and periodically cleans
  up the hash-maps from old entries. Also passes user options to the BPF
  programs by setting a "global variable" (stored in the programs .rodata
  section).
- **pping_kern.c:** Contains the BPF programs that are loaded on tc (egress) and
  XDP (ingress), as well as several common functions, a global constant `config`
  (set from userspace) and map definitions. The tc program `pping_egress()`
  parses outgoing packets for identifiers. If an identifier is found and the
  sampling strategy allows it, a timestamp for the packet is created in
  `packet_ts`. The XDP program `pping_ingress()` parses incomming packets for an
  identifier. If found, it looks up the `packet_ts` map for a match on the
  reverse flow (to match source/dest on egress). If there is a match, it
  calculates the RTT from the stored timestamp and deletes the entry. The
  calculated RTT (together with the flow-tuple) is pushed to the perf-buffer
  `events`. Both `pping_egress()` and `pping_ingress` can also push flow-events
  to the `events` buffer.
- **bpf_egress_loader.sh:** A shell script that's used by `pping.c` to setup a
  clsact qdisc and attach the `pping_egress()` program to egress using
  tc. **Note**: Unless your iproute2 comes with libbpf support, tc will use
  iproute's own loading mechanism when loading and attaching object files
  directly through the tc command line. To ensure that libbpf is always used to
  load `pping_egress()`, `pping.c` actually loads the program and pins it to
  `/sys/fs/bpf/pping/classifier`, and tc only attaches the pinned program.
- **functions.sh and parameters.sh:** Imported by `bpf_egress_loader.sh`.
- **pping.h:** Common header file included by `pping.c` and
  `pping_kern.c`. Contains some common structs used by both (are part of the
  maps).

### BPF Maps:
- **flow_state:** A hash-map storing some basic state for each flow, such as the
  last seen identifier for the flow and when the last timestamp entry for the
  flow was created. Entries are created by `pping_egress()`, and can be updated
  or deleted by both `pping_egress()` and `pping_ingress()`. Leftover entries
  are eventually removed by `pping.c`.
- **packet_ts:** A hash-map storing a timestamp for a specific packet
  identifier. Entries are created by `pping_egress()` and removed by
  `pping_ingress()` if a match is found. Leftover entries are eventually removed
  by `pping.c`.
- **events:** A perf-buffer used by the BPF programs to push flow or RTT events
  to `pping.c`, which continuously polls the map the prints them out.

### A note on concurrency
The program uses "global" (not `PERCPU`) hash maps to keep state. As the BPF
programs need to see the global view to function properly, using `PERCPU` maps
is not an option. The program must be able to match against stored packet
timestamps regardless of the CPU the packets are processed on, and must also
have a global view of the flow state in order for the sampling to work
correctly.

As the BPF programs may run concurrently on different CPU cores accessing these
global hash maps, this may result in some concurrency issues. In practice, I do
not believe these will occur particularly often, as I'm under the impression
that packets from the same flow will typically be processed by the some
CPU. Furthermore, most of the concurrency issues will not be that problematic
even if they do occur. For now, I've therefore left these concurrency issues
unattended, even if some of them could be avoided with atomic operations and/or
spinlocks, in order to keep things simple and not hurt performance.

The (known) potential concurrency issues are:

#### Tracking last seen identifier
The tc/egress program keeps track of the last seen outgoing identifier for each
flow, by storing it in the `flow_state` map. This is done to detect the first
packet with a new identifier. If multiple packets are processed concurrently,
several of them could potentially detect themselves as being first with the same
identifier (which only matters if they also pass rate-limit check as well),
alternatively if the concurrent packets have different identifiers there may be
a lost update (but for TCP timestamps, concurrent packets would typically be
expected to have the same timestamp).

A possibly more severe issue is out-of-order packets. If a packet with an old
identifier arrives out of order, that identifier could be detected as a new
identifier. If for example the following flow of four packets with just two
different identifiers (id1 and id2) were to occur:

id1 -> id2 -> id1 -> id2

Then the tc/egress program would consider each of these packets to have new
identifiers and try to create a new timestamp for each of them if the sampling
strategy allows it. However even if the sampling strategy allows it, the
(incorrect) creation of timestamps for id1 and id2 the second time would only be
successful in case the first timestamps for id1 and id2 have already been
matched against (and thus deleted). Even if that is the case, they would only
result in reporting an incorrect RTT in case there are also new matches against
these identifiers.

This issue could be avoided entirely by requiring that new-id > old-id instead
of simply checking that new-id != old-id, as TCP timestamps should monotonically
increase. That may however not be a suitable solution if/when we add support for
other types of identifiers.

#### Rate-limiting new timestamps
In the tc/egress program packets to timestamp are sampled by using a per-flow
rate-limit, which is enforced by storing when the last timestamp was created in
the `flow_state` map. If multiple packets perform this check concurrently, it's
possible that multiple packets think they are allowed to create timestamps
before any of them are able to update the `last_timestamp`. When they update
`last_timestamp` it might also be slightly incorrect, however if they are
processed concurrently then they should also generate very similar timestamps.

If the packets have different identifiers, (which would typically not be
expected for concurrent TCP timestamps), then this would allow some packets to
bypass the rate-limit. By bypassing the rate-limit, the flow would use up some
additional map space and report some additional RTT(s) more than expected
(however the reported RTTs should still be correct).

If the packets have the same identifier, they must first have managed to bypass
the previous check for unique identifiers (see [previous point](#Tracking last
seen identifier)), and only one of them will be able to successfully store a
timestamp entry.

#### Matching against stored timestamps
The XDP/ingress program could potentially match multiple concurrent packets with
the same identifier against a single timestamp entry in `packet_ts`, before any
of them manage to delete the timestamp entry. This would result in multiple RTTs
being reported for the same identifier, but if they are processed concurrently
these RTTs should be very similar, so would mainly result in over-reporting
rather than reporting incorrect RTTs.

#### Updating flow statistics
Both the tc/egress and XDP/ingress programs will try to update some flow
statistics each time they successfully parse a packet with an
identifier. Specifically, they'll update the number of packets and bytes
sent/received. This is not done in an atomic fashion, so there could potentially
be some lost updates resulting an underestimate.

Furthermore, whenever the XDP/ingress program calculates an RTT, it will check
if this is the lowest RTT seen so far for the flow. If multiple RTTs are
calculated concurrently, then several could pass this check concurrently and
there may be a lost update. It should only be possible for multiple RTTs to be
calculated concurrently in case either the [timestamp rate-limit was
bypassed](#Rate-limiting new timestamps) or [multiple packets managed to match
against the same timestamp](#Matching against stored timestamps).

It's worth noting that with sampling the reported minimum-RTT is only an
estimate anyways (may never calculate RTT for packet with the true minimum
RTT). And even without sampling there is some inherent sampling due to TCP
timestamps only being updated at a limited rate (1000 Hz).

## Similar projects
Passively measuring the RTT for TCP traffic is not a novel concept, and there
exists a number of other tools that can do so. A good overview of how passive
RTT calculation using TCP timestamps (as in this project) works is provided in
[this paper](https://doi.org/10.1145/2523426.2539132) from 2013.

- [pping](https://github.com/pollere/pping): This project is largely a
  re-implementation of Kathie's pping, but by using BPF and XDP as well as
  implementing some filtering logic the hope is to be able to create a always-on
  tool that can scale well even to large amounts of massive flows.
- [ppviz](https://github.com/pollere/ppviz): Web-based visualization tool for
  the "machine-friendly" (-m) output from Kathie's pping tool. Running this
  implementation of pping with --format="ppviz" will generate output that can be
  used by ppviz.
- [tcptrace](https://github.com/blitz/tcptrace): A post-processing tool which
  can analyze a tcpdump file and among other things calculate RTTs based on
  seq/ACK numbers (`-r` or `-R` flag).
- **Dapper**: A passive TCP data plane monitoring tool implemented in P4 which
  can among other things calculate the RTT based on the matching seq/ACK
  numbers. [Paper](https://doi.org/10.1145/3050220.3050228). [Unofficial
  source](https://github.com/muhe1991/p4-programs-survey/tree/master/dapper).
- [P4 Tofino TCP RTT measurement](https://github.com/Princeton-Cabernet/p4-projects/tree/master/RTT-tofino): 
  A passive TCP RTT monitor based on seq/ACK numbers implemented in P4 for
  Tofino programmable switches. [Paper](https://doi.org/10.1145/3405669.3405823).
