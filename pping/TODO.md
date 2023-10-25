# TODO

## Protocols
- [x] TCP (based on timestamp options)
  - [x] Skip pure ACKs for egress
    - Timestamping pure ACKs may lead to erroneous RTTs (ex. delay
      between application attempting to send data being recognized as
      an RTT)
  - [x] Skip non-ACKs for ingress
    - The echoed TSecr is not valid if the ACK-flag is not set
  - [ ] Add fallback to SEQ/ACK in case of no timestamp?
    - Some machines may not use TCP timestamps (either not supported
      at all, or disabled as in ex. Windows 10)
    - If one only considers SEQ/ACK (and don't check for SACK
      options), could result in ex. delay from retransmission being
      included in RTT
- [x] ICMP (ex Echo/Reply)
- [ ] QUIC (based on spinbit)
- [ ] DNS queries

## General pping
- [x] Add sampling so that RTT is not calculated for every packet
      (with unique value) for large flows
  - [ ] Allow short bursts to bypass sampling in order to handle 
        delayed ACKs, reordered or lost packets etc.
- [x] Keep some per-flow state
  - Will likely be needed for the sampling
  - [x] Could potentially include keeping track of average RTT, which
        may be useful for some decisions (ex. how often to sample,
        when entry can be removed etc)
  - [x] Could potentially include keeping track of minimum RTT (as
        done by the original pping), ex. to track bufferbloat
  - [ ] Could potentially include keeping track of if flow is
        bi-directional
    - Original pping checks if flow is bi-directional before adding
      timestamps, but this could miss shorter flows
- [ ] Dynamically grow the maps if they are starting to get full
- [ ] Use libxdp to load XDP program

## Done
- [x] Clean up commits and add signed-off-by tags
- [x] Add SPDX-license-identifier tags
- [x] Format C-code in kernel style
- [x] Use existing functionality to reuse maps by using BTF-defined
      maps
  - [x] Use BTF-defined maps for TC-BPF as well if iproute has libbpf
        support
- [x] Cleanup: Unload TC-BPF at program shutdown, and unpin map - In
      userspace part
- [x] Add IPv6 support
- [x] Refactor to support easy addition of other protocols
- [x] Load tc-bpf program with libbpf (only attach it with tc)
- [x] Switch to libbpf TC-BPF API for attaching the TC-BPF program
- [x] Add option for machine-readable output (as original pping)
  - It may be a good idea to keep the same format as original pping,
    so that tools such as [ppviz](https://github.com/pollere/ppviz)
    works for both pping implementations.
- [x] Add timestamps to output (as original pping)
- [x] Add support for other hooks
  - TC-BFP on ingress instead of XDP
- [x] Improve map cleaning:
  - [x] Use BPF iter to clean up maps with BPF programs instead of
        looping through entries in userspace.
  - [x] Use a dynamic time to live for map entries based on flow's RTT
        instead of static 10s limit
    - Keeping entries around for a long time allows the map to grow
    unnecessarily large, which slows down the cleaning and may block
    new entries
- [x] Keep track of outstanding timestamps, only match when necessary
  - Can avoid doing lookups in timestamp hash map if we know that
  there are no outstanding (unmatched) timestamps for the flow


# Potential issues
## Limited information in different output formats
The ppviz format is a bit limited in what information it can
include. One of these limitations is that it does not include any
protocol information as it was designed with only TCP in mind. If
using PPing with other protocols than TCP may therefore not be
possible to distinguish flows with different protocols. PPing will
therefore emit a warning if attempting to use the ppviz format with
protocols other than TCP, but will still allow it.

Another piece of information tracked by PPing which can't be included
in the ppviz format is if the calculated RTT includes the local
processing delay or not (that is, it was timestamped on ingress and
matched on egress instead of being timestamped on egress and matched
on ingress). Currently this information is only included in the JSON
format, but could potentially be added to the standard format if
deemed important.

## Cannot detect end of ICMP "flow"
ICMP is not a flow-based protocol, and therefore there is no signaling
that the ICMP "flow" is about to close. Subsequently, there is not way
for PPing to automatically detect that and ICMP flow has stopped and
delete its flow-state entry (and send a timely flow closing event).

A consequence of this is that the ICMP flow entries will stick around
and occupy a space in the flow state map until they are cleaned out by
the periodic cleanup process. The current timeout for ICMP flows is 30
seconds, which means a lot of short ICMP flows could quickly fill up
the flow map and potentially block other flows for a considerable
time.

## RTT-based sampling
The RTT-based sampling features means that timestamp entries may only
be created at an interval proportional to the flows RTT. This allows
flows with shorter RTTs to get more frequent RTT samples than flows
with long RTTs. However, as the flows RTT can only be updated based on
the calculated RTT samples, this creates a situation where the RTTs
update rate is dependent on itself. Flows with short RTTs will update
the RTT more often, which in turn affects how often they can update
the RTT.

This mainly becomes problematic if basing the sampling rate on the
sRTT which may grow. In this case the sRTT will generally be prone to
growing faster than it shrinks, as if it starts with a low RTT it will
quickly update it to higher RTTs, but with high RTTs it will take
longer for it do decrease to a lower RTT again.

## Losing debug/warning information
The "map full" and "map cleaning" events are pushed through the same
perf-buffer as the rtt and flow events. Just like rtt events may be
lost if too many of them are pushed, these debug/warning messages may
also be lost if there's a lot of other events being pushed. In case
one considers these debug/warning messages more critical than the
normal RTT reports, it may be worth considering pushing them through a
separate channel to make it less likely that they are lost.

## RTT-based cleanup of timestamp entries
For most flows the RTT will likely be well below one second, which
allows for removing timestamp entries much earlier than the 10s static
limit. This helps keep the timestamp map size down, thereby decreasing
the risk of there being no room for new entries as well as reducing
the number of entries the cleanup process must go through. However, if
the RTT for a flow grows quickly (due to ex. buffer bloat) then the
actual RTT of the flow may increase to beyond 8 times the initial RTT
before ePPing has collected enough RTT samples to increase sRTT to a
similar level. This may cause timestamps being deleted too early
before they have time to actually match against a reply, in which case
one also loses the RTT sample that would be used to update the sRTT
causing the sRTT to remain too low.

In practice this issue is limited by the fact that the cleanup process
only runs periodically, so even for flows with a very low RTT the
average time to delete a timestamp entry would still be 500ms (at
default rate of running at 1Hz). But this also limits the usefulness
of trying to delete entries earlier.

Overall, a better approach in the future might be to get rid of the
periodic cleanup process entirely, and instead only evict old entries
if they're blocking a new entry from being inserted. This would be
similar to using LRU maps, but would need some way to prevent an
existing entry from being removed in case it's too young.

## Periodical map cleanup may miss entries on delete
Due to how the hash map traversal is implemented, all entries may not
be traversed each time a map is iterated through. Specifically, if an
entry is deleted and there are other entries remaining in the same
bucket, those remaining entries will not be traversed. As the
periodical cleanup may delete entries as it is traversing the map,
this may result in some of the entries which share the bucket
with deleted entries not always be traversed.

In general this should not cause a large problem as those entries will
simply be traversed the next time the map is iterated over
instead. However, it may cause certain entries to remain in the hash
map a bit longer than expected (and if the map is full subsequently
block new entries from being created for that duration)


## Concurrency issues

The program uses "global" (not `PERCPU`) hash maps to keep state. As
the BPF programs need to see the global view to function properly,
using `PERCPU` maps is not an option. The program must be able to
match against stored packet timestamps regardless of the CPU the
packets are processed on, and must also have a global view of the flow
state in order for the sampling to work correctly.

As the BPF programs may run concurrently on different CPU cores
accessing these global hash maps, this may result in some concurrency
issues. In practice, I do not believe these will occur particularly
often as the hash-map entries are per-flow, and I'm under the
impression that packets from the same flow will typically be processed
by the same CPU. Furthermore, most of the concurrency issues will not
be that problematic even if they do occur. For now, I've therefore
left these concurrency issues unattended, even if some of them could
be avoided with atomic operations and/or spinlocks, in order to keep
things simple and not hurt performance.

The (known) potential concurrency issues are:

### Tracking last seen identifier
The tc/egress program keeps track of the last seen outgoing identifier
for each flow, by storing it in the `flow_state` map. This is done to
detect the first packet with a new identifier. If multiple packets are
processed concurrently, several of them could potentially detect
themselves as being first with the same identifier (which only matters
if they also pass rate-limit check as well), alternatively if the
concurrent packets have different identifiers there may be a lost
update (but for TCP timestamps, concurrent packets would typically be
expected to have the same timestamp).

### Rate-limiting new timestamps
In the tc/egress program packets to timestamp are sampled by using a
per-flow rate-limit, which is enforced by storing when the last
timestamp was created in the `flow_state` map. If multiple packets
perform this check concurrently, it's possible that multiple packets
think they are allowed to create timestamps before any of them are
able to update the `last_timestamp`. When they update `last_timestamp`
it might also be slightly incorrect, however if they are processed
concurrently then they should also generate very similar timestamps.

If the packets have different identifiers, (which would typically not
be expected for concurrent TCP timestamps), then this would allow some
packets to bypass the rate-limit. By bypassing the rate-limit, the
flow would use up some additional map space and report some additional
RTT(s) more than expected (however the reported RTTs should still be
correct).

If the packets have the same identifier, they must first have managed
to bypass the previous check for unique identifiers (see [previous
point](#tracking-last-seen-identifier)), and only one of them will be
able to successfully store a timestamp entry.

### Matching against stored timestamps
The XDP/ingress program could potentially match multiple concurrent
packets with the same identifier against a single timestamp entry in
`packet_ts`, before any of them manage to delete the timestamp
entry. This would result in multiple RTTs being reported for the same
identifier, but if they are processed concurrently these RTTs should
be very similar, so would mainly result in over-reporting rather than
reporting incorrect RTTs.

### Updating flow statistics
Both the tc/egress and XDP/ingress programs will try to update some
flow statistics each time they successfully parse a packet with an
identifier. Specifically, they'll update the number of packets and
bytes sent/received. This is not done in an atomic fashion, so there
could potentially be some lost updates resulting an underestimate.

Furthermore, whenever the XDP/ingress program calculates an RTT, it
will check if this is the lowest RTT seen so far for the flow. If
multiple RTTs are calculated concurrently, then several could pass
this check concurrently and there may be a lost update. It should only
be possible for multiple RTTs to be calculated concurrently in case
either the [timestamp rate-limit was
bypassed](#rate-limiting-new-timestamps) or [multiple packets managed
to match against the same
timestamp](#matching-against-stored-timestamps).

It's worth noting that with sampling the reported minimum-RTT is only
an estimate anyways (may never calculate RTT for packet with the true
minimum RTT). And even without sampling there is some inherent
sampling due to TCP timestamps only being updated at a limited rate
(1000 Hz).

### Outputting flow opening/closing events
A flow is not considered opened until a reply has been seen for
it. The `flow_state` map keeps information about if the flow has been
opened or not, which is checked and updated for each reply. The check
and update of this information is not performed atomically, which may
result in multiple replies thinking they are the first, emitting
multiple flow-opened events, in case they are processed concurrently.

Likewise, when flows are closed it checks if the flow has been opened
to determine if a flow closing message should be sent. If multiple
replies are processed concurrently, it's possible one of them will
update the flow-open information and emit a flow opening message, but
another reply closing the flow without thinking it's ever been opened,
thus not sending a flow closing message.

### Reporting global counters
While the global counters use per-CPU maps, and are therefore safe to
concurrently update in the BPF programs, there is no synchronization
between the BPF programs updating these stats and the user space
fetching them. It is therefore possible that the user space reports
these counters in an inconsistent state, i.e. a BPF program may only
have updated a subset of all the counters it will update by the time
the user space process fetches the map. For example, a BPF program
could have updated the packet count but not the byte count when user
space reports the stats. In practice these errors should be very
small, and any updates missed in one report will be included in the
next, i.e. it has eventual consistency.

This problem could be avoided by using two instances of the maps and
swapping between them (as done by the aggregation stats), however such
a solution is a fair bit more complex, and has slightly more overhead
(needs to perform an initial map lookup to determine which instance of
a map it should update).
