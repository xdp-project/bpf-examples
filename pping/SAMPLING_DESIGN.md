# Introduction
This file is intended to document some of the challenges and design
decisions for adding sampling functionality to pping.

## Purpose of sampling
The main purpose of adding sampling to pping is to prevent a massive
amount of timestamp entries being created and quickly filling up the
map. This prevents new entries from being made until old ones can be
cleared out. A few large flows could thus "hog" all the map entries,
and prevent RTTs from other flows from being reported. Sampling is
therefore only used on egress to determine if a timestamp entry should
be created for a packet. All packets on ingress will still be parsed
and checked for a potential match.

A secondary purpose of the sampling is the reduce the amount of output
that pping creates. In most circumstances, getting 1000 RTT reports
per second from a single flow will probably not be of interest, making
it less useful as a direct command-line utility.

# Considered sampling approaches
There are a number of different ways that the sampling could be
performed, ex:

- Sample every N packets per flow
  - Not very flexible
  - If same rate is used for all flows small flows would get very few
    samples.
- Sample completely random packets
  - Probably not a good idea...
- Probabilistic approach
  - Probabilistic approaches have been used to for example capture
    most relevant information with limited overhead in INT
  - Could potentially be configured across multiple devices, so that
    pping on all of the devices together capture the most relevant
    traffic.
  - While it could potentially work well, I'm not very familiar with
    these approaches. Would take considerable research from my side
    to figure out how these methods work, how to best apply it to
    pping, and how to implement it in BPF.
- Used time-based sampling, limiting the rate of how often entries
  can be created per flow
  - Intuitively simple
  - Should correspond quite well with the output you would probably
    want? I.e. a few entries per flow (regardless of how heavy they
    are) stating their current RTT.

I believe that time-based sampling is the most promising solution that
I can implement in a reasonable time. In the future additional
sampling methods could potentially be added.

# Considerations for time-based sampling
## Time interval
For the time-based sampling, we must determine how the interval
between when new timestamp entries are allowed should be set. 

### Static time interval
The simplest alternative is probably to use a static limit, ex
100ms. This would provide a rather simple and predictable limit for
how often entries can be created (per flow), and how much output you
would get (per flow).

### RTT-based time interval
It may be desirable to use a more dynamic time limit, which is
adapted to each flow. One way to do this, would be do base the time
limit on the RTT for the flow. Flows with short RTTs could be expected
to undergo more rapid changes than flows with long RTTs. This would
require keeping track of the RTT for each flow, for example a moving
average. Additionally, some fall back is required before the RTT for
the flow is known.

### User configurable
Regardless if a static or RTT-based (or some other alternative) is
used, it should probably be user configurable (including allowing the
user to disable to sampling entirely).

## Allowing bursts
It may be desirable to allow to allow for multiple packets in a short
burst to be timestamped. Due to delayed ACKs, one may only get a
response for every other packet. If the first packed is timestamped,
and shortly after a second packet is sent (that has a different
identifier), then the response will effectively be for the second
packet, and no match for the timestamped identifier will be found. For
flows of the right (or wrong depending on how you look at it)
intensity, slow enough where consecutive packets are likely to get
different TCP timestamps, but fast enough for the delayed ACKs to
acknowledge multiple packets, then you essentially have a 50/50 chance
of timestamping the wrong identifier an miss the RTT. 

## Handing duplicate identifiers
TCP timestamps are only updated at a limited rate (ex. 1000 Hz), and
thus you can have multiple consecutive packets with the same TCP
timestamp if they're sent fast enough. For the calculated RTT to be
correct, you should only match the first sent packet with a unique
identifier with the first received packet with a matching
identifier. Otherwise, you may for example have a sequence with 100
packets with the same identifier, and match the last of the outgoing
packets with the first incoming response, which may underestimate the
RTT with as much as the TCP timestamp clock rate (ex. 1 ms). 

### Current solution
The current solution to this is very simple. For outgoing packets, a
timestamp entry is only allowed to be created if no previous entry for
the identifier exists (realized through the BPF_NOEXIST flag to
bpf_map_update_elem() call). Thus only the first outgoing packet with
a specific identifier can be timestamped. On egress, the first packet
with a matching identifier will mark the timestamp as used, preventing
later incoming responses from using that timestamp. The reason why the
timestamp is marked as used rather than directly deleted once a
matching packet on ingress is found, is to avoid the egress side
creating a new entry for the same identifier. This could occur if the
RTT is shorter than the TCP timestamp clock rate, and could result in
a massively underestimated RTT. This is the same mechanic that is used
in the original pping, as explained
[here](https://github.com/pollere/pping/blob/777eb72fd9b748b4bb628ef97b7fff19b751f1fd/pping.cpp#L155-L168).

### New solution
The current solution will no longer work if sampling is
introduced. With sampling, there's no guarantee that the sampled
packed will be the first outgoing packet in the sequence of packets
with identical timestamps. Thus the RTT may still be underestimated by
as much as the TCP timestamp clock rate (ex. 1 ms). Therefore, a new
solution is needed. The current idea is to keep track of what the most
recent identifier of each flow is, and only allow a packet to be
sampled for timestamping if its identifier differs from the tracked
identifier of the flow, i.e. it is the first packet in the flow with
that identifier. This would perhaps be problematic with some sampling
approaches as it requires that the packet is both the first one with a
specific identifier, as well as being elected for sampling. However
for the rate-limited sampling it should work quite well, as it will
only delay the sampling until a packet with a new identifier is found.

Another advantage with this solution is that it should allow for
timestamp entries to be deleted as soon as the matching response is
found on egress. The timestamp no longer needs to be kept around only
to prevent egress to create a new timestamp with the same identifier,
as this new solution should take care of that. This would help a lot
with keeping the map clean, as the timestamp entries would then
automatically be removed as soon as they are no longer needed. The
periodic cleanup from userspace would only be needed to remove the
occasional entries that were never matched for some reason (e.g. the
previously mentioned issue with delayed ACKs, flow stopped, the
reverse flow can't be observed etc.).

# Implementation considerations
TODO (can partly be found in
[status-slides](https://github.com/xdp-project/bpf-research/blob/master/meetings/simon/work_summary_20210222.org))
## "Global" vs PERCPU maps
## Concurrency issues
## Global variable vs single-entry map





