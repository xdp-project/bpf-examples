# Introduction
This file is intended to document some of the challenges and design
decisions for adding sampling functionality to pping. It is partly
based on discussions from my supervisor meeting on 2021-02-22, and the
contents of my 
[status slides](https://github.com/xdp-project/bpf-research/blob/master/meetings/simon/work_summary_20210222.org)
from that meeting.

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
- Head sampling (sample the first few packets of each flow)
  - Not suitable for monitoring long flows
  - RTT may change over lifetime of flow (due to buffer bloat)
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
user to disable sampling entirely).

## Allowing bursts
It may be desirable to allow to allow for multiple packets in a short
burst to be timestamped. Due to delayed ACKs, one may only get a
response for every other packet. If the first packed is timestamped,
and shortly after a second packet is sent (that has a different
identifier), then the response will effectively be for the second
packet, and no match for the timestamped identifier will be found. For
flows of the right (or wrong, depending on how you look at it)
intensity, slow enough where consecutive packets are likely to get
different TCP timestamps, but fast enough for the delayed ACKs to
acknowledge multiple packets, then you essentially have a 50/50 chance
of timestamping the wrong identifier and miss the RTT.

To handle this, you could timestamp multiple consecutive packets (with
unique indentifiers) in a short burst. You probably need to limit this
burst in both number of packets, as well as timeframe after the first
packet that additional packets may be included. For example, allowing
up to 3 packets (with different identifiers) get a timestamp for up to
4 ms after the first one of them are timestamped.

If allowing bursts of timestamps to be created, it may also be
desirable to rate limit the output, in order to not get a burst of
similar RTTs for the flow in the output (which may also skew averages
and other post-processing).

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
the identifier exists (realized through the `BPF_NOEXIST` flag to
`bpf_map_update_elem()` call). Thus only the first outgoing packet with
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
solution is needed. The current idea is to keep track of the last-seen
identifier of each flow, and only allow a packet to be sampled for
timestamping if its identifier differs from the last-seen identifier
of the flow, i.e. it is the first packet in the flow with that
identifier. This would perhaps be problematic with some sampling
approaches as it requires that the packet is both the first one with a
specific identifier, as well as being elected for sampling. However
for the rate-limited sampling it should work quite well, as it will
only delay the sampling until a packet with a new identifier is found.

Another advantage with this solution is that it should allow for
timestamp entries to be deleted as soon as the matching response is
found on ingress. The timestamp no longer needs to be kept around only
to prevent egress to create a new timestamp with the same identifier,
as this new solution should take care of that. This would help a lot
with keeping the map clean, as the timestamp entries would then
automatically be removed as soon as they are no longer needed. The
periodic cleanup from userspace would only be needed to remove the
occasional entries that were never matched for some reason (e.g. the
previously mentioned issue with delayed ACKs, flow stopped, the
reverse flow can't be observed etc.).

One issue for this new solution is handling out-of-order packets. If
an entry with an older identifier is a bit delayed, it may arrive after
the last seen identifier for the flow has been updated. This old
identifier may then be considered new (as it differs from the current
one), allowing an entry to be created for it and reverting the last
seen identifier to a previous one. Additionally, this may
now allow the next packet having what used to be the current
identifier, also being detected as a new identifier (as the out-of
order packet reverted the last-seen identifier to an old one, creating
a bit of a ping-pong effect). For TCP timestamps this can easily be
avoided by simply requiring the new identifier to be greater than the
last-seen identifier (as TCP timestamps should be monotonically
increasing). That solution may however not be suitable if one wants to
reuse this mechanic for other protocols, such as the QUIC spinbit.

## Keeping per-flow information
In order for the per-flow rate limiting to work, some per-flow state
must be maintained, namely when the last timestamp for that flow was
added (so that one can check that sufficient time has passed before
attempting to add another one).

There may be some drawbacks with having to keep per-flow state. First
off, there will be some additional overhead from having to keep track
of this state. However, the savings from sampling the per-packet state
(the identifier/timestamps mappings) should hopefully cover the
overhead from keeping some per-flow state (and then some). 

Another issue that is worth keeping in mind is that this flow-state
will also need to be cleaned up eventually. This cleanup could be
handled in a similar manner as the current per-packet state is cleaned
up, by having the userspace process occasionally remove old
entries. In this case, the entries could be deemed as old if there was
a long time since the last timestamp was added for the flow, ex 300
seconds as used by the [original
pping](https://github.com/pollere/pping/blob/777eb72fd9b748b4bb628ef97b7fff19b751f1fd/pping.cpp#L117).
Additionally, one can parse the packets for indications that the
connection is being closed (ex TCP FIN/RST), and then directly delete
the flow-state for that flow from the BPF programs.

Later on, this per-flow state could potentially be expanded to include
other information deemed useful (such as ex. minimum and average RTT).

### Alternative solution - keeping identifier in flow-state
One idea that came up during my supervisor meeting, was that instead
of creating timestamps for individual packets as is currently done,
you only create a number of timestamps for each flow. That is, instead
of creating per-packet entries in a separate map, you include a number
of timestamp/identifier pairs in the flow-state information itself.

While this would potentially be rather efficient, limiting the number
of timestamp entries to a fixed number per flow, I'm opposed to this
idea for a few reasons:

1. The sampling rate would be inherently tied to the RTT of the
   flow. While this may in many cases be desirable, it is not very
   flexible. It would also make it hard to ex. turn of sampling
   completely.
2. The number of timestamps per flow would need to be fixed and known
   at compile time(?). As the timestamps/identifier pairs are kept in
   the state-flow information itself, and the state-flow information
   needs to be of a known and fixed size when creating the maps. This
   may also result in some wasted space if the flow-state includes
   spots for several timestamp/identifier pairs, but most flows only
   makes use of a few (although having an additional timestamp entry
   map of fixed size wastes space in a similar manner).
2. If a low number of timestamp/identifier pairs are kept, selecting
   an identifier that is missed (ex due to delayed ACKs) could
   effectivly block new timestamps from being created (and thus from
   RTTs being calculated) for the flow for a relatively long
   while. New timestamps can only be created if you have a free slot,
   and you can only free a slot by either getting a matching reply, or
   waiting until it can be safely assumed that the response was missed
   (and not just delayed).

## Graceful degradation
Another aspect I've been asked to consider is how to gracefully reduce
the functionality of pping as the timestamp entry map gets full (as
with sufficiently many and heavy flows, it's likely inevitable).

What currently happens when the timestamp entry map is full, is simply
that no more entries can be made until some have been cleared
out. When adding a rate-limit to the number of entries per flow, as
well as directly deleting entries upon match, I believe this is a
reasonable way to handle the situation. As soon as some RTTs for
current flows have been reported, space for new entries will be
available. The next outgoing packet with a valid identifier from any
flow that does not have to currently wait for its rate limit will then
be able to grab the next spot. However this will still favor heavy
flows over smaller flows, as heavy flows are more likely to be able to
get in a packet first, but they will at least still be limited by the
rate limit, and thus have to take turns with other flows.

It also worth noting that as per-flow state will need to be kept,
there will be strict limit to the number of concurrent flows that can
be monitored, corresponding to the number of entries that can be held
by the map for the per-flow state. Once the per-flow state map is
full, no new flows can be added until one is cleared. It also doesn't
make sense to add packet timestamp entries for flows which state
cannot be tracked, as the rate limit cannot be enforced then.

I see a few ways to more actively handle degradation, depending on what
one views as desirable:

1. One can attempt to monitor many flows, with infrequent RTT
   calculations for each. In this case, the userspace process that
   occasionally clears out the timestamp map could automatically
   decrease the per-flow rate limit if it detects the map is getting
   close to full. That way, fewer entries would be generated per flow,
   and flows would be forced to take turns to a greater degree when
   the map is completely full. Similarly, one may wish to reduce the
   timeout for old flows if the per-flow map is getting full, in order
   to more quickly allow new flows to be monitored, and only keeping
   the most active flows around.
2. One can attempt to monitor fewer flows, but with more frequent RTT
   calculations for each. The easiest way to achieve this is to
   probably to set a smaller size on the per-flow map relative to the
   per-packet timestamp map. In case one wants to primarily focus on
   heavier flows, one could possibly add ex. packet rate to the
   per-flow information, and remove the flows with the lowest packet
   rates.
3. One can attempt to focus on flows with shorter RTTs. Flows with
   shorter RTTs should make more efficient use of timestamp entries,
   as they can be cleared out faster allowing for new entries. On the
   other hand, flows with longer RTTs may be the more interesting
   ones, as they are more likely to indicate some issue.
4. One can simply try to create a larger map (and copy over the old
   contents) once the map is approaching full. This way one can start
   with reasonably small maps, and only start eating up more memory if
   required. 

While I'm leaning towards option 1 or 4, I don't have a very strong
personal opinion here, and would like some input on what others (who
may have more experience with network measurements) think are
reasonable trade-offs to do.

# Implementation considerations
There are of course several more practical considerations as well when
implementing the sampling, some of which I'll try to address here.

## "Global" vs PERCPU maps
In general, it's likely wise to go with PERCPU maps over "global" (aka
non-PERCPU) maps whenever possible, as PERCPU maps should be more
performant, and also avoids concurrency issues. But this only applies
of course, if the BPF programs don't need to act on global state.

For pping, I unfortunately see no way for the program to work with
only information local to each CPU core individually. The per-packet
identifier and timestamps need to be global, as there is no guarantee
that the same core that timestamped a packet will process the response
for that packet. Likewise, the per-flow information, like the time of
the last timestamping, also needs to be global. Otherwise rate limit
would be per-CPU-per-flow rather than just per-flow.

In practice, packets from the same flow are apparently often handled
by the same CPU, but this is not guaranteed, and therefore not
something we can rely on (especially when state needs to be shared by
both ingress and egress). Could try to use a CPU map to enforce this
behavior, but probably not a great idea.

## Concurrency issues
In addition to the performance hit, sharing global state between
multiple concurrent processes risks running into concurrency issues
unless access is synchronized in some manner (in BPF, the two
mechanics I know of are atomic adds and spin-locks for maps). With the
risk of me misunderstanding the memory model for BPF programs (which
from what I can tell I'm probably not alone about), I will attempt to
explain the potential concurrency issues I see with the pping
implementation.

The current pping implementation already has a potential concurrency
issue. When matches for identifiers are found on ingress, a check is
performed to see if the timestamp has already been used or
not. Multiple packets processed in parallel could potentially all
find that the timestamp is unused, before any of them manage to mark
it as used for the others. This may result in pping matching several
responses to a single timestamp entry and reporting the RTTs for each
of them. I do not consider this a significant issue however, as if
they are concurrent enough that they manage to lookup the used status
before another has time to set it, the difference in time between them
should be very small, and therefore compute very similar RTTs. So the
reported RTTs should still be rather accurate, just over-reported.

When adding sampling and per-flow information, some additional
concurrency issues may be encountered. Mainly, multiple packets may
find that they are allowed to add a new timestamp, before they manage
to update the time of last added time-stamp in the per-flow
state. This may lead to multiple attempts at creating a timestamp at
approximately the same time. For TCP timestamps, all the identifiers
are likely to be identical (as the TCP timestamp itself is only
updated at limited rate), so only one of them should succeed
anyways. If using identifiers that are more unique however, such as
TCP sequence numbers, then it's possible that a short burst of entries
would be created instead of just a single entry within the rate-limit
for the flow.

Overall, I don't think these concurrency issues are that severe, as
they should still result in accurate RTTs, just some possible
over-reporting. I don't believe these issues warrants the performance
impact and potential code complexity of trying to synchronize
access. Furthermore, from what I understand these concurrency issues
are not too likely to occur in reality, as packets from the same flow
are often processed on the same core.

## Global variable vs single-entry map
With BTF, there seems like BPF programs now support the use of global
variables. These global variables can supposedly be modified from user
space, and should from what I've heard also be more efficient than map
lookups. They therefore seem like promising way to pass some
user-configured options from userspace to the BPF programs.

I would however need to lookup how to actually use these, as the
examples I've seen have used a slightly different libbpf setup, where
a "skeleton" header-file is compiled and imported to the userspace
program. There should be some examples in the [xdp-tools
repository](https://github.com/xdp-project/xdp-tools).

The alternative I guess would be to use a
`BPF_MAP_TYPE_PERCPU_ARRAY` with a single entry, which is filled in
with the user-configured option by the userspace program.





