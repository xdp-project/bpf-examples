# Considerations for measurement study
There are a number of considerations to think about before we deploy pping for a
measurement study.

## How to save the results?
When running pping locally, just piping the output the JSON output mode to a
file seems like the easiest solution to me and should be sufficient. However, if
we deploy this at some ISP's router I guess they may not want us to store a
massive JSON-file on the router. So I guess we would then either have to
directly stream it to some other storage, or at least occasionally transfer the
output.

Furthermore, should the JSON output be used at all, or should we instead try to
integrate it with some database or Kafka stream or something? I have very little
experience with deploying and running experiments on other people's machines, so
I'm very open to suggestions here.

## What information do we need?
The main-purpose of pping is of course to monitor RTTs. But there may be
additional information that can be useful or relevant for that. For example, it
may be interesting to try and correlate RTTs with traffic intensity, and then it
would be useful to also log ex. nr. of sent and received packets and bytes
(which is something I plan on implementing soon).

There's also the question of minimizing data-collection (only collect what we
know we need, in the GDPR spirit), or collect as much as possible and see if
anything of it turns out to be interesting later when analyzing the result.

As a bit of a side-effect, pping also ends up mapping out all the (TCP) traffic
flows. While this can of course be interesting from some aspects, it's likely
something we may want to anonymize in this case.

### Anonymizing flows
As IP addresses are considered personal identifiers, it's probably something we
want to avoid collecting (and something I also guess the ISP may not want us
logging).

So the question is how we should do this? The easiest way would probably be to
do it with post-processing, but then we optimally need to run this
post-processing before we ever get hold of the data.

Furthermore, to what degree should the anonymization be done? IP-addresses can
contain some potentially useful information, for example are these public or
private IP-addresses (depending on where the router is deployed and if
carrier-grade NAT is used). IP-addresses can typically also be mapped to a
geographical area, which could be of interest if one wants to try and correlate
RTTs with distance between hosts.

Additionally, should only the IP-addresses by anonymized, or should the ports be
to? The ports could reveal to a certain degree what type of services the traffic
is for, which may or may not be interesting. And if they are to be anonymized,
should that be done independently from the IP-addresses (so that one can still
map how different anonymized hosts are mapped to each other), or should each
flow-tuple be anonymized as a whole?

## What to analyze?
Perhaps one of the most important questions is why are we collecting these
measurements? What do we hope to get out of them? What are we analyzing them
for?

My initial thoughts there would be to mainly look for variations in RTTs within
a flow to see indications of buffer-bloat, and possibly try to look at how that
correlates with the traffic load. But I should probably read some more papers on
this topic first to get an idea what other's have already done.

Another interesting aspect is of course the performance of pping. Our hope is to
make it something that can be always on, but does this version of it achieve
that? How much more efficient is it than Kathie's pping? To do this we should
probably setup some type of synthetic benchmark where we can compare some
different scenarios (single heavy flow, multiple heavy flow, massive amount of
flows etc.).
