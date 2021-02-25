# TODO

## Protocols
- [x] TCP (based on timestamp options)
  - [x] Skip pure ACKs for egress
    - Timestamping pure ACKs may lead to erroneous RTTs (ex. delay between application attempting to send data being recognized as an RTT)
  - [ ] Add fallback to SEQ/ACK in case of no timestamp?
    - Some machines may not use TCP timestamps (either not supported at all, or disabled as in ex. Windows 10)
    - If one only considers SEQ/ACK (and don't check for SACK options), could result in ex. delay from retransmission being included in RTT
- [ ] ICMP (ex Echo/Reply)
- [ ] QUIC (based on spinbit)

## General pping
- [ ] Add sampling so that RTT is not calculated for every packet (with unique value) for large flows
  - This serves two purposes, limiting the output from pping and reducing the rate at which the timestamp map grows (making it less likely to become full)
  - Will likely be based on a per-flow rate limit
- [ ] Keep some per-flow state
  - Will likely be needed for the sampling
  - [ ] Could potentially include keeping track of average RTT, which may be useful for some decisions (ex. how often to sample, when entry can be removed etc)
  - [ ] Could potentially include keeping track of minimum RTT (as done by the original pping), ex. to track bufferbloat
  - [ ] Could potentially include keeping track of if flow is bi-directional
    - Original pping checks if flow is bi-directional before adding timestamps, but this could miss shorter flows
- [ ] Improve map cleaning: Use a dynamic time to live for map entries based on flow's RTT, instead of static 10s limit
  - Keeping entries around for a long time allows the map to grow unnecessarily large, which slows down the cleaning and may block new entries
- [ ] Add support for automatically deleting entries if they are unique
  - TCP timestamp need to be kept for a while so only first packet with unique value is timestamped. For identifiers that are unique per packet, they can be removed directly after RTT is calculated
  - Once sampling is introduced, keeping entry around will not be sufficient to guarantee only timestamping first packet. May at that point remove every entry once RTT is calculated.
- [ ] Use libxdp to load XDP program
- [ ] Add option for machine-readable output (as original pping)
- [ ] Add timestamps to output (as original pping)
- [ ] Add support for other hooks
  - Ex TC-BFP on ingress instead of XDP?

## Done
- [x] Clean up commits and add signed-off-by tags
- [x] Add SPDX-license-identifier tags
- [x] Format C-code in kernel style
- [x] Use existing functionality to reuse maps by using BTF-defined maps
  - [x] Use BTF-defined maps for TC-BPF as well if iproute has libbpf support
- [x] Cleanup: Unload TC-BPF at program shutdown, and unpin map - In userspace part
- [x] Add IPv6 support
- [x] Refactor to support easy addition of other protocols
