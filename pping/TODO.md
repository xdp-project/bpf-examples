# TODO

## Protocols
- [x] TCP (based on timestamp options)
  - [ ] Skip pure ACKs for egress?
  - [ ] Add fallback to SEQ/ACK in case of no timestamp?
- [ ] ICMP (ex Echo/Reply)
- [ ] QUIC (based on spinbit)

## General pping
- [ ] Use libxdp to load XDP program
- [ ] Check for existance of reverse flow before adding to hash-map (to avoid adding identifiers for flows that we can't see the reverse traffic for)?
  -  This could miss the first few packets, would not be ideal for short flows
- [ ] Keep track of minimum RTT for each flow (done by Pollere's pping, and helps identify buffer bloat)
- [ ] Add configurable rate-limit for how often each flow can add entries to the map (prevent high-rate flows from quickly filling up the map)
- [ ] Improve map cleaning: Use a dynamic time to live for hash map entries based on flow's RTT, instead of static 10s limit
- [ ] Add support for automatically deleting entries if they are unique
  - TCP timestamp need to be kept for a while (because multiple packets can have the same timestamp), but for identifiers that are unique per packet, they can be removed directly after RTT is calculated

## Done
- [x] Clean up commits and add signed-off-by tags
- [x] Add SPDX-license-identifier tags
- [x] Format C-code in kernel style
- [x] Use existing funcionality to reuse maps by using BTF-defined maps
  - [x] Use BTF-defined maps for TC-BPF as well if iproute has libbpf support
- [x] Cleanup: Unload TC-BPF at program shutdown, and unpin map - In userspace part
- [x] Add IPv6 support
- [x] Refactor to support easy addition of other protocols
