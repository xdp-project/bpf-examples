# TODO

## For initial merge
- [x] Clean up commits and add signed-off-by tags
- [x] Add SPDX-license-identifier tags
- [x] Format C-code in kernel style
- [x] Use existing funcionality to reuse maps by using BTF-defined maps
  - [ ] Use BTF-defined maps for TC-BPF as well if iproute has libbpf support

## Future
- [ ] Use libxdp to load XDP program
- [x] Cleanup: Unload TC-BPF at program shutdown, and unpin map - In userspace part
- [ ] Add IPv6 support - In TC-BPF, XDP and userspace part
- [ ] Check for existance of reverse flow before adding to hash-map (to avoid adding timestamps for flows that we can't see the reverse traffic for) - In TC-BPF part
  -  This could miss the first few packets, would not be ideal for short flows
- [ ] Keep track of minimum RTT for each flow (done by Pollere's pping, and helps identify buffer bloat) - In XDP part
- [ ] Add configurable rate-limit for how often each flow can add entries to the map (prevent high-rate flows from quickly filling up the map) - In TCP-BPF part
- [ ] Improve map cleaning: Use a dynamic time to live for hash map entries based on flow's RTT, instead of static 10s limit - In TC-BPF, XDP and userspace
