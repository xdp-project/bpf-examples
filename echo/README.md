# echo

Echo is an example that creates a TCP Echo Server using socket redirection.
For comparison, a simple (naive) TCP Echo Server is also provided.


## Prerequisites

1. Install a rust stable toolchain: `rustup install stable`
1. Install a rust nightly toolchain: `rustup install nightly`
1. Install bpf-linker: `cargo install bpf-linker`

## Running The eBPF Example

```bash
cargo xtask build-ebpf
cargo xtask run
```

## Running the Native Example

```bash
cargo run --bin echo-tokio
```

## Interacting with the Example

```bash
nc localhost 41234
```

Any data sent will be echoed back to the client