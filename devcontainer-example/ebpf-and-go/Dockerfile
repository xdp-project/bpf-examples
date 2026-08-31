FROM mcr.microsoft.com/devcontainers/go:1.23-bookworm

RUN apt update

RUN apt install -y build-essential
RUN apt install -y pkg-config
RUN apt install -y clang
RUN apt install -y llvm
RUN apt install -y git
RUN apt install -y libelf-dev
RUN apt install -y libpcap-dev
RUN apt install -y iproute2
RUN apt install -y iputils-ping
RUN apt install -y linux-headers-generic
RUN apt install -y libbpf-dev
RUN apt install -y linux-libc-dev
RUN apt install -y cmake
RUN apt install -y libpcap-dev
RUN apt install -y libcap-ng-dev
RUN apt install -y libbfd-dev
RUN apt install -y gcc-multilib
RUN apt install -y m4
RUN ln -sf /usr/include/asm-generic/ /usr/include/asm
RUN apt install -y libcap-dev
RUN ln -sf /usr/local/go/bin/go /bin/go
RUN ln -sf /usr/include/asm-generic/ /usr/include/asm

RUN mkdir /sources/
WORKDIR /sources/
RUN git clone --recurse-submodules https://github.com/libbpf/bpftool.git
RUN make -C bpftool/src/ install
RUN git clone --recurse-submodules https://github.com/xdp-project/xdp-tools.git
RUN make -C xdp-tools/ install