# Standalone container for the binary-fuzzer tool.
# Builds AFL++ with QEMU mode, installs the Python CLI, and provides
# `binary-fuzz` on PATH. Mount your binary + seeds in and write the
# crash output to a host volume.
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential git wget curl ca-certificates \
        clang lld llvm \
        ninja-build cmake pkg-config \
        python3 python3-pip python3-dev \
        gcc-multilib g++-multilib \
        libglib2.0-dev libtool automake autoconf \
        bison flex \
    && rm -rf /var/lib/apt/lists/*

# Build AFL++ with QEMU and Frida modes.
ARG AFL_VERSION=v4.21c
RUN git clone --depth 1 --branch ${AFL_VERSION} https://github.com/AFLplusplus/AFLplusplus.git /opt/aflpp \
 && cd /opt/aflpp \
 && make distrib NO_NYX=1 \
 && cd qemu_mode && ./build_qemu_support.sh \
 && cd ../frida_mode && make \
 && cd .. && make install

WORKDIR /opt/binary-fuzzer
COPY pyproject.toml README.md ./
COPY binary_fuzzer ./binary_fuzzer
RUN pip3 install --no-cache-dir .

ENV PATH="/opt/aflpp:${PATH}"

ENTRYPOINT ["binary-fuzz"]
CMD ["--help"]
