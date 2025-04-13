FROM ubuntu:24.04

# Safe dependency installation
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    build-essential \
    meson \
    ninja-build \
    python3-pyelftools \
    libnuma-dev \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

# Non-root user setup
RUN useradd -m dpdk && \
    mkdir -p /app && \
    chown -R dpdk:dpdk /app

USER dpdk
WORKDIR /app

# DPDK build with Meson
COPY --chown=dpdk:dpdk . .
RUN meson setup build && \
    ninja -C build