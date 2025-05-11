# === Stage 1: Build DPDK ===
# Use an ARG for flexibility
ARG UBUNTU_VERSION=22.04
FROM ubuntu:${UBUNTU_VERSION} AS dpdk-builder

LABEL stage="dpdk-builder"

# Prevent interactive prompts
ENV DEBIAN_FRONTEND=noninteractive

# Install build essentials and DPDK dependencies
# Adjust dependencies based on your specific DPDK config/version if needed
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    meson \
    ninja-build \
    python3 \
    pkg-config \
    git \
    libpcap-dev \
    libnuma-dev \
    libatomic1 \
    && rm -rf /var/lib/apt/lists/*

# Set working directory for the build
WORKDIR /build

# Copy only the DPDK submodule source
COPY deps/dpdk /build/dpdk

# Build and install DPDK
# Note: Default install prefix is /usr/local
# Add any custom DPDK meson options if needed (e.g., -Dexamples=...)
WORKDIR /build/dpdk 
RUN meson setup build
RUN ninja -C build
RUN ninja -C build install
# Update linker cache within this build stage
RUN ldconfig

# === Stage 2: Build PoT Application ===
# Use the DPDK builder stage as the base
FROM dpdk-builder AS app-builder

LABEL stage="app-builder"

# Set working directory for the application
WORKDIR /app

# Copy the entire application source code
# Ensure you have a .dockerignore file to exclude .git, .venv, deps, build dirs etc.
COPY . /app

# Build the application
# Meson will find the pre-installed DPDK via pkg-config
RUN meson setup build
RUN ninja -C build
# The executable will be in /app/build/dpdk-pot based on your meson.build

# === Stage 3: Final Runtime Image ===
# Start from a clean Ubuntu base for the final image
FROM ubuntu:${UBUNTU_VERSION}

LABEL stage="runtime"

# Prevent interactive prompts
ENV DEBIAN_FRONTEND=noninteractive

# Install only essential runtime dependencies for DPDK
# libnuma1 is common, libpcap0.8 if using PCAP PMD (less likely for ENA)
RUN apt-get update && apt-get install -y --no-install-recommends \
    libnuma1 \
    libpcap0.8 \
    # Add other runtime libs if needed (e.g. libssl3 if crypto used)
    && rm -rf /var/lib/apt/lists/*

# Copy DPDK runtime libraries from the dpdk-builder stage
COPY --from=dpdk-builder /usr/local/lib/ /usr/local/lib/

# Copy the compiled application from the app-builder stage
COPY --from=app-builder /app/build/dpdk-pot /usr/local/bin/dpdk-pot

# Copy configuration files (adjust path as needed)
COPY config /etc/dpdk-pot/config

# Copy scripts (optional, if needed at runtime)
COPY scripts /opt/dpdk-pot/scripts

# Update linker cache to recognize the copied DPDK libraries
RUN ldconfig

# Set the working directory (optional)
WORKDIR /opt/dpdk-pot

# Define the default command to run when the container starts
# Add any necessary default arguments for your application
# You might override this command in docker-compose.yaml
CMD ["/usr/local/bin/dpdk-pot"]