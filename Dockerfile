# Multi-stage build for Amadeus Node
# Optimized for Confidential Containers deployment

# Build stage
FROM rust:1.75-slim AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    pkg-config \
    libssl-dev \
    libclang-dev \
    libzstd-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Copy workspace files
COPY Cargo.toml Cargo.lock ./
COPY amadeus-utils ./amadeus-utils
COPY amadeus-runtime ./amadeus-runtime
COPY amadeus-node ./amadeus-node
COPY amadeus-cli ./amadeus-cli
COPY amadeusd ./amadeusd
COPY http ./http
COPY assets ./assets

# Build the node binary (release mode for production)
RUN cargo build --release -p amadeusd --bin amadeusd

# Runtime stage
FROM debian:bookworm-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    libzstd1 \
    && rm -rf /var/lib/apt/lists/*

# Create amadeus user for running the node
RUN useradd -m -u 1000 -s /bin/bash amadeus

WORKDIR /home/amadeus

# Copy the compiled binary from builder
COPY --from=builder /build/target/release/amadeusd /usr/local/bin/amadeusd

# Create data directory
RUN mkdir -p /home/amadeus/.amadeusd-rs && \
    chown -R amadeus:amadeus /home/amadeus

# Switch to non-root user
USER amadeus

# Expose ports
# P2P port (UDP)
EXPOSE 36969/udp
# HTTP API/Dashboard port
EXPOSE 3000/tcp

# Environment variables with defaults
ENV UDP_ADDR=0.0.0.0:36969 \
    HTTP_PORT=3000 \
    RUST_LOG=info \
    WORKFOLDER=/home/amadeus/.amadeusd-rs

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:${HTTP_PORT}/health || exit 1

# Run the node
ENTRYPOINT ["/usr/local/bin/amadeusd"]
