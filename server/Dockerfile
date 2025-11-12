# Rust Notary Server - Production-ready container

FROM rust:latest as builder

WORKDIR /app

# Install dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy manifests
COPY Cargo.toml Cargo.lock ./

# Cache dependencies
RUN mkdir src && \
    echo "fn main() {}" > src/main.rs && \
    cargo build --release && \
    rm -rf src

# Copy source code
COPY src ./src

# Build application
RUN cargo build --release

# ============================================================================
# Runtime Stage
# ============================================================================
FROM debian:bookworm-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd -m -u 1001 mlchain

WORKDIR /app

# Copy binary from builder
COPY --from=builder /app/target/release/ml-chain-server /app/server

# Set ownership
RUN chown -R mlchain:mlchain /app

# Switch to non-root user
USER mlchain

EXPOSE 3000

CMD ["./server"]
