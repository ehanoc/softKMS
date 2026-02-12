# softKMS Docker Image
# Multi-stage build for minimal, secure container

# Stage 1: Build
FROM rust:1.75-bookworm as builder

WORKDIR /app

# Copy manifests
COPY Cargo.toml Cargo.lock ./
COPY cli/Cargo.toml ./cli/
COPY pkcs11-module/Cargo.toml ./pkcs11-module/

# Copy source code
COPY src ./src
COPY cli/src ./cli/src
COPY pkcs11-module/src ./pkcs11-module/src

# Build release binary
RUN cargo build --release --bin softkms-daemon

# Stage 2: Runtime
FROM debian:bookworm-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN groupadd -r softkms && useradd -r -g softkms -s /bin/false softkms

# Create data directory
RUN mkdir -p /var/lib/softkms && chown softkms:softkms /var/lib/softkms

# Copy binary from builder
COPY --from=builder /app/target/release/softkms-daemon /usr/local/bin/softkms-daemon

# Switch to non-root user
USER softkms

# Expose ports
EXPOSE 50051 8080

# Volume for data
VOLUME ["/var/lib/softkms"]

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD softkms-daemon --health-check || exit 1

ENTRYPOINT ["softkms-daemon"]
CMD ["--config", "/etc/softkms/config.toml"]
