#!/bin/sh
# softKMS Docker Entrypoint Script
# Handles initialization and startup in container environments

set -e

# Default values
SOFTKMS_CONFIG="${SOFTKMS_CONFIG:-/etc/softkms/config.toml}"
SOFTKMS_LOG_LEVEL="${SOFTKMS_LOG_LEVEL:-info}"
SOFTKMS_STORAGE_PATH="${SOFTKMS_STORAGE_PATH:-/var/lib/softkms}"

# Create config directory if it doesn't exist
if [ ! -d "/etc/softkms" ]; then
    mkdir -p /etc/softkms
fi

# Create default config if none exists
if [ ! -f "$SOFTKMS_CONFIG" ]; then
    echo "Creating default configuration at $SOFTKMS_CONFIG"
    cat > "$SOFTKMS_CONFIG" <<EOF
[storage]
backend = "file"
path = "$SOFTKMS_STORAGE_PATH"

[storage.encryption]
pbkdf2_iterations = 210000

[api]
grpc_addr = "0.0.0.0:50051"
rest_addr = "0.0.0.0:8080"
enable_pkcs11 = false

[logging]
level = "$SOFTKMS_LOG_LEVEL"
EOF
fi

# Ensure storage directory exists and is owned by softkms user
if [ ! -d "$SOFTKMS_STORAGE_PATH" ]; then
    mkdir -p "$SOFTKMS_STORAGE_PATH"
fi

# Create PID directory
if [ ! -d "/var/run/softkms" ]; then
    mkdir -p /var/run/softkms
fi

# If running as root, fix permissions
if [ "$(id -u)" = "0" ]; then
    chown -R softkms:softkms "$SOFTKMS_STORAGE_PATH"
    chown -R softkms:softkms /var/run/softkms
fi

# Handle health check
if [ "$1" = "--health-check" ]; then
    # Simple health check - try to connect to gRPC port
    if nc -z localhost 50051 2>/dev/null; then
        echo "Health check passed"
        exit 0
    else
        echo "Health check failed: daemon not responding"
        exit 1
    fi
fi

# Handle special commands
if [ "$1" = "--version" ] || [ "$1" = "-v" ]; then
    exec softkms-daemon --version
fi

if [ "$1" = "--help" ] || [ "$1" = "-h" ]; then
    exec softkms-daemon --help
fi

# Default: start daemon
exec softkms-daemon \
    --config "$SOFTKMS_CONFIG" \
    --foreground \
    --log-level "$SOFTKMS_LOG_LEVEL" \
    "$@"
