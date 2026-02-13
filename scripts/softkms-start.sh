#!/bin/bash
# softKMS Daemon Start Script
# Starts the softKMS daemon with local user directories

set -e

# Configuration
SOFTKMS_HOME="${HOME}/.softKMS"
DATA_DIR="${SOFTKMS_HOME}/data"
RUN_DIR="${SOFTKMS_HOME}/run"
LOGS_DIR="${SOFTKMS_HOME}/logs"
CONFIG_FILE="${SOFTKMS_HOME}/config.toml"
PID_FILE="${RUN_DIR}/softkms.pid"

# Default daemon binary location
DAEMON_BIN="${DAEMON_BIN:-./target/release/softkms-daemon}"

# Create directories if they don't exist
mkdir -p "${DATA_DIR}" "${RUN_DIR}" "${LOGS_DIR}"

# Check if daemon is already running
if [ -f "${PID_FILE}" ]; then
    PID=$(cat "${PID_FILE}" 2>/dev/null)
    if [ -n "${PID}" ] && kill -0 "${PID}" 2>/dev/null; then
        echo "softKMS daemon is already running (PID: ${PID})"
        echo "Use './scripts/softkms-stop.sh' to stop it first"
        exit 1
    else
        # Stale PID file, remove it
        rm -f "${PID_FILE}"
    fi
fi

# Create default config if it doesn't exist
if [ ! -f "${CONFIG_FILE}" ]; then
    echo "Creating default configuration at ${CONFIG_FILE}"
    cat > "${CONFIG_FILE}" <<EOF
[storage]
backend = "file"
path = "${DATA_DIR}"

[storage.encryption]
pbkdf2_iterations = 210000

[api]
grpc_addr = "127.0.0.1:50051"
rest_addr = "127.0.0.1:8080"
enable_pkcs11 = false

[logging]
level = "info"
EOF
fi

echo "Starting softKMS daemon..."
echo "  Data directory: ${DATA_DIR}"
echo "  PID file: ${PID_FILE}"
echo "  Config: ${CONFIG_FILE}"
echo ""

# Start the daemon in background
# We use nohup to prevent SIGHUP when the terminal closes
# and redirect output to log file
# Note: We don't use --foreground here since we're starting it in background
nohup "${DAEMON_BIN}" \
    --config "${CONFIG_FILE}" \
    --storage-path "${DATA_DIR}" \
    --pid-file "${PID_FILE}" \
    --log-level info \
    > "${LOGS_DIR}/daemon.log" 2>&1 &

DAEMON_PID=$!

# Save PID to file
echo "${DAEMON_PID}" > "${PID_FILE}"

# Wait a moment to see if it started successfully
sleep 1

if kill -0 "${DAEMON_PID}" 2>/dev/null; then
    echo "softKMS daemon started successfully (PID: ${DAEMON_PID})"
    echo ""
    echo "APIs available at:"
    echo "  gRPC: 127.0.0.1:50051"
    echo "  REST: http://127.0.0.1:8080"
    echo ""
    echo "Health check: curl http://127.0.0.1:8080/health"
    echo "Logs: tail -f ${LOGS_DIR}/daemon.log"
    echo ""
    echo "To stop: ./scripts/softkms-stop.sh"
else
    echo "ERROR: Daemon failed to start"
    echo "Check logs: ${LOGS_DIR}/daemon.log"
    rm -f "${PID_FILE}"
    exit 1
fi
