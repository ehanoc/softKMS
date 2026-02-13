#!/bin/bash
# softKMS Daemon Stop Script
# Gracefully stops the softKMS daemon

set -e

# Configuration
SOFTKMS_HOME="${HOME}/.softKMS"
PID_FILE="${SOFTKMS_HOME}/run/softkms.pid"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to print colored output
print_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if PID file exists
if [ ! -f "${PID_FILE}" ]; then
    print_warn "PID file not found: ${PID_FILE}"
    print_info "Daemon may not be running or was started without PID file"
    exit 0
fi

# Read PID
PID=$(cat "${PID_FILE}" 2>/dev/null)

if [ -z "${PID}" ]; then
    print_error "PID file is empty"
    rm -f "${PID_FILE}"
    exit 1
fi

# Check if process exists
if ! kill -0 "${PID}" 2>/dev/null; then
    print_warn "Process ${PID} is not running (stale PID file)"
    rm -f "${PID_FILE}"
    exit 0
fi

print_info "Stopping softKMS daemon (PID: ${PID})..."

# Send SIGTERM for graceful shutdown
if kill -TERM "${PID}" 2>/dev/null; then
    # Wait for process to terminate
    TIMEOUT=10
    COUNT=0
    
    while kill -0 "${PID}" 2>/dev/null; do
        if [ ${COUNT} -ge ${TIMEOUT} ]; then
            print_warn "Daemon did not stop gracefully within ${TIMEOUT} seconds"
            print_info "Sending SIGKILL..."
            kill -KILL "${PID}" 2>/dev/null || true
            break
        fi
        sleep 1
        COUNT=$((COUNT + 1))
    done
    
    if ! kill -0 "${PID}" 2>/dev/null; then
        print_info "Daemon stopped successfully"
        rm -f "${PID_FILE}"
    else
        print_error "Failed to stop daemon"
        exit 1
    fi
else
    print_error "Failed to send signal to process ${PID}"
    exit 1
fi
