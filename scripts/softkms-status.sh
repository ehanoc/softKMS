#!/bin/bash
# softKMS Daemon Status Script
# Shows the current status of the softKMS daemon

# Configuration
SOFTKMS_HOME="${HOME}/.softKMS"
PID_FILE="${SOFTKMS_HOME}/run/softkms.pid"
DATA_DIR="${SOFTKMS_HOME}/data"
LOGS_DIR="${SOFTKMS_HOME}/logs"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    local status=$1
    local message=$2
    if [ "${status}" = "running" ]; then
        echo -e "${GREEN}[RUNNING]${NC} ${message}"
    elif [ "${status}" = "stopped" ]; then
        echo -e "${RED}[STOPPED]${NC} ${message}"
    elif [ "${status}" = "warning" ]; then
        echo -e "${YELLOW}[WARNING]${NC} ${message}"
    else
        echo -e "${BLUE}[INFO]${NC} ${message}"
    fi
}

echo "========================================"
echo "softKMS Daemon Status"
echo "========================================"
echo ""

# Check if PID file exists
if [ ! -f "${PID_FILE}" ]; then
    print_status "stopped" "Daemon is not running (no PID file)"
    echo ""
    echo "To start: ./scripts/softkms-start.sh"
    exit 0
fi

# Read PID
PID=$(cat "${PID_FILE}" 2>/dev/null)

if [ -z "${PID}" ]; then
    print_status "warning" "PID file is empty: ${PID_FILE}"
    echo ""
    echo "Removing stale PID file..."
    rm -f "${PID_FILE}"
    exit 1
fi

# Check if process exists
if kill -0 "${PID}" 2>/dev/null; then
    print_status "running" "Daemon is running (PID: ${PID})"
    
    # Try to get more process info
    if command -v ps >/dev/null 2>&1; then
        echo ""
        echo "Process Info:"
        ps -p "${PID}" -o pid,ppid,cmd,etime 2>/dev/null | tail -1 || true
    fi
    
    # Check ports
    echo ""
    echo "Network Status:"
    if command -v netstat >/dev/null 2>&1; then
        netstat -tlnp 2>/dev/null | grep -E "50051|8080" || echo "  (Cannot determine port status)"
    elif command -v ss >/dev/null 2>&1; then
        ss -tlnp 2>/dev/null | grep -E "50051|8080" || echo "  (Cannot determine port status)"
    else
        echo "  (netstat/ss not available)"
    fi
    
    # Test health endpoint
    echo ""
    echo "Health Check:"
    if command -v curl >/dev/null 2>&1; then
        HEALTH=$(curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:8080/health 2>/dev/null || echo "failed")
        if [ "${HEALTH}" = "200" ]; then
            print_status "running" "REST API responding (HTTP 200)"
        else
            print_status "warning" "REST API not responding (HTTP ${HEALTH})"
        fi
    else
        echo "  (curl not available, cannot test health endpoint)"
    fi
    
    echo ""
    echo "Directories:"
    echo "  Data: ${DATA_DIR}"
    echo "  Logs: ${LOGS_DIR}"
    
    # Check data directory
    if [ -d "${DATA_DIR}" ]; then
        KEY_COUNT=$(find "${DATA_DIR}" -name "*.json" 2>/dev/null | wc -l)
        echo "  Keys stored: ${KEY_COUNT}"
    fi
    
    echo ""
    echo "To stop: ./scripts/softkms-stop.sh"
    
else
    print_status "stopped" "Daemon is not running (stale PID file: ${PID})"
    echo ""
    echo "Removing stale PID file..."
    rm -f "${PID_FILE}"
    echo ""
    echo "To start: ./scripts/softkms-start.sh"
fi
