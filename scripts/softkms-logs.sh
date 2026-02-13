#!/bin/bash
# softKMS Daemon Logs Viewer
# Shows and follows the daemon logs

# Configuration
SOFTKMS_HOME="${HOME}/.softKMS"
LOGS_DIR="${SOFTKMS_HOME}/logs"

# Check if logs directory exists
if [ ! -d "${LOGS_DIR}" ]; then
    echo "Logs directory not found: ${LOGS_DIR}"
    echo "Has the daemon been started?"
    exit 1
fi

# Check if log file exists
if [ ! -f "${LOGS_DIR}/daemon.log" ]; then
    echo "No log file found. Has the daemon been started?"
    exit 1
fi

# Show usage
if [ "$1" = "--help" ] || [ "$1" = "-h" ]; then
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  -f, --follow    Follow log output (like tail -f)"
    echo "  -n NUM          Show last NUM lines (default: 50)"
    echo "  --help          Show this help"
    echo ""
    exit 0
fi

# Parse arguments
FOLLOW=false
LINES=50

while [[ $# -gt 0 ]]; do
    case $1 in
        -f|--follow)
            FOLLOW=true
            shift
            ;;
        -n)
            LINES="$2"
            shift 2
            ;;
        *)
            echo "Unknown option: $1"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
done

# Show logs
if [ "${FOLLOW}" = true ]; then
    echo "Following logs (press Ctrl+C to exit)..."
    echo ""
    tail -f "${LOGS_DIR}/daemon.log"
else
    echo "softKMS Daemon Logs (last ${LINES} lines):"
    echo "========================================="
    tail -n "${LINES}" "${LOGS_DIR}/daemon.log"
fi
