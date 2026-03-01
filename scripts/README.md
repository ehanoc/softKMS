# softKMS Daemon Scripts

This directory contains helper scripts for managing the softKMS daemon.

**Note:** These scripts are for development/testing. The daemon now uses XDG Base Directory paths by default.

## Directory Structure

When running as a regular user, softKMS uses XDG paths:

```
~/.config/softkms/              # Configuration
├── config.toml
└── pkcs11.conf

~/.local/share/softkms/         # Data storage
├── keys/
├── identities/
├── .salt
└── .verification_hash

~/.local/state/softkms/         # State (logs, audit)
└── audit.log

$XDG_RUNTIME_DIR/softkms/        # Runtime files (PID, sockets)
└── softkms.pid
```

When running as root (system mode):
- Config: `/etc/softkms/`
- Data: `/var/lib/softkms/`
- Logs: `/var/log/softkms/`
- Runtime: `/var/run/softkms/`

## Scripts

### softkms-start.sh
Starts the softKMS daemon with user-local directories.

```bash
./scripts/softkms-start.sh
```

**Features:**
- Creates XDG directory structure automatically
- Generates default config if not present
- Runs daemon in background
- Saves PID to file for management

**Data locations (user mode):**
- Config: `~/.config/softkms/config.toml`
- Data: `~/.local/share/softkms/`
- State: `~/.local/state/softkms/`
- PID file: `$XDG_RUNTIME_DIR/softkms/softkms.pid` (or `/tmp/softkms.pid`)

### softkms-stop.sh
Gracefully stops the running softKMS daemon.

```bash
./scripts/softkms-stop.sh
```

**Features:**
- Sends SIGTERM for graceful shutdown
- Waits up to 10 seconds
- Falls back to SIGKILL if needed
- Cleans up PID file

### softkms-status.sh
Shows the current status of the daemon.

```bash
./scripts/softkms-status.sh
```

**Shows:**
- Running/stopped status
- Process information
- Network port status
- Health check results
- Data directory info

### softkms-logs.sh
Views the daemon logs.

```bash
# Show last 50 lines
./scripts/softkms-logs.sh

# Show last 100 lines
./scripts/softkms-logs.sh -n 100

# Follow logs in real-time (Ctrl+C to exit)
./scripts/softkms-logs.sh -f
```

## Quick Start

```bash
# Start the daemon (auto-detects user mode)
./scripts/softkms-start.sh

# Check if it's running
./scripts/softkms-status.sh

# Test the REST API
curl http://127.0.0.1:8080/health

# View logs
./scripts/softkms-logs.sh -f

# Stop the daemon
./scripts/softkms-stop.sh
```

## Troubleshooting

### "Daemon failed to start"

Check the logs:
```bash
./scripts/softkms-logs.sh
```

Common causes:
- Port 50051 or 8080 already in use
- Permission denied on XDG directories

### "Another instance is already running"

If the daemon crashed and left a stale PID file:
```bash
# Check if process exists
ps aux | grep softkms-daemon

# Kill manually if needed
pkill -9 softkms-daemon

# Remove stale PID file
rm "$XDG_RUNTIME_DIR/softkms/softkms.pid" 2>/dev/null || rm /tmp/softkms.pid

# Start fresh
./scripts/softkms-start.sh
```

### Port already in use

Change ports in `~/.config/softkms/config.toml`:
```toml
[api]
grpc_addr = "127.0.0.1:50052"  # Different port
rest_addr = "127.0.0.1:8081"   # Different port
```

Then restart:
```bash
./scripts/softkms-stop.sh
./scripts/softkms-start.sh
```

## Direct Usage (without scripts)

If you prefer not to use the scripts:

```bash
# Start daemon directly (auto-detects user mode)
./target/release/softkms-daemon \
  --grpc-addr "127.0.0.1:50051" \
  --rest-addr "127.0.0.1:8080" \
  --foreground
```

Or use explicit paths:

```bash
# Create directories (optional - daemon creates them)
mkdir -p ~/.config/softkms ~/.local/share/softkms ~/.local/state/softkms

# Start daemon directly
./target/release/softkms-daemon \
  --config ~/.config/softkms/config.toml \
  --storage-path ~/.local/share/softkms \
  --grpc-addr "127.0.0.1:50051" \
  --rest-addr "127.0.0.1:8080" \
  --foreground
```

Press Ctrl+C to stop when running in foreground.