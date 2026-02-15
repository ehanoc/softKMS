# Quick Start for Developers

## Current State

**Last Updated**: 2026-02-15  
**Status**: v0.2 - Functional with tests

## How to Get Started

### 1. Verify Build
```bash
cd ~/workspace/softKMS
./build.sh
```

Expected output:
- ✅ Build completes
- ✅ Tests pass (18 tests)
- ✅ Binaries: `softkms-daemon`, `softkms`

### 2. Key Files

| File | Purpose |
|------|---------|
| `README.md` | Project overview |
| `STATUS.md` | What's implemented (source of truth) |
| `docs/ARCHITECTURE.md` | Design docs |
| `src/lib.rs` | Core types |
| `src/key_service.rs` | Key lifecycle |
| `src/api/grpc.rs` | gRPC implementation |
| `cli/src/main.rs` | CLI commands |

### 3. Running

```bash
# Build
cargo build --release

# Start daemon
./target/release/softkms-daemon &

# Initialize (first time)
./target/release/softkms init

# Use CLI
./target/release/softkms list
./target/release/softkms generate --algorithm ed25519 --label "test"
./target/release/softkms sign --label "test" --data "hello"

# Run tests
cargo test
```

### 4. Architecture

```
src/
├── api/           # gRPC server
├── crypto/        # Ed25519, P-256, HD engines
├── security/      # AES-GCM, PBKDF2, master key
├── storage/       # File-based encrypted storage
├── key_service.rs # Key lifecycle (wrap/unwrap)
└── daemon/        # Daemon startup
```

### 5. Next Steps

1. Read STATUS.md for current implementation state
2. Pick a task from NEXT_STEPS.md or the GitHub issues
3. Check existing code for patterns

## Documentation

```
README.md              → Project overview
STATUS.md              → Implementation status (authoritative)
docs/ARCHITECTURE.md   → Architecture design
docs/SECURITY_MODEL.md → Security design
docs/cli-hd-ed25519-*.md → CLI guides
```

## Common Commands

```bash
# Build
./build.sh

# Run daemon
./target/release/softkms-daemon --foreground

# CLI
./target/release/softkms --help
./target/release/softkms init
./target/release/softkms generate --algorithm ed25519 --label "mykey"
./target/release/softkms sign --label "mykey" --data "hello"

# Tests
cargo test
./test_runner.sh
```
