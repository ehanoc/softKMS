#!/bin/bash
set -e

echo "=== softKMS Build Verification ==="
echo ""

echo "1. Checking Rust toolchain..."
rustc --version
cargo --version
echo ""

echo "2. Checking protobuf..."
if command -v protoc &> /dev/null; then
    protoc --version
else
    echo "protoc not found (optional - needed for gRPC protobuf generation)"
fi
echo ""

echo "3. Checking Docker..."
docker --version 2>/dev/null || echo "Docker not installed (optional)"
echo ""

echo "4. Building softKMS..."
cd "$(dirname "$0")"
cargo build --release 2>&1 | tail -20

echo ""
echo "5. Running tests..."
cargo test --release 2>&1 | tail -20

echo ""
echo "=== Build Complete ==="
echo ""
echo "Binary location: target/release/softkms-daemon"
echo "CLI location: target/release/softkms-cli"
