#!/bin/bash
# Test script for HD Ed25519 sign/verify fix

set -e

# Kill any existing daemon
pkill -f softkms-daemon 2>/dev/null || true
sleep 1

# Clean test directory
TEST_DIR="$HOME/.softKMS-test-fix"
rm -rf "$TEST_DIR"
mkdir -p "$TEST_DIR"

# Start daemon with test directory
./target/release/softkms-daemon \
    --storage-path "$TEST_DIR" \
    --pid-file "$TEST_DIR/softkms.pid" \
    --grpc-addr "127.0.0.1:50501" \
    --log-level debug > "$TEST_DIR/daemon.log" 2>&1 &

DAEMON_PID=$!
echo "Started daemon with PID: $DAEMON_PID"
sleep 2

# Set up server address
export SERVER="http://127.0.0.1:50501"

# Initialize keystore
echo "=== Step 1: Initialize keystore ==="
./target/release/softkms --server "$SERVER" --passphrase "testpass123" init --confirm false
echo "Keystore initialized"

# Import seed
echo -e "\n=== Step 2: Import BIP39 seed ==="
MNEMONIC="abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
SEED_OUTPUT=$(./target/release/softkms --server "$SERVER" --passphrase "testpass123" import-seed \
    --mnemonic "$MNEMONIC" \
    --label "testseed" 2>&1)
echo "$SEED_OUTPUT"
SEED_ID=$(echo "$SEED_OUTPUT" | grep "ID:" | awk '{print $2}')
echo "Seed ID: $SEED_ID"

# Derive Ed25519 key
echo -e "\n=== Step 3: Derive Ed25519 key ==="
DERIVE_OUTPUT=$(./target/release/softkms --server "$SERVER" --passphrase "testpass123" derive \
    --algorithm ed25519 \
    --seed "$SEED_ID" \
    --path "m/44'/283'/0'/0/0" \
    --label "test-derived-key" 2>&1)
echo "$DERIVE_OUTPUT"
KEY_ID=$(echo "$DERIVE_OUTPUT" | grep "Key ID:" | awk '{print $3}')
echo "Derived Key ID: $KEY_ID"

# List keys
echo -e "\n=== Step 4: List keys ==="
./target/release/softkms --server "$SERVER" list

# Sign data
echo -e "\n=== Step 5: Sign data ==="
SIGN_OUTPUT=$(./target/release/softkms --server "$SERVER" --passphrase "testpass123" sign \
    --key "$KEY_ID" \
    --data "hello" 2>&1)
echo "$SIGN_OUTPUT"
SIGNATURE=$(echo "$SIGN_OUTPUT" | grep "Signature (base64):" | awk '{print $3}')
echo "Signature: $SIGNATURE"

# Verify signature
echo -e "\n=== Step 6: Verify signature ==="
./target/release/softkms --server "$SERVER" verify \
    --key "$KEY_ID" \
    --data "hello" \
    --signature "$SIGNATURE" 2>&1

# Test with wrong data (should fail)
echo -e "\n=== Step 7: Verify with wrong data (should fail) ==="
./target/release/softkms --server "$SERVER" verify \
    --key "$KEY_ID" \
    --data "wrong" \
    --signature "$SIGNATURE" 2>&1 || echo "Verification correctly failed for wrong data"

# Cleanup
echo -e "\n=== Cleanup ==="
kill "$DAEMON_PID" 2>/dev/null || true
rm -rf "$TEST_DIR"
echo "Test complete!"
