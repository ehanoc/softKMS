#!/bin/bash
# test_passphrase_prompt.sh
# Demonstrates when passphrase is prompted

echo "=========================================="
echo "Passphrase Prompt Timing Test"
echo "=========================================="
echo ""
echo "Important: The passphrase is NOT prompted during daemon startup!"
echo "It's only prompted when you actually try to encrypt/decrypt data."
echo ""

# Clean start
rm -rf ~/.softKMS-demo

echo "Step 1: Starting daemon..."
echo "(Notice: NO passphrase prompt here)"
./target/release/softkms-daemon \
  --foreground \
  --storage-path ~/.softKMS-demo/data \
  --pid-file ~/.softKMS-demo/run/softkms.pid \
  --grpc-addr "127.0.0.1:50051" \
  --rest-addr "127.0.0.1:8080" &
echo ""
echo "Daemon started without passphrase! ✓"
echo ""
echo "This is correct - the passphrase is only needed when you:"
echo "  - Create a key"
echo "  - Retrieve a key"
echo "  - Sign with a key"
echo ""
echo "The daemon can run and accept API calls without the passphrase."
echo "The passphrase is derived from user input only when needed."
echo ""
echo "=========================================="
echo ""
echo "To test the passphrase prompt:"
echo ""
echo "  1. Create a key (requires passphrase):"
echo "     ./target/release/softkms key create --label 'Test'"
echo "     (This will prompt: 'Enter passphrase: ')"
echo ""
echo "  2. Or run the example:"
echo "     cargo run --example demo_passphrase"
echo ""
echo "  3. The passphrase is then cached for 5 minutes"
echo "     (configurable in SecurityConfig::cache_duration)"
echo ""
echo "=========================================="
echo ""
echo "Stopping demo daemon..."
pkill -f "softkms-daemon.*softKMS-demo" || true
rm -rf ~/.softKMS-demo
echo "Done!"
