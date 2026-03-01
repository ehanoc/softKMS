# softKMS PKCS#11 Testing Guide

This directory contains tests to verify the PKCS#11 integration with softKMS daemon.

## Prerequisites

1. **softKMS daemon must be running**
2. **libsoftkms.so must be built**

## Quick Start

### 1. Start the daemon

```bash
# In one terminal, start the daemon
cargo run --bin softkms-daemon &
sleep 3
```

### 2. Run the test

```bash
# Compile (if not already)
gcc tests/pkcs11/test_pkcs11.c -o tests/pkcs11/test_pkcs11 -ldl

# Run full test (generate key + sign)
./tests/pkcs11/test_pkcs11
```

### 3. Verify key was created in daemon

```bash
cargo run --bin softkms -- list
```

---

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `SOFTKMS_PKCS11_MODULE` | Path to libsoftkms.so | `./target/debug/libsoftkms.so` |
| `SOFTKMS_PASSPHRASE` | Passphrase for keystore | `test` |

---

## Test Program Options

```bash
# Full test (default)
./tests/pkcs11/test_pkcs11

# Skip key generation (use existing key)
./tests/pkcs11/test_pkcs11 --no-genkey

# Skip signing test
./tests/pkcs11/test_pkcs11 --no-sign

# Show help
./tests/pkcs11/test_pkcs11 --help
```

---

## Expected Output

```
=== softKMS PKCS#11 Test ===
Module: ./target/debug/libsoftkms.so
Passphrase: test

Functions loaded successfully

--- Initialization ---
C_Initialize: rv=0x0 (OK)
C_GetSlotList: rv=0x0 (OK)
  Found 1 slots
C_GetMechanismList: rv=0x0 (OK)
  Supported mechanisms: 0

--- Session ---
C_OpenSession: rv=0x0 (OK)
  Session handle: 1
C_Login: rv=0x0 (OK)

--- Key Generation ---
C_GenerateKeyPair: rv=0x0 (OK)
  Public key handle: 123456789
  Private key handle: 123456790

--- Signing ---
C_SignInit: rv=0x0 (OK)
C_Sign: rv=0x0 (OK)
  Data signed: "Hello from softKMS PKCS#11!"
  Signature length: 64 bytes
  Signature (hex): 1a2b3c4d...

--- Cleanup ---
C_Logout: rv=0x0 (OK)
C_CloseSession: rv=0x0 (OK)
C_Finalize: rv=0x0 (OK)

=== Test Complete ===
```

---

## Testing with OpenSSL (NOT RECOMMENDED)

**Warning:** libp11 has a fallback mechanism that may bypass our module. Use the test program above instead.

```bash
# This may generate key locally (NOT in daemon)
SOFTKMS_PKCS11_MODULE=./target/debug/libsoftkms.so \
  openssl genpkey -algorithm Ed25519 -engine pkcs11 \
  -provider-path /usr/lib/x86_64-linux-gnu/engines-3/libpkcs11.so
```

To verify if the key was actually created in the daemon:
```bash
cargo run --bin softkms -- list
```

If no new key appears, OpenSSL used its fallback (not our daemon).

---

## Testing with pkcs11-tool (RECOMMENDED when available)

When pkcs11-tool is available, it should work correctly without fallback:

```bash
# Generate key
pkcs11-tool --module ./target/debug/libsoftkms.so --keypairgen --key-type Ed25519 --label "test"

# List keys
pkcs11-tool --module ./target/debug/libsoftkms.so --list-objects

# Sign data
echo "test data" | pkcs11-tool --module ./target/debug/libsoftkms.so --sign --label "test"
```

---

## Fresh Start

To start with a clean slate:

```bash
# Stop daemon
pkill softkms-daemon

# Delete all data
rm -rf ~/.local/share/softkms ~/.local/state/softkms ~/.config/softkms

# Restart daemon
cargo run --bin softkms-daemon &
sleep 3

# Run test
./tests/pkcs11/test_pkcs11

# Check keys
cargo run --bin softkms -- list
```

---

## Current Implementation Status

| Function | Status |
|----------|--------|
| C_Initialize | ✅ Works |
| C_GetSlotList | ✅ Works |
| C_GetMechanismList | ✅ Works |
| C_OpenSession | ✅ Works |
| C_Login | ✅ Works |
| C_Logout | ✅ Works |
| C_CloseSession | ✅ Works |
| C_GenerateKeyPair | ✅ Works |
| C_SignInit | ✅ Works |
| C_Sign | ✅ Works |
| C_FindObjects | ❌ Not implemented |
| C_VerifyInit | ❌ Not implemented |
| C_Verify | ❌ Not implemented |
