# softKMS Security Layer - Testing Guide

## Overview

This guide demonstrates how to test the new Security Layer with AES-256-GCM encryption.

## What Was Implemented

1. **Master Key Derivation**: PBKDF2-HMAC-SHA256 (210k iterations)
2. **Key Wrapping**: AES-256-GCM with per-key salts
3. **Encrypted Storage**: Automatic encryption/decryption
4. **Passphrase Caching**: 5-minute TTL with thread-safe Mutex
5. **Memory Protection**: mlock with graceful fallback

## Quick Test

### 1. Build the Project

```bash
cd /home/user/workspace/softKMS
cargo build --release
```

### 2. Run Unit Tests

```bash
# Test security module
cargo test security:: --lib -- --nocapture

# Expected output:
# test security::config::tests::test_default_config ... ok
# test security::config::tests::test_validation_invalid_algorithm ... ok
# test security::config::tests::test_validation_low_iterations ... ok
# test security::master_key::tests::test_different_passphrases ... ok
# test security::master_key::tests::test_derive_key ... ok
# test security::master_key::tests::test_derive_with_same_salt ... ok
# test security::master_key::tests::test_salt_randomness ... ok
# test security::mod::tests::test_cache_expiration ... ok
# test security::mod::tests::test_cache_validity ... ok
# test security::wrapper::tests::test_invalid_bytes_too_short ... ok
# test security::wrapper::tests::test_serialization ... ok
# test security::wrapper::tests::test_unique_nonces ... ok
# test security::wrapper::tests::test_unique_salts ... ok
# test security::wrapper::tests::test_version_mismatch ... ok
# test security::wrapper::tests::test_wrap_unwrap_roundtrip ... ok
# test security::wrapper::tests::test_wrong_aad ... ok
# test security::wrapper::tests::test_wrong_passphrase ... ok
```

### 3. Test Manual Integration

#### Test 3.1: Start Daemon with Passphrase

```bash
# Clean start
rm -rf ~/.softKMS

# Start daemon - it will prompt for passphrase
./target/release/softkms-daemon --foreground
```

**Expected behavior:**
- Prompt: "Enter passphrase: "
- Prompt: "Confirm passphrase: " (first time only)
- Log: "Initialized encrypted file storage at /home/user/.softKMS/data"
- Log: "Daemon started successfully"

#### Test 3.2: Verify Encryption

In another terminal:

```bash
# Check storage directory exists
ls -la ~/.softKMS/data/

# If you've created keys (via CLI), verify they're encrypted
ls ~/.softKMS/data/*.enc 2>/dev/null

# Check that files are binary (not JSON)
file ~/.softKMS/data/*.enc
# Should output: "data" or "ISO-8859 text" (encrypted data)
# NOT: "JSON data"
```

#### Test 3.3: Test Cache

```bash
# Create a second operation within 5 minutes
# Should NOT prompt for passphrase again (cached)
```

#### Test 3.4: Stop and Restart

```bash
# Stop daemon
./scripts/softkms-stop.sh

# Wait 5+ minutes (or clear cache)

# Restart
./scripts/softkms-start.sh
# Should prompt for passphrase again (cache expired)
```

### 4. Test Security Features

#### Test 4.1: Wrong Passphrase

```bash
# Create a script that provides wrong passphrase
echo "wrongpass" | ./target/release/softkms-daemon --foreground

# Expected: Decryption error, daemon fails to start
```

#### Test 4.2: Memory Protection

```bash
# Check if mlock worked (Linux only)
grep -i "mlock" ~/.softKMS/logs/daemon.log

# Expected: Either "Memory locked successfully" or warning
```

### 5. Binary Format Verification

```bash
# If you have a wrapped key file:
xxd ~/.softKMS/data/<key-id>.enc | head -20

# Expected format:
# [version: 1 byte][salt: 32 bytes][nonce: 12 bytes][tag: 16 bytes][aad_hash: 32 bytes][ciphertext: N bytes]
```

## API Usage Examples

### Creating an Encrypted Storage

```rust
use softkms::storage::encrypted::create_encrypted_storage;
use softkms::Config;

// Create encrypted storage with 5-minute cache
let config = Config::default();
let storage = create_encrypted_storage(
    "/home/user/.softKMS/data".into(),
    config,
    300, // 5 minutes
)?;
```

### Wrapping a Key

```rust
use softkms::security::{MasterKey, KeyWrapper, SecurityConfig};

// Derive master key
let master_key = MasterKey::derive("my_passphrase", 210_000)?;

// Create wrapper
let wrapper = KeyWrapper::new(master_key);

// Wrap key material with metadata as AAD
let key_material = b"my_secret_key";
let aad = b"key_id=xxx&algorithm=ed25519";
let wrapped = wrapper.wrap(key_material, aad)?;

// Serialize for storage
let bytes = wrapped.to_bytes();
```

### Unwrapping a Key

```rust
// Deserialize
let wrapped = WrappedKey::from_bytes(&bytes)?;

// Unwrap (using same passphrase)
let master_key = MasterKey::derive("my_passphrase", 210_000)?;
let wrapper = KeyWrapper::new(master_key);
let plaintext = wrapper.unwrap(&wrapped, aad)?;
```

## Troubleshooting

### Issue: "Passphrase mismatch"
**Cause:** First-time setup requires confirmation
**Fix:** Enter same passphrase twice

### Issue: "Memory locking failed"
**Cause:** mlock requires elevated privileges or memory limits
**Fix:** This is a warning, operation continues (as designed)

### Issue: "Decryption failed"
**Cause:** Wrong passphrase or tampered data
**Fix:** Verify passphrase or check file integrity

### Issue: Cache not working
**Cause:** TTL is 0 (no caching) or cache was cleared
**Fix:** Check config: `cache_duration = 300` (5 minutes)

## Performance

### PBKDF2 Benchmark

```bash
cargo bench -- security

# Expected: ~100ms for 210k iterations
```

### Memory Usage

```bash
# Monitor during operation
watch -n 1 'ps aux | grep softkms-daemon'

# Check locked memory
# Linux:
cat /proc/$(pgrep softkms-daemon)/status | grep -i vmrss
```

## Security Checklist

- [ ] Encryption is actually happening (files are binary, not JSON)
- [ ] Wrong passphrase fails with clear error
- [ ] Passphrase confirmation works on first setup
- [ ] Cache TTL works (second operation doesn't prompt)
- [ ] mlock fallback works (warning, not crash)
- [ ] Zeroization happens (sensitive data cleared)
- [ ] Per-key salts are unique (check with xxd)
- [ ] AAD integrity prevents tampering

## Next Steps

1. **CLI Commands**: Implement `softkms key create` and `key list`
2. **Passphrase Change**: Implement `change_passphrase` CLI command
3. **Benchmarks**: Add PBKDF2 iteration benchmarks
4. **Documentation**: Add man pages

## Files Changed

- `src/security/mod.rs` - Security manager with caching
- `src/security/master_key.rs` - Master key derivation
- `src/security/wrapper.rs` - AES-GCM encryption
- `src/security/config.rs` - Security configuration
- `src/security/error.rs` - Security error types
- `src/storage/encrypted.rs` - Encrypted storage backend
- `src/daemon/mod.rs` - Daemon integration
- `src/storage/mod.rs` - Storage module exports

Total: ~1,100 lines of security-critical code

## References

- PBKDF2: RFC 2898, OWASP recommendation (210k iterations)
- AES-GCM: NIST SP 800-38D
- BIP39: Bitcoin mnemonic seed format (future use)
