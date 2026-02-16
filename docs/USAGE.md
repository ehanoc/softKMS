# softKMS Usage Guide

Complete guide for using softKMS via CLI, PKCS#11, and HD wallet operations.

## Table of Contents

1. [Quick Start](#quick-start)
2. [CLI Reference](#cli-reference)
3. [PKCS#11 Usage](#pkcs11-usage)
4. [HD Wallet Operations](#hd-wallet-operations)
5. [Examples](#examples)
6. [Troubleshooting](#troubleshooting)

## Quick Start

### 1. Start the Daemon

```bash
# Foreground (development)
softkms-daemon --foreground

# Background with custom storage
softkms-daemon --storage-path /var/lib/softkms
```

### 2. Initialize the Keystore

```bash
# First-time setup
softkms init

# Or non-interactive
softkms -p mypassphrase init --confirm false
```

### 3. Generate Your First Key

```bash
softkms generate --algorithm ed25519 --label my-first-key
softkms list
```

## CLI Reference

### Key Management

```bash
# Generate a new key
softkms generate --algorithm ed25519 --label mykey
softkms generate --algorithm p256 --label my-ec-key

# List all keys
softkms list

# Get key details
softkms info --label mykey

# Delete a key
softkms delete --label mykey
```

### Signing Operations

```bash
# Sign data (returns base64 signature)
softkms sign --label mykey --data "Hello World"

# Sign from file
softkms sign --label mykey --file message.txt

# Verify signature
softkms verify --label mykey --data "Hello World" --signature "base64..."
```

### Daemon Operations

```bash
# Check daemon health
softkms health

# Change passphrase
softkms change-passphrase --old oldpass --new newpass

# List keys (requires passphrase)
softkms -p mypass list
```

## PKCS#11 Usage

softKMS provides a PKCS#11 shared library for compatibility with existing tools.

### Prerequisites

```bash
# Build the shared library
cargo build

# Library location
export PKCS11_MODULE=target/debug/libsoftkms.so
```

### List Slots

```bash
pkcs11-tool --module $PKCS11_MODULE --list-slots
```

**Expected output:**
```
Available slots:
Slot 0: softKMS
```

### Generate EC Key (P-256)

**Important**: Due to a pkcs11-tool issue, you must specify the mechanism:

```bash
pkcs11-tool --module $PKCS11_MODULE \
  --token-label softKMS \
  --login --pin mypassphrase \
  --keypairgen \
  --key-type EC:prime256v1 \
  --label my-ec-key \
  -m 0x1050
```

### Sign and Verify

```bash
# Sign data
echo "Hello World" > data.txt

pkcs11-tool --module $PKCS11_MODULE \
  --token-label softKMS \
  --login --pin mypassphrase \
  --sign \
  --label my-ec-key \
  --input-file data.txt \
  --output-file signature.bin \
  -m 0x1001

# Verify
pkcs11-tool --module $PKCS11_MODULE \
  --token-label softKMS \
  --login --pin mypassphrase \
  --verify \
  --label my-ec-key \
  --input-file data.txt \
  --signature-file signature.bin \
  -m 0x1001
```

### OpenSSH Integration

```bash
# Configure SSH
export SSH_PKCS11_MODULE=$PKCS11_MODULE

# List SSH keys
ssh-keygen -D $PKCS11_MODULE -l

# Use with SSH
ssh -I $PKCS11_MODULE user@hostname
```

### Git Integration

```bash
export GIT_SSH_COMMAND="ssh -I $PKCS11_MODULE"
git clone git@github.com:user/repo.git
```

## HD Wallet Operations

softKMS supports BIP32/BIP44 hierarchical deterministic key derivation.

### Import Seed

**BIP39 Mnemonic:**
```bash
softkms import-seed \
  --mnemonic "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about" \
  --label mywallet
```

**Raw Hex (64 bytes):**
```bash
softkms import-seed \
  --seed "a1b2c3d4..." \
  --label backup
```

### Derive Child Keys

**Algorand (coin type 283):**
```bash
softkms derive \
  --algorithm ed25519 \
  --seed mywallet \
  --path "m/44'/283'/0'/0/0" \
  --label algo-address-0
```

**Bitcoin (coin type 0):**
```bash
softkms derive \
  --algorithm ed25519 \
  --seed mywallet \
  --path "m/44'/0'/0'/0/0" \
  --label btc-address-0
```

**P-256 for WebAuthn:**
```bash
softkms derive \
  --algorithm p256 \
  --seed mywallet \
  --origin "github.com" \
  --user-handle "user123" \
  --counter 0 \
  --label github-key
```

### Derivation Schemes

- **Peikert** (default) - Enhanced entropy, recommended
- **V2** - Original IEEE BIP32-Ed25519 standard

```bash
softkms derive \
  --algorithm ed25519 \
  --seed mywallet \
  --path "m/44'/283'/0'/0/0" \
  --scheme peikert \
  --label mykey
```

### BIP44 Path Format

```
m / purpose' / coin_type' / account' / change / index
```

| Chain | Coin Type | Example Path |
|-------|-----------|--------------|
| Algorand | 283 | `m/44'/283'/0'/0/0` |
| Bitcoin | 0 | `m/44'/0'/0'/0/0` |
| Ethereum | 60 | `m/44'/60'/0'/0/0` |

## Examples

### Complete PKCS#11 Workflow

```bash
# 1. Start fresh
pkill softkms-daemon || true
rm -rf ~/.softKMS

# 2. Start daemon
./target/debug/softkms-daemon &
sleep 2

# 3. Initialize
./target/debug/softkms -p mysecret123 init --confirm false

# 4. Generate EC key
pkcs11-tool --module ./target/debug/libsoftkms.so \
  --token-label softKMS \
  --login --pin mysecret123 \
  --keypairgen \
  --key-type EC:prime256v1 \
  --label github-key \
  -m 0x1050

# 5. Verify key exists
./target/debug/softkms -p mysecret123 list
```

### HD Wallet with Multiple Keys

```bash
# 1. Import seed
softkms import-seed \
  --mnemonic "word1 word2 ... word12" \
  --label wallet

# 2. Generate multiple addresses
for i in {0..9}; do
  softkms derive \
    --seed wallet \
    --path "m/44'/283'/0'/0/$i" \
    --label "algo-addr-$i"
done

# 3. List all derived keys
softkms list
```

### Batch Key Generation

```bash
#!/bin/bash
PASSPHRASE="mypassword"

for i in {1..100}; do
  softkms -p $PASSPHRASE generate \
    --algorithm ed25519 \
    --label "key-$i" \
    --attributes "batch=batch1"
done
```

## Troubleshooting

### Error: "Daemon not ready"

```bash
# Check if daemon is running
pgrep softkms-daemon

# Check health
softkms health

# Restart with foreground to see errors
softkms-daemon --foreground
```

### Error: "Keystore not initialized"

```bash
# Initialize first
softkms init

# Or with passphrase
softkms -p mypass init --confirm false
```

### PKCS#11 Error: "Generate EC key mechanism 1040 not supported"

Use explicit mechanism flag:
```bash
-m 0x1050
```

### PKCS#11 Error: "CKR_KEY_HANDLE_INVALID"

Keystore not initialized or daemon not running:
```bash
# Check daemon
pgrep softkms-daemon || softkms-daemon &

# Initialize
softkms -p mypass init --confirm false
```

### Connection Refused

```bash
# Check if daemon is listening
ss -tlnp | grep 50051

# Use explicit server address
softkms --server http://127.0.0.1:50051 list
```

## Security Notes

1. **Never share your passphrase** - It's used to derive the master key
2. **Keys never leave the daemon** - They are generated and stored internally
3. **Use strong passphrases** in production (16+ characters)
4. **Daemon runs locally** by default - not accessible over network
5. **Backup your seed** - If using HD wallets, store the seed phrase securely

## See Also

- [Architecture Guide](ARCHITECTURE.md) - System design
- [Security Model](SECURITY.md) - Security features
- [API Reference](API.md) - gRPC API documentation
