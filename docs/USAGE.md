# softKMS Usage Guide

Complete guide for using softKMS via CLI, PKCS#11, and HD wallet operations with identity-based access control.

## Table of Contents

1. [Quick Start](#quick-start)
2. [Identity Management](#identity-management)
3. [CLI Reference](#cli-reference)
4. [PKCS#11 Usage](#pkcs11-usage)
5. [HD Wallet Operations](#hd-wallet-operations)
6. [Examples](#examples)
7. [Troubleshooting](#troubleshooting)

## Quick Start

### 1. Start the Daemon

```bash
# Foreground (development)
softkms-daemon --foreground

# Background with custom storage
softkms-daemon --storage-path /var/lib/softkms
```

### 2. Initialize the Keystore (Admin)

```bash
# First-time setup (creates admin identity)
softkms init

# Or non-interactive
softkms -p mypassphrase init --confirm false
```

### 3. Create a Client Identity

```bash
# Create identity for a service or agent
softkms identity create --type ai-agent --description "Trading Bot"
# Token: ZGlkOmtleTp6Nk1rLi4uOnNlY3JldDEyMw== (SAVE THIS!)

# Use the token
export SOFTKMS_TOKEN="ZGlkOmtleTp6Nk1rLi4uOnNlY3JldDEyMw=="
softkms --token $SOFTKMS_TOKEN generate --algorithm ed25519 --label bot-key
```

## Identity Management

softKMS uses identity-based access control where:
- **Admin** (passphrase): Full access to all keys
- **Clients** (token): Isolated access to their own keys only

### Creating Identities

#### CLI

```bash
# Create Ed25519 identity (default, recommended)
softkms identity create --type ai-agent --description "Trading Bot"
# Output:
# Public Key: ed25519:MCowBQYDK2VwAyE...
# Token: ZGlkOmtleTp6Nk1rLi4uOnNlY3JldDEyMw==
# SAVE THIS TOKEN - never shown again!

# Create P-256 identity (for PKCS#11 compatibility)
softkms identity create --type service --key-type p256 --description "Payment API"
# Token: cDI1NjpCTDVhNXRENHgwdk0...

# Create identity without description
softkms identity create --type ai-agent
```

#### Supported Types

- `ai-agent`: AI/autonomous agents
- `service`: Backend services
- `user`: Human users (if needed)
- `pkcs11`: PKCS#11 clients

### Using Tokens

#### Environment Variable (Recommended)

```bash
# Set token
export SOFTKMS_TOKEN="ZGlkOmtleTp6Nk1rLi4uOnNlY3JldDEyMw=="

# All commands use token automatically
softkms list
softkms generate --algorithm ed25519 --label mykey
softkms sign --label mykey --data "Hello"
```

#### Command Line Flag

```bash
# Pass token directly
softkms --token "ZGlkOmtleTp6Nk1rLi4uOnNlY3JldDEyMw==" list
softkms --token "..." generate --algorithm ed25519 --label mykey
```

#### In Scripts

```bash
#!/bin/bash
SOFTKMS_TOKEN="${SOFTKMS_TOKEN:?Set token first}"

# Operations are isolated to this identity
softkms --token "$SOFTKMS_TOKEN" generate --algorithm ed25519 --label "key-$(date +%s)"
signature=$(softkms --token "$SOFTKMS_TOKEN" sign --label "key-$(date +%s)" --data "$1")
echo "$signature"
```

### Admin Operations

Admin uses passphrase, not tokens:

```bash
# Admin sees ALL keys (all identities)
softkms -p admin_pass list

# Admin can create identities
softkms -p admin_pass identity create --type ai-agent

# Admin can revoke identities
softkms -p admin_pass identity revoke ed25519:MCowBQY...

# Admin can list all identities
softkms -p admin_pass identity list
```

### Revoking Identities

```bash
# Revoke an identity (admin only)
softkms identity revoke ed25519:MCowBQY...

# Token immediately stops working
softkms --token "..." list
# Error: Invalid or revoked identity
```

## CLI Reference

### Identity Commands

```bash
# Create identity
softkms identity create --type <type> [--key-type ed25519|p256] [--description <desc>]

# List identities (admin only)
softkms identity list

# Revoke identity (admin only)
softkms identity revoke <public-key>
```

### Key Management

```bash
# Generate a new key (uses token from env or --token)
softkms generate --algorithm ed25519 --label mykey
softkms generate --algorithm p256 --label my-ec-key

# List keys (only shows keys for current identity)
softkms list

# Get key details
softkms info --label mykey

# Delete a key (must be owner)
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

# Check current identity (shows which identity is active)
softkms --token $SOFTKMS_TOKEN health
```

## PKCS#11 Usage

softKMS provides a PKCS#11 shared library with token-based authentication.

### Prerequisites

```bash
# Build the shared library
cargo build

# Library location
export PKCS11_MODULE=target/debug/libsoftkms.so
```

### Authentication Options

#### Option 1: Token as PIN (Clients)

```bash
# Use your identity token as PIN
export TOKEN="ZGlkOmtleTp6Nk1rLi4uOnNlY3JldDEyMw=="

pkcs11-tool --module $PKCS11_MODULE \
  --token-label softKMS \
  --login --pin "$TOKEN" \
  --list-slots
```

#### Option 2: Passphrase with Prefix (Admin)

```bash
# Admin uses "pass:" prefix
pkcs11-tool --module $PKCS11_MODULE \
  --token-label softKMS \
  --login --pin "pass:admin_passphrase" \
  --list-objects
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
export TOKEN="your-identity-token-here"

pkcs11-tool --module $PKCS11_MODULE \
  --token-label softKMS \
  --login --pin "$TOKEN" \
  --keypairgen \
  --key-type EC:prime256v1 \
  --label my-ec-key \
  -m 0x1050
```

**Note**: The key is created in YOUR identity's namespace, not visible to other identities.

### Sign and Verify

```bash
# Sign data
echo "Hello World" > data.txt

pkcs11-tool --module $PKCS11_MODULE \
  --token-label softKMS \
  --login --pin "$TOKEN" \
  --sign \
  --label my-ec-key \
  --input-file data.txt \
  --output-file signature.bin \
  -m 0x1001

# Verify
pkcs11-tool --module $PKCS11_MODULE \
  --token-label softKMS \
  --login --pin "$TOKEN" \
  --verify \
  --label my-ec-key \
  --input-file data.txt \
  --signature-file signature.bin \
  -m 0x1001
```

### OpenSSH Integration

```bash
# Create identity for SSH
softkms identity create --type user --description "SSH Identity"
export TOKEN="..."

# Configure SSH
export SSH_PKCS11_MODULE=$PKCS11_MODULE
export PKCS11_PIN="$TOKEN"

# List SSH keys
ssh-keygen -D $PKCS11_MODULE -l

# Use with SSH
ssh -I $PKCS11_MODULE user@hostname
```

### Git Integration

```bash
export GIT_SSH_COMMAND="ssh -I $PKCS11_MODULE"
export PKCS11_PIN="$TOKEN"
git clone git@github.com:user/repo.git
```

## HD Wallet Operations

softKMS supports BIP32/BIP44 hierarchical deterministic key derivation.

### Import Seed

**Note**: Seeds are owned by the current identity.

```bash
# Set token first
export SOFTKMS_TOKEN="..."

# BIP39 Mnemonic
softkms import-seed \
  --mnemonic "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about" \
  --label mywallet

# Raw Hex (64 bytes)
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

### Complete Identity Workflow

```bash
#!/bin/bash
set -e

# 1. Start daemon (admin does this)
pkill softkms-daemon 2>/dev/null || true
sleep 1
./target/debug/softkms-daemon --foreground &
sleep 2

# 2. Initialize (admin)
./target/debug/softkms -p admin123 init --confirm false

# 3. Create identity for trading bot (admin)
OUTPUT=$(./target/debug/softkms -p admin123 identity create --type ai-agent --description "Trading Bot")
TOKEN=$(echo "$OUTPUT" | grep "Token:" | cut -d' ' -f2)
echo "Created identity with token: $TOKEN"

# 4. Use identity (bot uses token)
export SOFTKMS_TOKEN="$TOKEN"

# 5. Generate keys (isolated to this identity)
./target/debug/softkms --token "$TOKEN" generate --algorithm ed25519 --label bot-key-1
./target/debug/softkms --token "$TOKEN" generate --algorithm ed25519 --label bot-key-2

# 6. List keys (only sees its own)
./target/debug/softkms --token "$TOKEN" list

# 7. Sign data
./target/debug/softkms --token "$TOKEN" sign --label bot-key-1 --data "Buy BTC"

# 8. Admin sees all keys (including bot's)
./target/debug/softkms -p admin123 list
```

### Multi-Identity Isolation

```bash
# Create two identities
TOKEN_A=$(softkms identity create --type ai-agent | grep Token | cut -d' ' -f2)
TOKEN_B=$(softkms identity create --type ai-agent | grep Token | cut -d' ' -f2)

# Identity A creates keys
softkms --token "$TOKEN_A" generate --label key-a1
softkms --token "$TOKEN_A" generate --label key-a2

# Identity B creates keys
softkms --token "$TOKEN_B" generate --label key-b1

# Identity A only sees A's keys
softkms --token "$TOKEN_A" list
# Shows: key-a1, key-a2
# Does NOT show: key-b1

# Identity B only sees B's keys
softkms --token "$TOKEN_B" list
# Shows: key-b1
# Does NOT show: key-a1, key-a2

# Admin sees all
softkms -p admin123 list
# Shows: key-a1, key-a2, key-b1
```

### PKCS#11 Identity Workflow

```bash
#!/bin/bash

# 1. Create P-256 identity for PKCS#11
OUTPUT=$(softkms identity create --type pkcs11 --key-type p256)
TOKEN=$(echo "$OUTPUT" | grep Token | cut -d' ' -f2)

# 2. Use token as PIN in PKCS#11
export PKCS11_PIN="$TOKEN"

# 3. Generate key via PKCS#11 (creates in identity's namespace)
pkcs11-tool --module libsoftkms.so \
  --login --pin "$PKCS11_PIN" \
  --keypairgen --key-type EC:prime256v1 --label mykey -m 0x1050

# 4. Sign data
pkcs11-tool --module libsoftkms.so \
  --login --pin "$PKCS11_PIN" \
  --sign --label mykey -m 0x1001 \
  --input-file data.txt --output-file sig.bin

# 5. Via CLI, identity only sees its PKCS#11 keys
softkms --token "$TOKEN" list
```

### Service Deployment

```bash
#!/bin/bash
# deploy.sh - Deploy service with identity

# Check if token exists
if [ -z "$SOFTKMS_TOKEN" ]; then
    echo "Error: SOFTKMS_TOKEN not set"
    echo "Create identity: softkms identity create --type service"
    exit 1
fi

# Service runs with its token
export SOFTKMS_TOKEN

# Generate ephemeral key for this session
KEY_LABEL="session-$(date +%s)"
softkms generate --algorithm ed25519 --label "$KEY_LABEL"

# Use key for operations
SIGNATURE=$(softkms sign --label "$KEY_LABEL" --data "$REQUEST_DATA")

# Cleanup (optional)
softkms delete --label "$KEY_LABEL" --force
```

## Troubleshooting

### Token Invalid

```
Error: Invalid or revoked identity
```

**Solutions:**
1. Create new identity: `softkms identity create ...`
2. Check if token was copied correctly
3. Verify identity not revoked: `softkms identity list` (admin)

### Access Denied

```
Error: Access denied to key
```

**Causes:**
- Trying to access another identity's key
- Using wrong token
- Key doesn't exist in your namespace

**Solution:** Verify you're using the correct token

### No Keys Found

```
$ softkms --token $TOKEN list
No keys found
```

**Causes:**
- No keys created yet (create with `generate`)
- Using wrong token
- Keys created by different identity

### PKCS#11 CKR_USER_NOT_LOGGED_IN

```
CKR_USER_NOT_LOGGED_IN (0x101)
```

**Solutions:**
```bash
# For clients: use token
pkcs11-tool ... --pin "$TOKEN"

# For admin: use pass: prefix
pkcs11-tool ... --pin "pass:admin_passphrase"
```

### Identity Not Created

```
$ softkms identity create --type ai-agent
Error: Keystore not initialized
```

**Solution:** Admin must initialize first:
```bash
softkms -p admin_pass init
```

### Daemon Not Ready

```bash
# Check if daemon is running
pgrep softkms-daemon

# Check health
softkms health

# Restart with foreground to see errors
softkms-daemon --foreground
```

## Security Notes

1. **Save tokens immediately** - Shown only once at creation
2. **Never share tokens** - Each service should have its own identity
3. **Secure token storage** - Use secret managers, not plaintext files
4. **Admin passphrase** - Keep separate from client tokens
5. **Identity isolation** - Each identity sees only their keys
6. **Audit logging** - All operations logged with identity
7. **Token rotation** - Revoke and recreate if compromised
8. **Namespace isolation** - Keys stored under identity's public key

## See Also

- [Identity Management](IDENTITIES.md) - Detailed identity system
- [Architecture Guide](ARCHITECTURE.md) - System design
- [Security Model](SECURITY.md) - Security features
- [API Reference](API.md) - gRPC API documentation
