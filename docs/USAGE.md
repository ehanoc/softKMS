# softKMS Usage Guide

Complete guide for using softKMS v0.2.0 via CLI, PKCS#11, and HD wallet operations.

## Table of Contents

1. [Quick Start](#quick-start)
2. [Admin Operations](#admin-operations)
3. [Identity Management](#identity-management)
4. [CLI Reference](#cli-reference)
5. [PKCS#11 Usage](#pkcs11-usage)
6. [HD Wallet Operations](#hd-wallet-operations)
7. [Key Export Operations](#key-export-operations)
8. [Examples](#examples)
9. [Troubleshooting](#troubleshooting)

---

## Quick Start

### 1. Start the Daemon

```bash
# Start daemon in foreground
./target/release/softkms-daemon --foreground

# Or with custom storage path
./target/release/softkms-daemon --storage-path /path/to/keystore --foreground
```

### 2. Initialize the Keystore (First Time Only)

```bash
# Initialize with passphrase (will prompt for passphrase)
./target/release/softkms init
```

**Output:**
```
Enter passphrase: ********
Confirm passphrase: ********
Keystore initialized successfully.
```

### 3. Create Your First Key

```bash
# Create Ed25519 key (will prompt for passphrase)
./target/release/softkms generate --algorithm ed25519 --label "my-first-key"

# Output:
# Enter passphrase: ********
# Key generated successfully:
#   ID: 550e8400-e29b-41d4-a716-446655440000
#   Algorithm: ed25519
#   Label: my-first-key
```

### 4. List Keys

```bash
# List keys (will prompt for passphrase)
./target/release/softkms list
```

**Output:**
```
Keys:
  550e8400-e29b-41d4-a716-446655440000:
    Algorithm: ed25519
    Type: imported
    Label: my-first-key
    Created: 2026-02-17T12:00:00Z

Total: 1 keys
```

---

## Admin Operations

All key operations currently require **admin passphrase** authentication.

### Create Keys

```bash
# Create Ed25519 key (recommended for most use cases)
./target/release/softkms generate --algorithm ed25519 --label "ed25519-key"

# Create P-256 key (for FIDO2/WebAuthn compatibility)
./target/release/softkms generate --algorithm p256 --label "p256-key"

# Create Falcon-512 key (post-quantum)
./target/release/softkms generate --algorithm falcon512 --label "falcon512-key"

# Create Falcon-1024 key (post-quantum, higher security)
./target/release/softkms generate --algorithm falcon1024 --label "falcon1024-key"
```

### List Keys

```bash
# List all keys
./target/release/softkms list

# With detailed output
./target/release/softkms list --detailed
```

### Sign Data

```bash
# Sign with specific key
./target/release/softkms sign --key "key-uuid" --data "Hello World"

# Sign with key by label
./target/release/softkms sign --label "my-key" --data "Hello World"
```

### Delete Keys

```bash
# Delete by key ID
./target/release/softkms delete --key "key-uuid"

# Force delete without confirmation
./target/release/softkms delete --key "key-uuid" --force
```

### Get Key Info

```bash
# Get key details
./target/release/softkms info --key "key-uuid"
```

---

## Identity Management (NEW in v0.2.0)

Create and manage identities for future token-based authentication.

### Create Identity (Admin Only)

```bash
# Create Ed25519 identity for AI agent
./target/release/softkms identity create --type ai-agent --description "Trading Bot"

# Output:
# Identity created successfully:
#   Public Key: ed25519:MCowBQYDK2VwAyEAabc123...
#   Token: eyJhbGciOiJIUzI1NiIs...
#   Created At: 2026-02-17T12:00:00Z
#
# IMPORTANT: Save this token - it will never be shown again!
```

**Identity Types:**
- `ai-agent` - AI/autonomous agents
- `service` - Backend services
- `user` - Human users
- `pkcs11` - PKCS#11 clients

**Key Types:**
- `ed25519` (default) - Ed25519 signing keys
- `p256` - P-256 ECDSA keys

### List Identities (Admin Only)

```bash
./target/release/softkms identity list
```

**Output:**
```
Identities:
  ed25519:MCowBQYDK2VwAyEAabc123...:
    Type: ed25519 (ai-agent)
    Description: Trading Bot
    Status: active
    Created: 2026-02-17T12:00:00Z
    Keys: 0
```

### Revoke Identity (Admin Only)

```bash
# Revoke an identity
./target/release/softkms identity revoke --public-key "ed25519:abc123..." --force

# Output:
# Identity revoked successfully.
#   Identity ed25519:abc123... revoked successfully
```

**Note:** Revoked identities cannot be used for authentication. To re-enable, delete the identity file from storage and recreate.

---

## CLI Reference

### Global Options

```
-s, --server <URL>      gRPC server URL [default: http://127.0.0.1:50051]
-p, --passphrase <PASS> Admin passphrase (required for most operations)
-t, --token <TOKEN>     Identity token (for token-based authentication)
-h, --help              Print help
-V, --version           Print version
```

### Commands

#### `init` - Initialize Keystore

Initialize the keystore with admin passphrase.

```bash
softkms init
```

**Options:**
- `-p, --passphrase <PASS>` - Admin passphrase (required)

#### `generate` - Create Key

Generate a new signing key.

```bash
softkms generate [OPTIONS]
```

**Options:**
- `-a, --algorithm <ALG>` - Algorithm: ed25519, p256, falcon512, or falcon1024 [default: ed25519]
- `-l, --label <LABEL>` - Key label for identification

#### `list` - List Keys

List all stored keys.

```bash
softkms list
```

**Options:**
- `-d, --detailed` - Show detailed information

#### `sign` - Sign Data

Sign data with a stored key.

```bash
softkms sign [OPTIONS]
```

**Options:**
- `-k, --key <ID>` - Key ID (required if label not provided)
- `-l, --label <LABEL>` - Key label (alternative to --key)
- `-d, --data <DATA>` - Data to sign (required)

#### `delete` - Delete Key

Delete a key from storage.

```bash
softkms delete [OPTIONS]
```

**Options:**
- `-k, --key <ID>` - Key ID to delete
- `-f, --force` - Skip confirmation prompt

#### `info` - Key Info

Get detailed information about a key.

```bash
softkms info --key <ID>
```

#### `import-seed` - Import BIP39 Seed

Import a BIP39 mnemonic phrase as a master seed.

```bash
softkms import-seed [OPTIONS]
```

**Options:**
- `-m, --mnemonic <PHRASE>` - BIP39 mnemonic phrase (12-24 words)
- `-l, --label <LABEL>` - Seed label

#### `derive` - Derive Key from Seed

Derive a key from a BIP32 seed. Supports Ed25519 (BIP44) and P-256 (FIDO2/WebAuthn).

```bash
softkms derive [OPTIONS]
```

**Options:**
- `-a, --algorithm <ALGORITHM>` - Algorithm: ed25519 or p256
- `-s, --seed <ID>` - Seed ID to derive from
- `-p, --path <PATH>` - Derivation path for Ed25519 (e.g., "m/44'/283'/0'/0/0")
- `--scheme <SCHEME>` - Derivation scheme for Ed25519: v2 or peikert
- `--origin <ORIGIN>` - Origin/domain for P-256 (e.g., "github.com")
- `--user-handle <HANDLE>` - User handle for P-256
- `--counter <N>` - Counter for P-256 [default: 0]
- `-l, --label <LABEL>` - Key label

**Examples:**

```bash
# Derive Ed25519 key (BIP44 style)
softkms derive --algorithm ed25519 --seed <seed-id> --path "m/44'/283'/0'/0/0" --label "hd-key"

# Derive P-256 key (FIDO2/WebAuthn style)
softkms derive --algorithm p256 --seed <seed-id> --origin "github.com" --user-handle "user123" --label "fido2-key"
```

#### `export-ssh` - Export Key to SSH Format

Export an Ed25519 key to OpenSSH private key format for use with SSH.

```bash
softkms export-ssh [OPTIONS]
```

**Options:**
- `-k, --key <ID>` - Key ID to export
- `-l, --label <LABEL>` - Key label (alternative to --key)
- `-o, --output <PATH>` - Output path [default: ~/.ssh/id_ed25519]

**Example:**
```bash
# Export by label
softkms export-ssh --label "myEdKey" --output ~/.ssh/id_ed25519

# Export by key ID
softkms export-ssh --key abc123-uuid --output ~/.ssh/my_key
```

**Notes:**
- Only Ed25519 keys are supported for SSH export
- The private key is written with mode 0600 (owner read/write only)
- Original key remains encrypted in softKMS keystore

#### `export-gpg` - Export Key to GPG Format

Export a key to GPG (OpenPGP) format for use with GnuPG.

```bash
softkms export-gpg [OPTIONS]
```

**Options:**
- `-k, --key <ID>` - Key ID to export
- `-l, --label <LABEL>` - Key label (alternative to --key)
- `-u, --user-id <USER_ID>` - GPG user ID (e.g., "User <user@example.com>")

**Example:**
```bash
# Export by label with custom user ID
softkms export-gpg --label "myEdKey" --user-id "John Doe <john@example.com>"

# Export by key ID
softkms export-gpg --key abc123-uuid --user-id "Backup Key <backup@example.com>"
```

**Notes:**
- Supports Ed25519 and P-256 keys
- Supports HD-derived keys (32, 64, or 96 bytes)
- Key is automatically imported to GPG keyring
- Temporary file is deleted after successful import

#### `identity create` - Create Identity

Create a new identity for token-based auth (admin only).

```bash
softkms identity create [OPTIONS]
```

**Options:**
- `-t, --type <TYPE>` - Identity type: ai-agent, service, user, pkcs11
- `-k, --key-type <TYPE>` - Key algorithm: ed25519, p256 [default: ed25519]
- `-d, --description <DESC>` - Description

#### `identity list` - List Identities

List all identities (admin only).

```bash
softkms identity list [OPTIONS]
```

**Options:**
- `--include-inactive` - Include revoked identities

#### `identity revoke` - Revoke Identity

Revoke an identity (admin only).

```bash
softkms identity revoke [OPTIONS]
```

**Options:**
- `-p, --public-key <KEY>` - Public key of identity to revoke
- `-f, --force` - Skip confirmation

## Key Export Operations

Export keys from softKMS for use with external tools like SSH and GPG.

#### `health` - Health Check

Check daemon health and status.

```bash
softkms health
```

#### `pkcs11` - PKCS#11 Info

Show PKCS#11 module information.

```bash
softkms pkcs11
softkms pkcs11 --module  # Show module path
```

---

## PKCS#11 Usage

### Module Path

```bash
# Get PKCS#11 module path
./target/release/softkms pkcs11 --module

# Output:
# /home/user/workspace/softKMS/target/release/libsoftkms_pkcs11.so
```

### Using with Applications

```bash
# Set environment variable
export PKCS11_MODULE=/path/to/libsoftkms_pkcs11.so

# Use with OpenSSL
openssl pkeyutl -sign -in data.txt -out data.sig -pkcs11 -inkey "pkcs11:..."
```

**Note:** PKCS#11 currently uses admin context. PIN-to-identity mapping coming in Phase 2.

---

## HD Wallet Operations

### Import BIP39 Seed

```bash
# Import 12-word mnemonic
./target/release/softkms import-seed \
  --mnemonic "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about" \
  --label "my-wallet"

# Output:
# Seed 550e8400-e29b-41d4-a716-446655440000 imported and stored encrypted
```

### Derive Ed25519 Key

```bash
# Derive first key from seed
./target/release/softkms derive \
  --algorithm ed25519 \
  --seed "550e8400-e29b-41d4-a716-446655440000" \
  --path "m/44'/283'/0'/0/0" \
  --label "account-0-key-0"

# Output:
# Ed25519 key 660e8400-e29b-41d4-a716-446655440001 derived successfully
```

### Derive P-256 Key (for FIDO2/WebAuthn)

```bash
./target/release/softkms derive \
  --algorithm p256 \
  --seed "550e8400-e29b-41d4-a716-446655440000" \
  --origin "example.com" \
  --user-handle "user123" \
  --counter 0 \
  --label "fido2-key"

# Output:
# P-256 key 770e8400-e29b-41d4-a716-446655440002 derived
#   Key ID: 770e8400-e29b-41d4-a716-446655440002
#   Public Key: base64...
```

---

## Examples

### Complete Workflow

```bash
# 1. Start daemon
./target/release/softkms-daemon --foreground &

# 2. Initialize keystore
./target/release/softkms init

# 3. Create Ed25519 key
./target/release/softkms generate \
  --algorithm ed25519 \
  --label "signing-key"

# 4. Sign data
./target/release/softkms sign \
  --label "signing-key" \
  --data "Hello World"

# 5. Create identity for service
./target/release/softkms identity create \
  --type service \
  --description "Payment API"
# Save the token output!

# 6. Import seed for HD wallet
./target/release/softkms import-seed \
  --mnemonic "abandon abandon ... about" \
  --label "master-seed"

# 7. Derive Ed25519 key from seed
./target/release/softkms derive \
  --algorithm ed25519 \
  --seed "seed-uuid-from-step-6" \
  --path "m/44'/283'/0'/0/0" \
  --label "derived-key-0"

# 8. List all keys
./target/release/softkms list

# 9. Check identities
./target/release/softkms identity list

# 10. Health check
./target/release/softkms health
```

### SSH and GPG Export Workflow

Export keys from softKMS for use with SSH and GPG:

```bash
# 1. Start daemon
./target/release/softkms-daemon --foreground &

# 2. Initialize (first time only)
./target/release/softkms init

# 3. Create an Ed25519 key
./target/release/softkms generate \
  --algorithm ed25519 \
  --label "my-ssh-key"

# 4. Export to SSH format
./target/release/softkms export-ssh \
  --label "my-ssh-key" \
  --output ~/.ssh/id_ed25519

# 5. Use with SSH
ssh -i ~/.ssh/id_ed25519 user@server

# 6. Create another key for GPG
./target/release/softkms generate \
  --algorithm ed25519 \
  --label "my-gpg-key"

# 7. Export to GPG format (auto-imports to GPG keyring)
./target/release/softkms export-gpg \
  --label "my-gpg-key" \
  --user-id "My Name <myname@example.com>"

# 8. Verify GPG key was imported
gpg --list-secret-keys
```

### HD Key Export Workflow

Export HD-derived keys to SSH/GPG:

```bash
# 1. Import BIP39 seed
./target/release/softkms import-seed \
  --mnemonic "abandon abandon ... about" \
  --label "master-seed"

# 2. Derive Ed25519 key from seed
./target/release/softkms derive \
  --algorithm ed25519 \
  --seed "seed-uuid" \
  --path "m/44'/283'/0'/0/0" \
  --label "hd-key-0"

# 3. Export HD key to GPG (supports 96-byte HD keys)
./target/release/softkms export-gpg \
  --label "hd-key-0" \
  --user-id "HD Key <hd@example.com>"

# The export handles the 96-byte extended key automatically
# Only the first 32 bytes (the scalar) are used for GPG
```

---

## Troubleshooting

### "Keystore not initialized"

**Cause:** Daemon started but keystore not initialized

**Solution:**
```bash
./target/release/softkms init
```

### "Invalid admin passphrase"

**Cause:** Wrong passphrase provided

**Solution:** Use the correct passphrase used during `init`

### "Identity has been revoked"

**Cause:** Trying to use a revoked identity token

**Solution:** Create a new identity with `identity create`

### "Key not found"

**Cause:** Key ID doesn't exist

**Solution:** Use `list` to see available keys

### "Cannot use both --passphrase and --auth-token"

**Cause:** Both authentication methods provided

**Solution:** Use only one:
```bash
# Admin operations (current)
./target/release/softkms generate --algorithm ed25519

# Token operations (Phase 2)
./target/release/softkms -t "token" generate --algorithm ed25519
```

### "Connection refused"

**Cause:** Daemon not running

**Solution:** Start the daemon:
```bash
./target/release/softkms-daemon --foreground
```

---

## What's Working vs Planned

### ✅ Working Today (v0.1.0)

- Admin passphrase authentication
- Token-based authentication
- Key generation (Ed25519, P-256, Falcon-512, Falcon-1024)
- Key signing and verification (all algorithms)
- Key listing/deletion
- Identity creation/revocation
- BIP39 seed import
- HD key derivation
- PKCS#11 basic operations
- REST API
- gRPC API

### ⏳ Future Features

- Custom policies
- TPM 2.0 binding
- Hardware token support

---

## See Also

- [IMPLEMENTATION_STATUS.md](../IMPLEMENTATION_STATUS.md) - Implementation status
- [docs/IDENTITIES.md](IDENTITIES.md) - Identity management details
- [docs/ARCHITECTURE.md](ARCHITECTURE.md) - System architecture
- [docs/SECURITY.md](SECURITY.md) - Security model
