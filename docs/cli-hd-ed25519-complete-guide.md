# softKMS HD Wallet Ed25519 Complete CLI Guide

A step-by-step guide from initialization to advanced HD Ed25519 operations.

## Table of Contents
1. [Initialization](#1-initialization)
2. [Import Seed](#2-import-seed)
3. [Derive Ed25519 Keys](#3-derive-ed25519-keys)
4. [Sign Data](#4-sign-data)
5. [Verify Signatures](#5-verify-signatures)
6. [Watch-Only Wallets (xpub)](#6-watch-only-wallets-xpub)
7. [Batch Operations](#7-batch-operations)
8. [Complete Workflow Example](#8-complete-workflow-example)

---

## 1. Initialization

### Start the softKMS daemon

First, ensure the daemon is running:

```bash
# Start the daemon (in a separate terminal or background)
softkms-daemon &

# Or with custom options
softkms-daemon --storage /data/softkms --port 50051
```

### Initialize the keystore

```bash
# Initialize with passphrase
softkms init --confirm true

# You'll be prompted:
Enter passphrase: ********
Confirm passphrase: ********
Keystore initialized successfully

# Or without confirmation
softkms init --confirm false
```

**Note**: This only needs to be done once per keystore. The passphrase is prompted once during init and cached by the daemon for subsequent operations.

---

## 2. Import Seed

### From BIP39 mnemonic

```bash
# Import from 12/24-word mnemonic
softkms import-seed \
  --mnemonic "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about" \
  --label "my-main-wallet"

# Output:
# Seed imported successfully:
#   ID: a1b2c3d4-e5f6-7890-abcd-ef1234567890
#   Created: 2026-02-14T10:30:00Z

# Save the seed ID for later use
export SEED_ID="a1b2c3d4-e5f6-7890-abcd-ef1234567890"
```

### From raw seed bytes

```bash
# Import from 64-byte hex seed
softkms import-seed \
  --mnemonic "a8ba80028922d9fcfa055c78aede55b5c575bcd8d5a53168edf45f36d9ec8f4694592b4bc892907583e22669ecdf1b0409a9f3bd5549f2dd751b51360909cd05" \
  --label "hardware-wallet-backup"

# Output:
# Seed imported successfully:
#   ID: b2c3d4e5-f6a7-8901-bcde-f23456789012
```

### Verify seed import

```bash
# List all seeds
softkms list --detailed

# Filter by type
softkms list | grep seed
```

---

## 3. Derive Ed25519 Keys

### Basic derivation (Algorand example)

```bash
# Derive first Algorand address
# Coin type (283) is embedded in the path
softkms derive --algorithm ed25519 \
  --seed $SEED_ID \
  --path "m/44'/283'/0'/0/0" \
  --label "algo-main-address-0"

# Output:
# Ed25519 key derived successfully:
#   Key ID: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
#   Algorithm: ed25519
#   Public Key (base64): ZWJn+Kj8C7Q3lP3...
#   Address: algo1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq
#   Stored: true
#   Created: 2026-02-14T10:30:00Z
```

### Choose derivation scheme

```bash
# Peikert scheme (default, enhanced entropy)
softkms derive --algorithm ed25519 \
  --seed $SEED_ID \
  --path "m/44'/283'/0'/0/0" \
  --scheme peikert \
  --label "algo-peikert"

# V2 scheme (original IEEE standard)
softkms derive --algorithm ed25519 \
  --seed $SEED_ID \
  --path "m/44'/283'/0'/0/0" \
  --scheme v2 \
  --label "algo-v2"
```

### Multiple accounts

```bash
# Create multiple accounts from same seed

# Account 0 - Personal
softkms derive --algorithm ed25519 \
  --seed $SEED_ID \
  --path "m/44'/283'/0'/0/0" \
  --label "personal-main"

# Account 1 - Business  
softkms derive --algorithm ed25519 \
  --seed $SEED_ID \
  --path "m/44'/283'/1'/0/0" \
  --label "business-main"

# Account 2 - Savings
softkms derive --algorithm ed25519 \
  --seed $SEED_ID \
  --path "m/44'/283'/2'/0/0" \
  --label "savings-main"
```

### List derived keys

```bash
# List all keys
softkms list --detailed

# List only Ed25519 keys
softkms list | grep ed25519

# Get specific key info
softkms info --key <key-uuid>

# Show derivation details
softkms info --key <key-uuid> --verbose
```

---

## 4. Sign Data

### Sign text data

```bash
# Sign a message
softkms sign \
  --key <derived-key-uuid> \
  --data "Hello, Algorand!"

# Output:
# Signature: MTExMTExMTExM...
# Algorithm: ed25519
```

### Sign using label

```bash
# Instead of key ID, use label
softkms sign \
  --label "algo-main-address-0" \
  --data "Hello, Algorand!"
```

### Sign file contents

```bash
# Sign a file
softkms sign \
  --key <key-uuid> \
  --file /path/to/transaction.json

# Save signature to file
softkms sign \
  --key <key-uuid> \
  --data "message" \
  --output signature.bin
```

---

## 5. Verify Signatures

### Verify with stored key

```bash
# Verify a signature
softkms verify \
  --key <key-uuid> \
  --data "Hello, Algorand!" \
  --signature "MTExMTExMTExM..."

# Output:
# Signature is VALID
```

### Verify with label

```bash
softkms verify \
  --label "algo-main-address-0" \
  --data "Hello, Algorand!" \
  --signature "MTExMTExMTExM..."
```

### Verify with public key directly

```bash
softkms verify \
  --public-key "7bda7ac12627b2c259f1df6875d30c10b35f55b33ad2cc8ea2736eaa3ebcfab9" \
  --data "Hello, Algorand!" \
  --signature "MTExMTExMTExM..."
```

---

## 6. Watch-Only Wallets (xpub)

### Import an xpub

xpub allows you to derive child public keys without having the private key.

```bash
# Import xpub (64 bytes = 32 bytes public key + 32 bytes chain code)
softkms import-xpub \
  --xpub "7bda7ac12627b2c259f1df6875d30c10b35f55b33ad2cc8ea2736eaa3ebcfab9d4c5b6e7f8a9b0c1d2e3f4051627384950" \
  --coin-type 283 \
  --account 0 \
  --label "watch-only-wallet"

# Output:
# XPub imported successfully:
#   XPub ID: yyyyyyyy-yyyy-yyyy-yyyy-yyyyyyyyyyyy
#   Created: 2026-02-14T10:30:00Z

export XPUB_ID="yyyyyyyy-yyyy-yyyy-yyyy-yyyyyyyyyyyy"
```

### Derive public keys from xpub

```bash
# Derive child public key at index 0
softkms derive-public \
  --xpub $XPUB_ID \
  --index 0

# Output:
# Public key derived successfully:
#   Key ID: zzzzzzzz-zzzz-zzzz-zzzz-zzzzzzzzzzzz
#   Public Key (base64): ZWJn+Kj8C7Q3lP3...
#   Address: algo1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq
#   Path: m/44'/283'/0'/0/0

# Derive with custom HRP (Human Readable Prefix)
softkms derive-public \
  --xpub $XPUB_ID \
  --index 1 \
  --hrp "algo"

# Multiple derivations
for i in {0..9}; do
  softkms derive-public \
    --xpub $XPUB_ID \
    --index $i \
    --hrp "algo"
  echo "---"
done
```

**Security note**: xpub can only derive soft (non-hardened) indices. It cannot sign or access hardened paths.

---

## 7. Batch Operations

### Batch derive multiple addresses

For production use, you typically want to derive many addresses at once:

```bash
#!/bin/bash

# Configuration
SEED_ID="your-seed-uuid-here"
COIN_TYPE=283
ACCOUNT=0
START_INDEX=0
COUNT=20

# Create a batch script
for i in $(seq $START_INDEX $((START_INDEX + COUNT - 1))); do
  echo "Deriving address $i..."
  
  softkms derive --algorithm ed25519 \
    --seed $SEED_ID \
    --path "m/44'/$COIN_TYPE'/$ACCOUNT'/0/$i" \
    --label "algo-recv-$i"
done

# Check all derived keys
softkms list | grep "algo-recv"
```

### Automated batch script

```bash
#!/bin/bash
# batch_derive.sh - Generate multiple addresses

SEED_ID=$1
COUNT=${2:-10}
COIN_TYPE=${3:-283}
OUTPUT_FILE="addresses_$(date +%Y%m%d_%H%M%S).txt"

echo "Generating $COUNT addresses..."
echo "Seed: $SEED_ID" > $OUTPUT_FILE
echo "Coin Type: $COIN_TYPE" >> $OUTPUT_FILE
echo "================================" >> $OUTPUT_FILE

for i in $(seq 0 $((COUNT - 1))); do
  RESULT=$(softkms derive --algorithm ed25519 \
    --seed $SEED_ID \
    --path "m/44'/$COIN_TYPE'/0'/0/$i" 2>&1)
  
  KEY_ID=$(echo "$RESULT" | grep "Key ID:" | cut -d' ' -f3)
  ADDRESS=$(echo "$RESULT" | grep "Address:" | cut -d' ' -f3)
  
  echo "$i,$KEY_ID,$ADDRESS" >> $OUTPUT_FILE
  echo "Address $i: $ADDRESS"
done

echo "Addresses saved to $OUTPUT_FILE"
```

**Usage**:
```bash
chmod +x batch_derive.sh
./batch_derive.sh <seed-uuid> 20 283
```

### Batch derivation for different purposes

```bash
#!/bin/bash
# Derive addresses for different purposes

SEED_ID="<your-seed-uuid>"

# External addresses (receiving)
echo "=== External Addresses ==="
for i in {0..4}; do
  softkms derive --algorithm ed25519 \
    --seed $SEED_ID \
    --path "m/44'/283'/0'/0/$i" \
    --label "external-$i"
done

# Internal addresses (change)
echo "=== Internal Addresses ==="
for i in {0..4}; do
  softkms derive --algorithm ed25519 \
    --seed $SEED_ID \
    --path "m/44'/283'/0'/1/$i" \
    --label "internal-$i"
done

# Different accounts
echo "=== Account 1 (Business) ==="
for i in {0..2}; do
  softkms derive --algorithm ed25519 \
    --seed $SEED_ID \
    --path "m/44'/283'/1'/0/$i" \
    --label "business-$i"
done
```

---

## 8. Complete Workflow Example

### Scenario: Setting up an Algorand wallet

```bash
#!/bin/bash

# Step 1: Initialize (if not already done)
echo "Step 1: Initializing softKMS..."
softkms init --confirm false

# Step 2: Import your seed
# Use your actual mnemonic here
MNEMONIC="abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
echo "Step 2: Importing seed..."
SEED_OUTPUT=$(softkms import-seed --mnemonic "$MNEMONIC" --label "algo-wallet")
SEED_ID=$(echo "$SEED_OUTPUT" | grep "ID:" | awk '{print $2}')
echo "Seed ID: $SEED_ID"

# Step 3: Derive your main address
echo "Step 3: Deriving main address..."
MAIN_OUTPUT=$(softkms derive --algorithm ed25519 \
  --seed $SEED_ID \
  --path "m/44'/283'/0'/0/0" \
  --label "algo-main")
MAIN_KEY=$(echo "$MAIN_OUTPUT" | grep "Key ID:" | awk '{print $3}')
MAIN_ADDR=$(echo "$MAIN_OUTPUT" | grep "Address:" | awk '{print $2}')
echo "Main Address: $MAIN_ADDR"

# Step 4: Derive a few receiving addresses
echo "Step 4: Deriving receiving addresses..."
for i in {1..3}; do
  RECV_OUTPUT=$(softkms derive --algorithm ed25519 \
    --seed $SEED_ID \
    --path "m/44'/283'/0'/0/$i" \
    --label "algo-recv-$i")
  RECV_ADDR=$(echo "$RECV_OUTPUT" | grep "Address:" | awk '{print $2}')
  echo "Receiving Address $i: $RECV_ADDR"
done

# Step 5: Sign a message
echo "Step 5: Signing a message..."
SIGNATURE=$(softkms sign \
  --key $MAIN_KEY \
  --data "Hello from softKMS!" | grep "Signature:" | awk '{print $2}')
echo "Signature: $SIGNATURE"

# Step 6: Verify the signature
echo "Step 6: Verifying signature..."
softkms verify \
  --key $MAIN_KEY \
  --data "Hello from softKMS!" \
  --signature "$SIGNATURE"

# Step 7: List all keys
echo "Step 7: Wallet summary..."
softkms list --detailed | grep -E "(ID:|Algorithm:|Label:)"

echo "=== Wallet Setup Complete ==="
echo "Main Address: $MAIN_ADDR"
echo "Seed ID: $SEED_ID"
```

---

## Common BIP44 Paths

| Path | Purpose | Example |
|------|---------|---------|
| `m/44'/283'/0'/0/0` | Algorand, account 0, external, address 0 | Main receiving |
| `m/44'/283'/0'/0/1` | Algorand, account 0, external, address 1 | Second receiving |
| `m/44'/283'/0'/1/0` | Algorand, account 0, internal, address 0 | Change address |
| `m/44'/283'/1'/0/0` | Algorand, account 1, external, address 0 | Business account |
| `m/44'/0'/0'/0/0` | Identity (SLIP-44), account 0 | Identity key |

## Security Best Practices

1. **Backup your seed**: It's the root of all keys
2. **Use strong passphrases**: Protect your keystore
3. **Use xpub for receiving**: Don't expose private keys
4. **Ephemeral for one-time**: Use `--store false` for temporary addresses
5. **Label clearly**: Helps identify key purposes
6. **Regular audits**: Review with `softkms list`

## Troubleshooting

| Issue | Solution |
|-------|----------|
| "Seed not found" | Check UUID with `softkms list --detailed` |
| "Invalid derivation path" | Ensure format: `m/44'/283'/0'/0/0` (hardened markers required) |
| "Cannot derive hardened from xpub" | Use indices < 2147483648 for public derivation |
| "Keystore not initialized" | Run `softkms init` first |

## See Also

- `softkms --help` - Show all commands
- `softkms <command> --help` - Command-specific help
- BIP32: https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
- BIP44: https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki
