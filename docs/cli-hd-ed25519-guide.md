# softKMS HD Wallet Ed25519 CLI Guide

A step-by-step guide for hierarchical deterministic (HD) Ed25519 key operations.

## Prerequisites

- softKMS daemon running
- Keystore initialized with passphrase

## Quick Start

```bash
# 1. Initialize (only needed once)
softkms init
Enter passphrase: ************
Keystore initialized successfully

# 2. Import a BIP39 seed
softkms import-seed \
  --mnemonic "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about" \
  --label myseed

# 3. Derive first Algorand address
softkms derive \
  --algorithm ed25519 \
  --seed myseed \
  --path "m/44'/283'/0'/0/0" \
  --label "algo-address-0"

# 4. Sign a message
softkms sign \
  --label "algo-address-0" \
  --data "Hello, Algorand!"

# 5. Verify signature
softkms verify \
  --label "algo-address-0" \
  --data "Hello, Algorand!" \
  --signature "..."
```

## Detailed Commands

### Initialize Keystore

Run once to set up the keystore with a passphrase. The daemon caches this passphrase for subsequent operations.

```bash
softkms init
```

### Import Seed

**From BIP39 mnemonic:**
```bash
softkms import-seed \
  --mnemonic "word1 word2 word3 ... word12" \
  --label "my-wallet"
```

**From raw seed (64 hex chars):**
```bash
softkms import-seed \
  --mnemonic "a8ba80028922d9fcfa055c78aede55b5c575bcd8d5a53168edf45f36d9ec8f4694592b4bc892907583e22669ecdf1b0409a9f3bd5549f2dd751b51360909cd05" \
  --label "hardware-backup"
```

### Derive Ed25519 Keys

Basic derivation with defaults:
```bash
softkms derive \
  --seed myseed \
  --path "m/44'/283'/0'/0/0"
```

Full options:
```bash
softkms derive \
  --algorithm ed25519 \
  --seed myseed \
  --path "m/44'/283'/0'/0/0" \
  --ctype 283 \
  --label "algo-address-0" \
  --scheme peikert
```

**Parameters:**
- `--algorithm`: ed25519 or p256 (default: ed25519)
- `--seed`: Seed ID or seed label
- `--path`: BIP44 derivation path (e.g., m/44'/283'/0'/0/0)
- `--ctype`: Coin type identifier (default: 283 for Algorand)
- `--scheme`: Derivation scheme - peikert (default) or v2
- `--label`: Optional label for the derived key

### P-256 Derivation (WebAuthn/Passkey)

```bash
softkms derive \
  --algorithm p256 \
  --seed myseed \
  --origin "github.com" \
  --user-handle "user123" \
  --counter 0 \
  --label "github-credential"
```

### Sign Data

```bash
# Sign with key label
softkms sign \
  --label "algo-address-0" \
  --data "message to sign"

# Sign with key ID
softkms sign \
  --key "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" \
  --data "message to sign"
```

### Verify Signatures

```bash
softkms verify \
  --label "algo-address-0" \
  --data "message to sign" \
  --signature "base64_encoded_signature"
```

### List Keys

```bash
# List all keys
softkms list

# Detailed view
softkms list --detailed
```

### Get Key Info

```bash
softkms info --label "algo-address-0"
# or
softkms info --key "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
```

### Delete Key

```bash
softkms delete --label "algo-address-0" --force
```

## BIP44 Path Structure

Format: `m / purpose' / ctype' / account' / change / index`

Examples:
- `m/44'/283'/0'/0/0` - Algorand, account 0, external, address 0
- `m/44'/283'/0'/0/1` - Algorand, account 0, external, address 1  
- `m/44'/283'/0'/1/0` - Algorand, account 0, internal (change), address 0
- `m/44'/283'/1'/0/0` - Algorand, account 1, external, address 0

**Path components:**
- `44'` - Purpose (hardened)
- `283'` - Coin type (hardened, 283 = Algorand)
- `0'` - Account (hardened)
- `0` - Change (0=external, 1=internal)
- `0` - Address index

## Derivation Schemes

**Peikert (default)**: Enhanced entropy scheme, recommended for Algorand
**V2**: Original IEEE BIP32-Ed25519 standard

```bash
# Peikert (default and recommended)
softkms derive --seed myseed --path "m/44'/283'/0'/0/0" --scheme peikert

# V2 (legacy compatibility)
softkms derive --seed myseed --path "m/44'/283'/0'/0/0" --scheme v2
```

## Complete Workflow Example

```bash
#!/bin/bash

# Initialize (one-time setup)
softkms init

# Import your seed
SEED_ID=$(softkms import-seed \
  --mnemonic "your actual mnemonic words here" \
  --label "main-wallet" | grep "ID:" | awk '{print $2}')

# Create multiple receiving addresses
for i in {0..4}; do
  softkms derive \
    --seed "main-wallet" \
    --path "m/44'/283'/0'/0/$i" \
    --label "receive-$i"
done

# Sign a transaction
SIGNATURE=$(softkms sign \
  --label "receive-0" \
  --data "transaction-data" | grep "Signature:" | awk '{print $2}')

echo "Addresses created and transaction signed!"
```

## Security Notes

1. **Passphrase caching**: The daemon caches the passphrase after `init`. No need to enter it repeatedly.
2. **Seed labels**: Use `--label` when importing seeds, then refer to them by label instead of UUID.
3. **Path hardening**: Hardened indices (marked with ') cannot be derived from public keys alone.
4. **Coin types**: Common values: 283 (Algorand), 0 (Bitcoin), 60 (Ethereum).

## Troubleshooting

**"Keystore not initialized"**: Run `softkms init` first.

**"Seed not found"**: Check available seeds with `softkms list`.

**"Invalid derivation path"**: Ensure format is `m/44'/ctype'/account'/change/index` with hardened markers (').

## See Also

- `softkms --help` - Show all commands
- BIP32: https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
- BIP44: https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki
