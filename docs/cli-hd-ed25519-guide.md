# softKMS HD Wallet Ed25519 CLI Guide

Quick reference for hierarchical deterministic (HD) Ed25519 key operations.

> For detailed workflows, batch operations, and xpub support, see [cli-hd-ed25519-complete-guide.md](cli-hd-ed25519-complete-guide.md).

## Prerequisites

- softKMS daemon running
- Keystore initialized: `softkms init`

## Quick Start

```bash
# 1. Initialize (once)
softkms init

# 2. Import BIP39 seed
softkms import-seed --mnemonic "abandon abandon ... about" --label myseed

# 3. Derive key (Algorand example)
softkms derive --algorithm ed25519 --seed myseed \
  --path "m/44'/283'/0'/0/0" --label "algo-address-0"

# 4. Sign
softkms sign --label "algo-address-0" --data "Hello"

# 5. Verify
softkms verify --label "algo-address-0" --data "Hello" --signature "..."
```

## Commands

### Initialize
```bash
softkms init
```

### Import Seed
```bash
# BIP39 mnemonic
softkms import-seed --mnemonic "word1 word2 ..." --label "mywallet"

# Raw hex seed (64 bytes)
softkms import-seed --mnemonic "a8ba8002..." --label "backup"
```

### Derive Ed25519 Keys
```bash
# Basic - coin type embedded in path
softkms derive --algorithm ed25519 --seed myseed \
  --path "m/44'/283'/0'/0/0"

# Full options
softkms derive --algorithm ed25519 --seed myseed \
  --path "m/44'/283'/0'/0/0" \
  --scheme peikert \
  --label "my-address"
```

### Derive P-256 Keys (WebAuthn)
```bash
softkms derive --algorithm p256 --seed myseed \
  --origin "github.com" \
  --user-handle "user123" \
  --counter 0 \
  --label "github-key"
```

### Sign/Verify
```bash
# Sign
softkms sign --label "my-address" --data "message"
softkms sign --key <uuid> --data "message"

# Verify
softkms verify --label "my-address" --data "message" --signature "base64..."
```

### Key Management
```bash
softkms list
softkms info --label "my-address"
softkms delete --label "my-address" --force
```

## BIP44 Path Format

`m / purpose' / coin_type' / account' / change / index`

| Chain | Coin Type | Path Example |
|-------|-----------|--------------|
| Algorand | 283 | `m/44'/283'/0'/0/0` |
| Bitcoin | 0 | `m/44'/0'/0'/0/0` |
| Ethereum | 60 | `m/44'/60'/0'/0/0` |

## Derivation Schemes

- `peikert` (default) - Enhanced entropy, recommended
- `v2` - Original IEEE standard

## See Also

- `softkms --help`
- `cli-hd-ed25519-complete-guide.md` - Detailed workflows
- BIP32/BIP44 specs
