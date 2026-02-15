# PKCS#11 Integration Guide

This document describes the PKCS#11 implementation in softKMS, architecture decisions, and interoperability details.

## Overview

softKMS provides a PKCS#11 module (`libsoftkms.so`) that allows existing applications to use softKMS as an HSM (Hardware Security Module) backend. The module acts as a PKCS#11 client that communicates with the softKMS daemon via gRPC.

## Architecture

```
┌─────────────────┐     gRPC      ┌─────────────────┐
│  Application    │               │  softKMS       │
│  (OpenSSH,      │───────────────│  Daemon        │
│   Git,          │   libsoftkms  │  (keys stored  │
│   OpenSSL)      │      .so      │   locally)     │
└─────────────────┘               └─────────────────┘
```

### Key Design Decisions

1. **Client-Server Model**: The PKCS#11 module is a client to the softKMS daemon. Keys never leave the daemon - all cryptographic operations happen server-side.

2. **Same Crate, Not Separate**: The PKCS#11 module is built-in by default (not optional), ensuring it's always available.

3. **ECDSA P-256 First**: Initial implementation supports ECDSA P-256 (secp256r1) for maximum compatibility with existing tools and workflows.

## PKCS#11 Implementation Details

### Supported Mechanisms

| Mechanism | Value | Purpose |
|-----------|-------|---------|
| CKM_ECDSA | 0x1001 | Raw ECDSA signing/verification |
| CKM_EC_KEY_PAIR_GEN | 0x1050 | EC key pair generation |
| CKM_ECDSA_SHA256 | 0x1041 | ECDSA with SHA-256 |
| CKM_ECDSA_SHA384 | 0x1042 | ECDSA with SHA-384 |
| CKM_ECDH | 0x1040 | EC key derivation (compatibility) |
| CKM_ECDH1_DERIVE | 0x1051 | EC DH key derivation |

### Mechanism Flags

| Mechanism | Flags |
|-----------|-------|
| CKM_ECDSA | CKF_SIGN, CKF_VERIFY |
| CKM_EC_KEY_PAIR_GEN | CKF_GENERATE_KEY_PAIR, CKF_GENERATE |
| CKM_ECDSA_SHA256 | CKF_SIGN, CKF_VERIFY |
| CKM_ECDSA_SHA384 | CKF_SIGN, CKF_VERIFY |
| CKM_ECDH | CKF_DERIVE, CKF_GENERATE_KEY_PAIR |
| CKM_ECDH1_DERIVE | CKF_DERIVE |

### Supported Key Types

- **EC**: P-256 (prime256v1/secp256r1)
- Key sizes: 256-521 bits

## Interoperability Research

We researched several PKCS#11 implementations to ensure maximum compatibility:

### SoftHSM2

- Uses `CKM_EC_KEY_PAIR_GEN` for key generation
- Uses `CKM_ECDH1_DERIVE` (not CKM_ECDH) for derivation
- Does not advertise CKM_ECDH with CKF_GENERATE_KEY_PAIR

### tpm2-pkcs11

- Had similar pkcs11-tool compatibility issues
- Fixed by proper CKA_* attribute handling

### p11tool (GnuTLS)

- Better fallback/error handling than pkcs11-tool
- Works with most PKCS#11 modules

### pkcs11-tool (OpenSC)

- Known issues with EC key generation mechanism selection
- Works when mechanism is explicitly specified (`-m 0x1050`)

## Implementation Notes

### Why CKM_ECDH Has CKF_GENERATE_KEY_PAIR

Some tools (including pkcs11-tool) check CKM_ECDH during key generation validation. While semantically incorrect (ECDH is a derivation mechanism, not generation), we include this flag for compatibility with tools that expect it.

### Why Mechanism Must Be Specified

Due to pkcs11-tool's internal mechanism selection logic, automatic mechanism detection may fail. Users should specify:
```bash
pkcs11-tool --module libsoftkms.so -m 0x1050 --keypairgen ...
```

This is a known limitation affecting multiple PKCS#11 modules, not just softKMS.

## Building

The PKCS#11 module is built automatically:

```bash
cargo build
```

Output: `target/debug/libsoftkms.so` (or `target/release/libsoftkms.so`)

## Configuration

### Starting the Daemon

```bash
# Start daemon in background
./target/debug/softkms-daemon &

# Initialize with passphrase (first time)
./target/debug/softkms -p <passphrase> init --confirm false
```

### Environment Variables

- `SOFTKMS_DAEMON_ADDR`: Daemon address (default: `127.0.0.1:50051`)

## Security Considerations

1. **Keys Stay in Daemon**: Private keys never leave the softKMS daemon
2. **Passphrase Protection**: Keys are encrypted with the user's passphrase
3. **Local Communication**: gRPC communication is localhost-only by default

## Future Enhancements

- Ed25519 support
- RSA key generation
- Key derivation (ECDH)
- Hardware token support
