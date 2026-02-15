# PKCS#11 Provider Implementation Plan

**Last Updated**: 2026-02-15  
**Target Version**: v0.3

## Overview

Add native PKCS#11 support to softKMS, allowing existing tools (OpenSSH, Git, OpenSSL) to use softKMS as an HSM backend without modification.

## Goals

- **Zero-friction adoption**: Users install softKMS and immediately use it with existing tools
- **Standard compliance**: Implement PKCS#11 v2.40 interface
- **Seamless migration**: Existing SoftHSM users can switch to softKMS

## Architecture

### How PKCS#11 Works

PKCS#11 is a standard interface for cryptographic tokens (HSMs, smartcards). Applications load a PKCS#11 provider (`.so` library) and call standard functions to:
- Discover slots and tokens
- Open sessions
- Find and use keys
- Sign/verify data

### softKMS as PKCS#11 Provider

```
Application (OpenSSH/Git/OpenSSL)
         ↓
    PKCS#11 API
         ↓
libsoftkms-pkcs11.so (softKMS Provider)
         ↓
    softKMS Key Service
         ↓
    Encrypted Storage
```

## Implementation

### Current Status: Stub/MVP

The PKCS#11 module is currently a stub with basic structure. Full implementation is planned for future releases.

### Directory Structure

```
src/
├── pkcs11/                 # PKCS#11 provider (stub)
│   └── mod.rs             # Main entry, basic exports
├── lib.rs                 # Add pkcs11 module
└── ...
```

### Dependencies Added

```toml
# Cargo.toml
[dependencies]
cryptoki = "0.12"
```

Using `cryptoki` (parallaxsecond/rust-cryptoki):
- 100% documented
- Actively maintained
- Safe Rust wrapper around PKCS#11
- Tested with SoftHSM

### Current Module (v0.3 Stub)

The current `src/pkcs11/mod.rs` provides:
- Basic error types
- Provider info structure
- Module path helpers
- Initialization stub

This is a foundation for full PKCS#11 implementation in future releases.

### Supported Key Types

| Algorithm | PKCS#11 Mechanism | Status |
|-----------|-------------------|--------|
| Ed25519 | CKM_ED25519 | Phase 1 |
| P-256 | CKM_ECDSA | Future |
| RSA | CKM_RSA_PKCS | Future |

### Supported Functions

| Category | Functions | Priority |
|----------|-----------|----------|
| Context | C_Initialize, C_GetInfo, C_Finalize | 1 |
| Slots | C_GetSlotList, C_GetSlotInfo, C_GetTokenInfo | 1 |
| Sessions | C_OpenSession, C_CloseSession, C_Login, C_Logout | 2 |
| Objects | C_FindObjects, C_GetObjectAttribute | 2 |
| Signing | C_Sign, C_SignInit, C_Verify, C_VerifyInit | 3 |

### Key Mapping

```
softKMS Key                    PKCS#11 Object
─────────────────────────────────────────────────
KeyId (UUID)         →         CKA_ID (unique identifier)
Key label            →         CKA_LABEL
Ed25519 private key →         CKO_PRIVATE_KEY (CKK_ED25519)
Ed25519 public key  →         CKO_PUBLIC_KEY (CKK_ED25519)
Key algorithm       →         CKA_KEY_TYPE
```

### Build Output

```
target/release/
├── softkms-daemon          # Main daemon
├── softkms                 # CLI
└── libsoftkms-pkcs11.so   # PKCS#11 provider (shared library)
```

### Installation Paths

| Location | Use Case |
|----------|----------|
| `~/.softKMS/libsoftkms-pkcs11.so` | Development, user-local |
| `/usr/lib/libsoftkms-pkcs11.so` | System-wide installation |

## Usage Examples

### OpenSSH

```bash
# Configure SSH to use softKMS
export PKCS11_MODULE=~/.softKMS/libsoftkms-pkcs11.so

# Add key to SSH agent
ssh-add -s ~/.softKMS/libsoftkms-pkcs11.so

# Use with SSH
ssh -I pkcs11 user@host
```

### Git

```bash
# Configure Git to use SSH key from softKMS
export PKCS11_MODULE=~/.softKMS/libsoftkms-pkcs11.so
export GIT_SSH_COMMAND="ssh -I pkcs11"

# Clone using softKMS key
git clone git@github.com:user/repo.git
```

### OpenSSL

```bash
# Use softKMS key with OpenSSL
export PKCS11_MODULE=~/.softKMS/libsoftkms-pkcs11.so

# Generate CSR
openssl req -new -key ed25519:my-key-label -engine pkcs11 -keyform engine -out request.csr

# Sign certificate
openssl x509 -req -in request.css -signkey pkcs11:my-key-label -out cert.pem
```

## Implementation Phases

### Completed (v0.3)
- [x] Create `src/pkcs11/` module structure
- [x] Add cryptoki dependency
- [x] Basic error types
- [x] Provider info structure

### Future Phases

#### Phase 1: Core Infrastructure
- [ ] Implement context (C_Initialize, C_GetInfo, C_Finalize)
- [ ] Set up logging and error handling
- [ ] Dynamic library compilation

#### Phase 2: Slot Management
- [ ] Implement C_GetSlotList
- [ ] Implement C_GetSlotInfo
- [ ] Implement C_GetTokenInfo
- [ ] Map softKMS storage to PKCS#11 token

#### Phase 3: Sessions
- [ ] Implement C_OpenSession
- [ ] Implement C_CloseSession
- [ ] Implement C_Login (PIN = softKMS passphrase)
- [ ] Implement C_Logout

#### Phase 4: Objects
- [ ] Implement C_FindObjects
- [ ] Implement C_GetObjectAttribute
- [ ] Map softKMS keys to PKCS#11 objects
- [ ] Handle private/public key pairs

#### Phase 5: Cryptographic Operations
- [ ] Implement C_SignInit, C_Sign (Ed25519)
- [ ] Implement C_VerifyInit, C_Verify (Ed25519)
- [ ] Integrate with softKMS crypto engines

#### Phase 6: Build & Integration
- [ ] Compile as shared library (`.so`)
- [ ] Add CLI command to show PKCS#11 module path
- [ ] Test with OpenSSH, OpenSSL

## Future Enhancements

- [ ] RSA key support
- [ ] P-256/EC key support
- [ ] Key generation (C_GenerateKeyPair)
- [ ] Import/Export (C_ImportKey)
- [ ] Multiple tokens (key sets)
- [ ] Hardware token support

## Testing

### Manual Testing
```bash
# Build
cargo build --release

# Test with OpenSSL
openssl engine -t pkcs11 - Verification/Tests

# Test with OpenSSH
ssh-add -l
```

### Integration Tests
- Test with SoftHSM for reference
- Test with actual PKCS#11 applications

## References

- [PKCS#11 v2.40 Specification](http://docs.oasis-open.org/pkcs11/pkcs11-spec/v2.40/pkcs11-spec-v2.40.html)
- [cryptoki crate](https://docs.rs/cryptoki/latest/cryptoki/)
- [SoftHSM2](https://github.com/opendnssec/SoftHSM2)
