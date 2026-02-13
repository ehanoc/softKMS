# Next Steps - Implementation Roadmap

**Current State**: v0.1 - Project structure complete, builds successfully
**Next Milestone**: v0.2 - Functional daemon with basic key operations

## Priority 1: Core Functionality (Week 1)

### 1.1 Configuration System
**Status**: Not implemented  
**Files**: `src/config.rs` (to create)  
**Priority**: HIGH

```rust
// Load from /etc/softkms/config.toml
pub struct Config {
    storage: StorageConfig,
    api: ApiConfig,
    logging: LoggingConfig,
}
```

**Tasks**:
- [ ] Create `src/config.rs` module
- [ ] Implement TOML config parsing
- [ ] Add environment variable overrides
- [ ] Create example config.toml
- [ ] Add config validation

**Success Criteria**: Daemon loads config from file

---

### 1.2 Storage Encryption
**Status**: File storage exists, no encryption  
**Files**: `src/storage/file.rs`, `src/crypto/`  
**Priority**: HIGH

**Current**:
```rust
// Keys stored in plaintext (encrypted_data param is just passed through)
tokio::fs::write(self.key_path(id), encrypted_data)
```

**Target**:
```rust
// Master PIN -> PBKDF2 -> AES-GCM encrypt
pub struct EncryptionWrapper {
    master_key: Secret<[u8; 32]>,
}
```

**Tasks**:
- [ ] Create `src/crypto/encryption.rs`
- [ ] Implement master key derivation (PBKDF2)
- [ ] Add AES-GCM encryption wrapper
- [ ] Integrate with FileStorage
- [ ] Add secure memory clearing (zeroize)

**Success Criteria**: Keys encrypted at rest with master PIN

---

### 1.3 Daemon Startup
**Status**: Stub exists  
**Files**: `src/daemon/mod.rs`, `src/main.rs`  
**Priority**: HIGH

**Current**:
```rust
pub async fn start(config: Config) -> Result<()> {
    // TODO: Implement daemon startup
    Ok(())
}
```

**Target**:
- [ ] Initialize storage backend
- [ ] Start API servers (gRPC + REST)
- [ ] Handle signals (SIGTERM, SIGINT)
- [ ] PID file management
- [ ] Logging setup
- [ ] Health check endpoint

**Success Criteria**: Daemon runs, responds to health checks

---

## Priority 2: Cryptographic Operations (Week 2)

### 2.1 Ed25519 Implementation
**Status**: Trait defined, no implementations  
**Files**: `src/crypto/ed25519.rs` (to create)  
**Priority**: HIGH

**Tasks**:
- [ ] Create `src/crypto/ed25519.rs`
- [ ] Implement `CryptoEngine` trait for Ed25519
- [ ] Use `ed25519-dalek` crate
- [ ] Key generation
- [ ] Sign/Verify
- [ ] Integration tests

**Success Criteria**: Can generate Ed25519 key and sign data

---

### 2.2 Key Generation API
**Status**: gRPC stub exists  
**Files**: `src/api/grpc.rs`, `src/api/mod.rs`  
**Priority**: MEDIUM

**Tasks**:
- [ ] Define protobuf for key generation
- [ ] Implement gRPC CreateKey handler
- [ ] Store generated keys in FileStorage
- [ ] Return key metadata

**Success Criteria**: Client can generate key via gRPC

---

### 2.3 Signing API
**Status**: Stub exists  
**Files**: `src/api/grpc.rs`  
**Priority**: MEDIUM

**Tasks**:
- [ ] Implement gRPC Sign handler
- [ ] Load key from storage
- [ ] Decrypt key (using master PIN)
- [ ] Sign data
- [ ] Return signature
- [ ] Clear key from memory after use

**Success Criteria**: Can sign data and verify with public key

---

## Priority 3: HD Wallet Support (Week 3)

### 3.1 BIP32 Implementation
**Status**: Module stub exists  
**Files**: `src/hd_wallet/mod.rs`  
**Priority**: MEDIUM

**Tasks**:
- [ ] Import or implement BIP32
- [ ] Master key generation from seed
- [ ] Child key derivation (hardened/non-hardened)
- [ ] Path parsing (m/44'/283'/0'/0/0)
- [ ] ARC-0052 compatibility

**Success Criteria**: Can derive keys from seed using standard paths

---

### 3.2 Seed Import/Export
**Status**: Not implemented  
**Files**: `src/hd_wallet/`, `src/api/`  
**Priority**: MEDIUM

**Tasks**:
- [ ] BIP39 mnemonic support (optional for now)
- [ ] Raw seed import (64 bytes)
- [ ] Seed storage with extra protection
- [ ] gRPC ImportSeed API
- [ ] gRPC DeriveKey API

**Success Criteria**: Import seed, derive child keys

---

## Priority 4: PKCS#11 Compatibility (Week 4)

### 4.1 PKCS#11 FFI Layer
**Status**: Not started  
**Files**: `pkcs11-module/src/`  
**Priority**: MEDIUM

**Tasks**:
- [ ] Create `pkcs11-module/Cargo.toml`
- [ ] Implement C ABI exports
- [ ] Implement C_Initialize, C_Finalize
- [ ] Implement C_OpenSession, C_CloseSession
- [ ] Implement C_Login (PIN authentication)
- [ ] Implement C_GenerateKey
- [ ] Implement C_Sign

**Success Criteria**: OpenSSL can use softKMS via PKCS#11

---

## Priority 5: Polish & Integration (Week 5)

### 5.1 CLI Implementation
**Status**: Stubs only  
**Files**: `cli/src/main.rs`  
**Priority**: LOW

**Tasks**:
- [ ] Connect CLI to gRPC client
- [ ] Implement `generate` command
- [ ] Implement `list` command
- [ ] Implement `sign` command
- [ ] Implement `import-seed` command
- [ ] Implement `derive` command

**Success Criteria**: Full CLI functionality

---

### 5.2 Testing
**Status**: 0 tests  
**Files**: `tests/`, `src/*/tests/`  
**Priority**: HIGH

**Tasks**:
- [ ] Unit tests for storage
- [ ] Unit tests for crypto
- [ ] Integration tests for API
- [ ] PKCS#11 compatibility tests
- [ ] HD wallet derivation tests

**Success Criteria**: >80% test coverage

---

### 5.3 Documentation
**Status**: Partial  
**Priority**: MEDIUM

**Tasks**:
- [ ] API documentation (rustdoc)
- [ ] Configuration guide
- [ ] Deployment guide (Docker)
- [ ] SoftHSM migration guide

---

## Quick Reference: What to Start With

**Tomorrow Morning**:
1. Run `./build.sh` to verify everything still works
2. Read STATUS.md to understand current state
3. Pick Priority 1.1 (Configuration) or 1.2 (Storage Encryption)
4. Check existing code in `src/storage/file.rs` for patterns

**Key Files to Understand**:
- `src/lib.rs` - Core types and error handling
- `src/storage/mod.rs` - Storage trait
- `src/storage/file.rs` - Actual implementation
- `src/api/mod.rs` - API coordinator (stubs)

**Dependencies Ready**:
- All deps in Cargo.toml are working
- Build command: `./build.sh`
- No toolchain issues expected

**Context from Related Projects**:
- See `docs/ARCHITECTURE.md` for detailed design patterns
- softKMS follows modern Rust async patterns throughout
