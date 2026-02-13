# softKMS - Modern Software Key Management System

A modern, modular, and secure alternative to SoftHSM designed for Linux systems with support for HD wallets, pluggable cryptographic schemes, and contemporary deployment patterns.

**Use Cases:**
- **Enterprise Key Management**: Secure key storage with PKCS#11, gRPC, and REST APIs
- **HD Wallet Infrastructure**: BIP32/BIP44 key derivation for cryptocurrency operations
- **Development & Testing**: Software HSM for development environments
- **Passkey Backup**: WebAuthn/FIDO2 authenticator with seed-based recovery

## Overview

softKMS is a software-based Key Management System (KMS) that provides:
- **Modern Architecture**: Modular design with pluggable components
- **HD Wallet Support**: Built-in hierarchical deterministic (HD) key derivation (BIP32/44)
- **Multiple APIs**: gRPC, REST, and PKCS#11 compatibility
- **Container-Native**: First-class Docker and Kubernetes support
- **Cross-Platform**: Native packages for Debian, Fedora, and other Linux distributions
- **WebAuthn Support**: *Optional* FIDO2 authenticator for Passkey backup/recovery (see below)

## Why softKMS?

### Compared to SoftHSM

| Feature | SoftHSM | softKMS |
|---------|---------|---------|
| **Status** | Abandoned | Actively maintained |
| **Architecture** | Monolithic C | Modular Rust with FFI |
| **HD Wallets** | ❌ | ✅ BIP32/44 |
| **Crypto Agility** | Fixed (RSA/ECC) | Pluggable (Lattice, etc.) |
| **APIs** | PKCS#11 only | PKCS#11 + gRPC + REST |
| **Deployment** | Manual | Docker + systemd + packages |
| **Storage** | File-only | Pluggable backends |
| **Monitoring** | Basic | Prometheus metrics |

## Architecture

```mermaid
flowchart TB
    subgraph "🌐 Client Zone"
        CLI["🖥️ CLI Client"]
        APP["📱 Applications"]
        WEB["🌐 Web Services"]
    end

    subgraph "🚪 Gateway Layer"
        direction LR
        GRPC["⚡ gRPC:50051"]
        REST["🌐 REST:8080"]
        PKCS["🔐 PKCS#11"]
    end

    subgraph "🔒 Security Fortress"
        direction TB
        
        subgraph "🛡️ Core Citadel"
            KEY["🔑 Key Service"]
            CRYPTO["⚔️ Crypto Engines"]
            HD["🌳 HD Wallet\nBIP32/44"]
        end
        
        subgraph "🧠 Brain Center"
            SEC["🔐 Security Manager"]
            MEM["🧹 Memory Guard"]
            AUDIT["📋 Audit Logger"]
        end
    end

    subgraph "💾 Storage Vaults"
        direction LR
        FILE["📁 Encrypted\nFiles"]
        TPM["🔒 TPM2\nHardware"]
        VAULT["☁️ HashiCorp\nVault"]
    end

    subgraph "🎯 Optional Modules"
        WEBAUTHN["🎭 WebAuthn\nFIDO2"]
    end

    CLI --> GRPC
    APP --> REST
    WEB --> PKCS
    
    GRPC --> KEY
    REST --> KEY
    PKCS --> KEY
    
    KEY --> CRYPTO
    KEY --> HD
    KEY --> SEC
    
    CRYPTO --> MEM
    SEC --> MEM
    
    KEY --> FILE
    KEY --> TPM
    KEY --> VAULT
    
    CRYPTO -.-> WEBAUTHN
    
    style CLI fill:#e1f5ff,stroke:#01579b,stroke-width:3px
    style APP fill:#e1f5ff,stroke:#01579b,stroke-width:3px
    style WEB fill:#e1f5ff,stroke:#01579b,stroke-width:3px
    style GRPC fill:#fff3e0,stroke:#e65100,stroke-width:3px
    style REST fill:#fff3e0,stroke:#e65100,stroke-width:3px
    style PKCS fill:#fff3e0,stroke:#e65100,stroke-width:3px
    style KEY fill:#f3e5f5,stroke:#6a1b9a,stroke-width:4px
    style CRYPTO fill:#e8f5e9,stroke:#2e7d32,stroke-width:3px
    style HD fill:#e8f5e9,stroke:#2e7d32,stroke-width:3px
    style SEC fill:#ffebee,stroke:#c62828,stroke-width:4px
    style MEM fill:#fff9c4,stroke:#f57f17,stroke-width:3px
    style FILE fill:#e0f2f1,stroke:#00695c,stroke-width:3px
    style TPM fill:#e0f2f1,stroke:#00695c,stroke-width:3px
    style VAULT fill:#e0f2f1,stroke:#00695c,stroke-width:3px
    style WEBAUTHN fill:#fce4ec,stroke:#ad1457,stroke-width:2px,stroke-dasharray: 5 5
```

**Legend:**
- 🌐 **Client Zone** - Where users and applications live
- 🚪 **Gateway Layer** - Entry points (gRPC, REST, PKCS#11)
- 🔒 **Security Fortress** - Core protection with Security Manager & Memory Guard
- 💾 **Storage Vaults** - Where encrypted keys sleep safely
- 🎯 **Optional** - WebAuthn for FIDO2/Passkey support

## Core Principles

### 1. Separation of Concerns
- **API Layer**: Multiple interfaces (gRPC, REST, PKCS#11)
- **Core Engine**: Secure, isolated key operations
- **Storage Layer**: Pluggable backends (file, TPM, cloud)

### 2. Pluggable Architecture
```rust
// Example: Adding a new cryptographic scheme
trait CryptoEngine {
    fn generate_key(&self, params: KeyParams) -> Result<Key, Error>;
    fn sign(&self, key: &Key, data: &[u8]) -> Result<Signature, Error>;
    fn verify(&self, key: &Key, data: &[u8], sig: &Signature) -> Result<bool, Error>;
}

// Implement for Ed25519, ECDSA, RSA, Lattice, etc.
```

### 3. Container-First
```dockerfile
FROM scratch
COPY softkms-daemon /bin/
VOLUME ["/var/lib/softkms"]
EXPOSE 50051 8080
ENTRYPOINT ["/bin/softkms-daemon"]
```

## Features

### Current (v0.1)
- [x] Basic daemon architecture
- [x] gRPC API
- [x] PKCS#11 compatibility layer
- [x] Ed25519 and ECDSA signing
- [x] Encrypted file storage
- [x] Docker support

### Roadmap
- [ ] HD Wallet support (BIP32/44)
- [ ] REST API
- [ ] TPM2 integration
- [ ] HashiCorp Vault backend
- [ ] Git/GPG integration
- [ ] Lattice-based crypto (post-quantum)
- [ ] SoftHSM database migration
- [ ] Prometheus metrics
- [ ] Web UI
- [ ] WebAuthn/FIDO2 authenticator (optional module)

## Installation

### Debian/Ubuntu
```bash
apt install softkms
systemctl enable softkms
systemctl start softkms
```

### Fedora
```bash
dnf install softkms
systemctl enable softkms
systemctl start softkms
```

### Docker
```bash
docker run -d \
  -v /var/lib/softkms:/var/lib/softkms \
  -p 127.0.0.1:50051:50051 \
  ghcr.io/yourusername/softkms:latest
```

## Quick Start

### Running the Daemon

```bash
# Build first
cargo build --release

# Start the daemon (runs in background)
./scripts/softkms-start.sh

# Check if it's running
./scripts/softkms-status.sh

# Test the API
curl http://127.0.0.1:8080/health

# View logs
./scripts/softkms-logs.sh -f

# Stop the daemon
./scripts/softkms-stop.sh
```

**Data and logs are stored in `~/.softKMS/`:**
- Config: `~/.softKMS/config.toml`
- Keys: `~/.softKMS/data/`
- Logs: `~/.softKMS/logs/daemon.log`

### Running Tests

```bash
# Run all tests
cargo test

# Run with output
cargo test -- --nocapture

# Run specific test
cargo test test_daemon_creation

# Run integration tests only
cargo test --test integration

# Use the test runner script
./test_runner.sh
```

## Usage

### Creating a Key
```bash
# Using CLI
softkms-cli key generate --algorithm ed25519 --label "My Key"

# Using gRPC (from your application)
```

### PKCS#11 Integration
```bash
# Set environment variable
export PKCS11_MODULE_PATH=/usr/lib/softkms/libsoftkms_pkcs11.so

# Use with OpenSSL
openssl req -new -x509 -keyform engine \
  -engine pkcs11 \
  -key pkcs11:object=MyKey
```

### HD Wallet
```bash
# Import seed
softkms-cli seed import --mnemonic "twelve words ..."

# Derive child key
softkms-cli key derive \
  --seed <seed-id> \
  --path "m/44'/283'/0'/0/0" \
  --label "Address 1"
```

## Optional: WebAuthn/Passkey Support

*Note: WebAuthn support is an optional module that can be enabled separately.*

softKMS can optionally act as a software-based FIDO2 authenticator, enabling:
- **Backup & Recovery**: Derive Passkeys from HD wallet seeds
- **Cross-Device Sync**: Same seed → same credentials on all devices
- **No Hardware Required**: Use as a security key replacement
- **Deterministic Credentials**: `derive(seed, rp_id, user_handle)` always gives same credential

### WebAuthn Setup

```bash
# Import seed for WebAuthn
softkms-cli seed import --mnemonic "twelve words ..."

# Install browser extension manifest
softkms-cli webauthn install-manifest

# List WebAuthn credentials
softkms-cli webauthn list
```

### WebAuthn Browser Setup

1. **Install Browser Extension**: Add softKMS extension to Chrome/Firefox
2. **Install Native Host**: Run `softkms-cli webauthn install-manifest`
3. **Import Seed**: Use your seed phrase to enable backup/recovery
4. **Create Passkeys**: softKMS appears as "Security Key" in WebAuthn dialogs
5. **Recovery**: On new device, import same seed → all Passkeys restored

See `docs/WEBAUTHN.md` for detailed WebAuthn documentation.

## API Reference

### gRPC
```protobuf
service KeyStore {
  rpc CreateKey(CreateKeyRequest) returns (CreateKeyResponse);
  rpc Sign(SignRequest) returns (SignResponse);
  rpc ImportSeed(ImportSeedRequest) returns (ImportSeedResponse);
  rpc DeriveKey(DeriveKeyRequest) returns (DeriveKeyResponse);
}
```

### REST
```bash
# Create key
curl -X POST http://localhost:8080/v1/keys \
  -H "Content-Type: application/json" \
  -d '{"algorithm": "ed25519", "label": "My Key"}'

# Sign data
curl -X POST http://localhost:8080/v1/keys/{key-id}/sign \
  -H "Content-Type: application/json" \
  -d '{"data": "base64-encoded-data"}'
```

## Quick Start

### Running the Daemon

```bash
# Build first
cargo build --release

# Start the daemon (runs in background)
./scripts/softkms-start.sh

# Check if it's running
./scripts/softkms-status.sh

# Test the API
curl http://127.0.0.1:8080/health

# View logs
./scripts/softkms-logs.sh -f

# Stop the daemon
./scripts/softkms-stop.sh
```

**Data and logs are stored in `~/.softKMS/`:**
- Config: `~/.softKMS/config.toml`
- Keys: `~/.softKMS/data/`
- Logs: `~/.softKMS/logs/daemon.log`

### Running Tests

```bash
# Run all tests
cargo test

# Run with output
cargo test -- --nocapture

# Run specific test
cargo test test_daemon_creation

# Run integration tests only
cargo test --test integration

# Use the test runner script
./test_runner.sh
```

## Development

### Building from Source
```bash
# Clone repository
git clone https://github.com/yourusername/softKMS
cd softKMS

# Build
cargo build --release

# Build and test
./build.sh

# Build Docker image
docker build -t softkms .
```

### Project Structure
```
softKMS/
├── src/                  # Core daemon (Rust)
│   ├── api/             # gRPC and REST APIs
│   ├── crypto/          # Cryptographic engines
│   ├── hd_wallet/       # HD wallet derivation
│   ├── storage/         # Storage backends
│   ├── webauthn/        # Optional: FIDO2/WebAuthn module
│   └── ...
├── cli/                  # Command-line tool
├── docs/                 # Documentation
├── docker/               # Docker configurations
└── pkg/                  # Packaging (deb, rpm)
```

## Security

### Threat Model
- **Trusted**: The softKMS daemon process
- **Untrusted**: Client applications, network, storage
- **Mitigations**: Process isolation, encrypted storage, memory clearing

### Security Features
- ✅ Memory protection (mlock, guard pages)
- ✅ Encrypted storage at rest (AES-GCM)
- ✅ Secure key deletion (zeroization)
- ✅ Hardware-backed storage (TPM2)
- ✅ Audit logging
- ✅ Container isolation

## License

**Copyright (c) 2024 - All Rights Reserved**

This is a proprietary project. Contributions are welcome but the codebase remains under the author's copyright.

## Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for details.

## Acknowledgments

- Inspired by SoftHSM and the need for a modern alternative
- Built with Rust for memory safety and performance
- WebAuthn implementation based on FIDO2 specifications

## Support

- GitHub Issues: https://github.com/yourusername/softKMS/issues
- Discussions: https://github.com/yourusername/softKMS/discussions
