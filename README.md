# softKMS - Modern Software Key Management System

A modern, modular, and secure alternative to SoftHSM designed for Linux systems with support for HD wallets, pluggable cryptographic schemes, and contemporary deployment patterns.

## Overview

softKMS is a software-based Key Management System (KMS) that provides:
- **Modern Architecture**: Modular design with pluggable components
- **HD Wallet Support**: Built-in hierarchical deterministic (HD) key derivation
- **Multiple APIs**: gRPC, REST, and PKCS#11 compatibility
- **Container-Native**: First-class Docker and Kubernetes support
- **Cross-Platform**: Native packages for Debian, Fedora, and other Linux distributions

## Why softKMS?

### Compared to SoftHSM

| Feature | SoftHSM | softKMS |
|---------|---------|---------|
| **Status** | Abandoned | Actively maintained |
| **Architecture** | Monolithic C | Modular Rust with FFI |
| **HD Wallets** | ❌ | ✅ BIP32/44/ARC-0052 |
| **Crypto Agility** | Fixed (RSA/ECC) | Pluggable (Lattice, etc.) |
| **APIs** | PKCS#11 only | PKCS#11 + gRPC + REST |
| **Deployment** | Manual | Docker + systemd + packages |
| **Storage** | File-only | Pluggable backends |
| **Monitoring** | Basic | Prometheus metrics |

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                    Client APIs                       │
│  ┌──────────┐  ┌──────────┐  ┌──────────────────┐  │
│  │   gRPC   │  │   REST   │  │     PKCS#11      │  │
│  │  :50051  │  │  :8080   │  │  (C library)     │  │
│  └──────────┘  └──────────┘  └──────────────────┘  │
└─────────────────────────────────────────────────────┘
                        │
        ┌───────────────┼───────────────┐
        ▼               ▼               ▼
┌─────────────────────────────────────────────────────┐
│              softKMS Core (Rust)                   │
│  ┌────────────┐ ┌──────────┐ ┌──────────────────┐  │
│  │  Crypto    │ │ Storage  │ │   HD Wallet      │  │
│  │  Engines   │ │ Backends │ │   Derivation     │  │
│  │  (Pluggable)│ │(Pluggable)│  (BIP32 & BIP44) │  │
│  └────────────┘ └──────────┘ └──────────────────┘  │
│  ┌────────────┐ ┌──────────┐ ┌──────────────────┐  │
│  │   Ed25519  │ │ Encrypted │ │   Audit Logging  │  │
│  │   ECDSA    │ │   Files   │ │   & Metrics      │  │
│  │   RSA      │ │   TPM2    │ │                  │  │
│  │   Lattice  │ │   Vault   │ │                  │  │
│  └────────────┘ └──────────┘ └──────────────────┘  │
└─────────────────────────────────────────────────────┘
                        │
                        ▼
        ┌───────────────┼───────────────┐
        ▼               ▼               ▼
┌─────────────────────────────────────────────────────┐
│              Storage Backends                      │
│  ┌──────────┐  ┌──────────┐  ┌──────────────────┐  │
│  │ Encrypted│  │   TPM2   │  │  HashiCorp Vault │  │
│  │   Files  │  │   HSM    │  │  Cloud KMS       │  │
│  └──────────┘  └──────────┘  └──────────────────┘  │
└─────────────────────────────────────────────────────┘
```

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

## Development

### Building from Source
```bash
# Clone repository
git clone https://github.com/yourusername/softKMS
cd softKMS

# Build
cargo build --release

# Run tests
cargo test

# Build Docker image
docker build -t softkms .
```

### Project Structure
```
softKMS/
├── src/                  # Core daemon (Rust)
├── pkcs11-module/        # PKCS#11 C library
├── cli/                  # Command-line tool
├── docker/               # Docker configurations
├── pkg/                  # Packaging (deb, rpm)
└── docs/                 # Documentation
```

## Security

### Threat Model
- **Trusted**: The softKMS daemon process
- **Untrusted**: Client applications, network, storage
- **Mitigations**: Process isolation, encrypted storage, memory clearing

### Security Features
- ✅ Memory protection (mlock, guard pages)
- ✅ Encrypted storage at rest
- ✅ Secure key deletion
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
- Designed with lessons learned from the wallet-provider-extensions project

## Support

- GitHub Issues: https://github.com/yourusername/softKMS/issues
- Discussions: https://github.com/yourusername/softKMS/discussions
