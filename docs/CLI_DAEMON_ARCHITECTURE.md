# CLI to Daemon Communication Architecture

## Security Principle: Isolation

The CLI **NEVER** accesses keys directly. All key operations go through the daemon.

## System Context Diagram

```mermaid
flowchart LR
    U[User] -->|Master Key| D[Daemon]
    A[Agent] -->|Ephemeral Token| D
    D -->|AES-256-GCM| S[Storage]
    
    style U fill:#f5f5f5,stroke:#333
    style A fill:#f5f5f5,stroke:#333,stroke-dasharray:5 5
    style D fill:#d0d0d0,stroke:#333
    style S fill:#e0e0e0,stroke:#333
```

> **Future (dashed)**: Agent support - Same API, agents use ephemeral tokens with RBAC roles

## Container Diagram

```mermaid
flowchart TB
    subgraph CLI[CLI Application]
        P[Passphrase] --> C[CLI Main]
        C --> G[gRPC Client]
    end
    
    subgraph Daemon[Daemon]
        G2[gRPC Server] --> KS[Key Service]
        KS --> SM[Security Manager]
        KS --> ST[Storage]
    end
    
    G -->|gRPC| G2
    
    style U fill:#f5f5f5,stroke:#333
    style P fill:#f5f5f5,stroke:#333
    style C fill:#e0e0e0,stroke:#333
    style G fill:#e0e0e0,stroke:#333
    style G2 fill:#e0e0e0,stroke:#333
    style KS fill:#d0d0d0,stroke:#333
    style SM fill:#d0d0d0,stroke:#333
    style ST fill:#e0e0e0,stroke:#333
```

## Component Diagram

```mermaid
flowchart LR
    C[gRPC Client] --> G[gRPC Server]
    G --> KS[Key Service]
    KS --> E[Ed25519 Engine]
    KS --> W[Key Wrapper]
    W --> MK[Master Key]
    KS --> S[Storage]
    
    style C fill:#e0e0e0,stroke:#333
    style G fill:#e0e0e0,stroke:#333
    style KS fill:#d0d0d0,stroke:#333
    style E fill:#d0d0d0,stroke:#333
    style W fill:#d0d0d0,stroke:#333
    style MK fill:#c0c0c0,stroke:#333
    style S fill:#e0e0e0,stroke:#333
```

## CLI Responsibilities

1. **Prompt user for passphrase** (securely via rpassword)
2. **Send gRPC requests** to daemon
3. **Display results** to user

## Daemon Responsibilities

1. **Receive passphrase via gRPC**
2. **Derive master key** (Security Layer - PBKDF2, 210k iter)
3. **Generate/derive keys**
4. **Wrap/Unwrap keys** (AES-256-GCM)
5. **Store to disk** (encrypted)
6. **Return key metadata** (NOT key material)

## Dynamic View: Create Key

```mermaid
sequenceDiagram
    participant U as User
    participant CLI as CLI
    participant D as Daemon
    participant SM as SecurityManager
    participant S as Storage

    U->>CLI: generate key
    CLI->>D: gRPC CreateKeyRequest
    D->>SM: derive_master_key()
    SM-->>D: master_key
    D->>SM: wrap(key)
    SM-->>D: wrapped
    D->>S: store_key()
    S-->>D: OK
    D-->>CLI: response
    CLI->>U: key info
```

## Dynamic View: Sign Data

```mermaid
sequenceDiagram
    participant U as User
    participant CLI as CLI
    participant D as Daemon
    participant SM as SecurityManager
    participant S as Storage

    U->>CLI: sign data
    CLI->>D: gRPC SignRequest
    D->>S: retrieve_key()
    S-->>D: encrypted_key
    D->>SM: unwrap(key)
    SM-->>D: plaintext
    D->>D: sign()
    D->>D: zeroize()
    D-->>CLI: signature
    CLI->>U: signature
```

## Key Security Lifecycle

```mermaid
flowchart TB
    G1[Generate] --> G2[Derive Master] --> G3[Wrap] --> G4[Store] --> G5[Zeroize]
    G4 --> R[At Rest]
    R --> U1[Retrieve] --> U2[Unwrap] --> U3[Sign] --> U4[Zeroize]
    
    style G1 fill:#f5f5f5,stroke:#333
    style G2 fill:#e0e0e0,stroke:#333
    style G3 fill:#e0e0e0,stroke:#333
    style G4 fill:#e0e0e0,stroke:#333
    style G5 fill:#d0d0d0,stroke:#333
    style R fill:#e0e0e0,stroke:#333
    style U1 fill:#e0e0e0,stroke:#333
    style U2 fill:#e0e0e0,stroke:#333
    style U3 fill:#d0d0d0,stroke:#333
    style U4 fill:#d0d0d0,stroke:#333
    style G3 fill:#e8e8e8,stroke:#555,stroke-width:2px
    style G4 fill:#e0e0e0,stroke:#666,stroke-width:2px
    style G5 fill:#c0c0c0,stroke:#333,stroke-width:3px
    style R1 fill:#e0e0e0,stroke:#666,stroke-width:2px
    style R2 fill:#e0e0e0,stroke:#666,stroke-width:2px
    style U1 fill:#e0e0e0,stroke:#666,stroke-width:2px
    style U2 fill:#e8e8e8,stroke:#555,stroke-width:2px
    style U3 fill:#d0d0d0,stroke:#444,stroke-width:3px
    style U4 fill:#c0c0c0,stroke:#333,stroke-width:3px
```

## Passphrase Flow

```mermaid
flowchart LR
    U[User] --> P[Passphrase]
    P -->|gRPC| D[Daemon]
    D -->|PBKDF2| MK[Master Key]
    MK --> C[Cache<br/>5 min]
    C --> W[Wrap]
    C --> U2[Unwrap]
    
    style U fill:#f5f5f5,stroke:#333
    style P fill:#f5f5f5,stroke:#333
    style D fill:#d0d0d0,stroke:#333
    style MK fill:#c0c0c0,stroke:#333
    style C fill:#c0c0c0,stroke:#333
    style W fill:#e0e0e0,stroke:#333
    style U2 fill:#e0e0e0,stroke:#333
```

## Security Benefits

1. **Isolation**: Keys never leave daemon process
2. **Single passphrase**: User enters once, cached securely
3. **Memory protection**: Automatic zeroization after use
4. **Encrypted at rest**: AES-256-GCM with unique salts
5. **Metadata binding**: AAD prevents tampering

## API Endpoints

```rust
// Keys
rpc CreateKey(CreateKeyRequest) returns (CreateKeyResponse);
rpc ListKeys(ListKeysRequest) returns (ListKeysResponse);
rpc GetKey(GetKeyRequest) returns (GetKeyResponse);
rpc DeleteKey(DeleteKeyRequest) returns (DeleteKeyResponse);
rpc Sign(SignRequest) returns (SignResponse);

// Seeds
rpc ImportSeed(ImportSeedRequest) returns (ImportSeedResponse);
rpc DeriveKey(DeriveKeyRequest) returns (DeriveKeyResponse);

// Health
rpc Health(HealthRequest) returns (HealthResponse);
```

## CLI Commands

```bash
# Initialize
softkms init

# Generate key
softkms generate --algorithm ed25519 --label "My Key"

# Sign data
softkms sign --key <uuid> --data "Hello"
# or by label:
softkms sign --label "My Key" --data "Hello"

# Import seed
softkms import-seed --mnemonic "abandon abandon ... about"

# List keys
softkms list

# Get key info
softkms info --key <uuid>

# Delete key
softkms delete --key <uuid> --force
```

## Security Considerations

### Passphrase Transmission
- Sent over gRPC (localhost in dev, TLS in production)
- Never logged
- Cleared from CLI memory after sending
- Used by daemon to derive master key

### Key Material
- **NEVER** returned to CLI
- Only metadata (ID, algorithm, label) returned
- Signing done by daemon, returns signature only

## Implementation Files

### Key Components
- `src/api/grpc.rs` - gRPC server implementation
- `src/key_service.rs` - Key lifecycle management
- `src/security/wrapper.rs` - AES-256-GCM wrap/unwrap
- `src/crypto/ed25519.rs` - Ed25519 signing
- `cli/src/main.rs` - CLI client

## Next Steps

1. ✅ REST/gRPC handlers implemented
2. ✅ HTTP/gRPC client in CLI
3. ✅ Passphrase prompting
4. ✅ End-to-end flow tested
5. ✅ Error handling
6. ✅ Logging
7. Add TLS support for production
8. Implement HD wallet derivation
9. Add audit logging
