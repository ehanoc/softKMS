# CLI to Daemon Communication Architecture

## Security Principle: Isolation

The CLI **NEVER** accesses keys directly. All key operations go through the daemon.

## System Context Diagram

```mermaid
C4Context
  title softKMS System Context

  Person(user, "User", "Application or end user")
  
  System_Boundary(softKMS, "softKMS") {
    System(cli, "CLI Client", "Command line interface")
    System(daemon, "softKMS Daemon", "Key management service")
  }
  
  System_Ext(storage, "Encrypted Storage", "~/.softKMS/data/")
  
  Rel(user, cli, "Uses", "CLI commands")
  Rel(cli, daemon, "gRPC API calls", "Passphrase + operations")
  Rel(daemon, storage, "Reads/Writes", "AES-256-GCM encrypted")
```

## Container Diagram

```mermaid
C4Container
  title softKMS Container Architecture

  Person(user, "User")
  
  Container_Boundary(cli_app, "CLI Application") {
    Container(cli_main, "CLI Main", "Rust", "Command parsing and user interaction")
    Container(cli_client, "gRPC Client", "tonic", "API communication")
    Container(passphrase_prompt, "Passphrase Prompt", "rpassword", "Secure user input")
  }
  
  Container_Boundary(daemon_app, "Daemon Application") {
    Container(grpc_server, "gRPC Server", "tonic", "API endpoints")
    Container(key_service, "Key Service", "Rust", "Business logic")
    Container(security_mgr, "Security Manager", "Rust", "Master key + encryption")
    Container(storage_adapter, "Storage Adapter", "Rust", "File I/O operations")
  }
  
  ContainerDb(encrypted_files, "Encrypted Key Files", "File System", "~/.softKMS/data/*.enc")
  ContainerDb(metadata_files, "Metadata Files", "JSON", "~/.softKMS/data/*.json")
  
  Rel(user, passphrase_prompt, "Enters passphrase")
  Rel(passphrase_prompt, cli_main, "Passphrase (secure)")
  Rel(cli_main, cli_client, "Commands")
  Rel(cli_client, grpc_server, "gRPC", "Port 50051")
  Rel(grpc_server, key_service, "Operations")
  Rel(key_service, security_mgr, "Encrypt/Decrypt")
  Rel(key_service, storage_adapter, "Store/Retrieve")
  Rel(storage_adapter, encrypted_files, "Write encrypted keys")
  Rel(storage_adapter, metadata_files, "Write metadata")
```

## Component Diagram

```mermaid
C4Component
  title softKMS Key Service Components

  Container(cli_client, "gRPC Client")
  Container(grpc_server, "gRPC Server")
  
  Component(key_service, "KeyService", "Rust Struct", "Key lifecycle management")
  Component(ed25519_engine, "Ed25519Engine", "Crypto", "Ed25519 operations")
  Component(key_wrapper, "KeyWrapper", "Security", "AES-256-GCM wrap/unwrap")
  Component(master_key, "MasterKey", "Security", "PBKDF2-derived key")
  Component(passphrase_cache, "PassphraseCache", "Security", "5-minute TTL cache")
  
  ContainerDb(file_storage, "FileStorage", "Storage", "Encrypted key files")
  
  Rel(cli_client, grpc_server, "Create key, Sign data, etc.")
  Rel(grpc_server, key_service, "Call methods")
  Rel(key_service, ed25519_engine, "Generate keys, Sign")
  Rel(key_service, key_wrapper, "Wrap/Unwrap keys")
  Rel(key_wrapper, master_key, "Use for encryption")
  Rel(master_key, passphrase_cache, "Derive from passphrase")
  Rel(key_service, file_storage, "Store/Load encrypted")
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
    participant CLI as CLI Client
    participant D as Daemon
    participant SM as SecurityManager
    participant S as Storage

    U->>CLI: softkms-cli generate --algorithm ed25519 --label "My Key"
    CLI->>U: Enter passphrase: ***
    CLI->>D: gRPC CreateKeyRequest
    Note over CLI,D: {algorithm, label, passphrase}
    
    D->>SM: derive_master_key(passphrase)
    SM->>SM: PBKDF2(passphrase, salt, 210k)
    SM->>SM: Cache master_key (5 min TTL)
    SM-->>D: master_key
    
    D->>D: Generate Ed25519 key pair
    D->>SM: wrap(key_material, aad)
    SM->>SM: AES-256-GCM encrypt
    SM-->>D: WrappedKey
    
    D->>S: store_key(metadata, encrypted_data)
    S->>S: Write to ~/.softKMS/data/
    S-->>D: OK
    
    D-->>CLI: CreateKeyResponse
    Note over D,CLI: {id, algorithm, label, created_at}
    CLI->>U: Display key info
```

## Dynamic View: Sign Data

```mermaid
sequenceDiagram
    participant U as User
    participant CLI as CLI Client
    participant D as Daemon
    participant SM as SecurityManager
    participant S as Storage

    U->>CLI: softkms-cli sign --key <uuid> --data "Hello"
    CLI->>U: Enter passphrase: ***
    CLI->>D: gRPC SignRequest
    Note over CLI,D: {key_id, data, passphrase}
    
    D->>S: retrieve_key(key_id)
    S-->>D: (metadata, encrypted_data)
    
    D->>SM: derive_master_key(passphrase)
    SM->>SM: Get from cache or derive
    SM-->>D: master_key
    
    D->>SM: unwrap(encrypted_data, aad)
    SM->>SM: AES-256-GCM decrypt
    SM-->>D: key_material (plaintext)
    
    D->>D: Ed25519.sign(data, key_material)
    D->>D: zeroize(key_material)
    
    D-->>CLI: SignResponse
    Note over D,CLI: {signature, algorithm}
    CLI->>U: Display signature
```

## Key Security Lifecycle

```mermaid
flowchart TB
    subgraph Generate["1. Generate"]
        G1[Generate Ed25519 key pair]
        G2[Derive master key from passphrase]
        G3[Wrap key with AES-256-GCM]
        G4[Store encrypted key]
        G5[Clear plaintext from memory]
    end
    
    subgraph Rest["2. At Rest"]
        R1[Encrypted key file]
        R2[Metadata JSON]
    end
    
    subgraph Use["3. Use"]
        U1[Retrieve encrypted key]
        U2[Unwrap with master key]
        U3[Sign data]
        U4[Clear key from memory]
    end
    
    G1 --> G2 --> G3 --> G4 --> G5 --> R1
    R1 --> U1 --> U2 --> U3 --> U4

    style G1 fill:#f5f5f5,stroke:#666,stroke-width:2px
    style G2 fill:#e8e8e8,stroke:#555,stroke-width:2px
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
    subgraph Input["User Input"]
        U[User]
        P[Passphrase Prompt<br/>rpassword]
    end
    
    subgraph Transport["Transport"]
        CLI[CLI Client]
        D[Daemon]
    end
    
    subgraph Security["Security Layer"]
        SM[SecurityManager]
        PBKDF2[PBKDF2<br/>210k iterations]
        Cache[Master Key Cache<br/>5 min TTL]
    end
    
    subgraph Crypto["Cryptographic Operations"]
        Wrap[Wrap Keys<br/>AES-256-GCM]
        Unwrap[Unwrap Keys<br/>AES-256-GCM]
    end
    
    U -->|Types passphrase| P
    P -->|Secure input| CLI
    CLI -->|gRPC request| D
    D -->|Derive master key| SM
    SM --> PBKDF2
    PBKDF2 -->|Master key| Cache
    Cache -->|Cached key| Wrap
    Cache -->|Cached key| Unwrap

    style U fill:#f5f5f5,stroke:#666,stroke-width:2px
    style P fill:#e8e8e8,stroke:#555,stroke-width:2px
    style CLI fill:#e8e8e8,stroke:#555,stroke-width:2px
    style D fill:#d0d0d0,stroke:#444,stroke-width:3px
    style SM fill:#c0c0c0,stroke:#333,stroke-width:3px
    style PBKDF2 fill:#d0d0d0,stroke:#444,stroke-width:2px
    style Cache fill:#c0c0c0,stroke:#333,stroke-width:3px
    style Wrap fill:#e8e8e8,stroke:#555,stroke-width:2px
    style Unwrap fill:#e8e8e8,stroke:#555,stroke-width:2px
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
softkms-cli init

# Generate key
softkms-cli generate --algorithm ed25519 --label "My Key"

# Sign data
softkms-cli sign --key <uuid> --data "Hello"
# or by label:
softkms-cli sign --label "My Key" --data "Hello"

# Import seed
softkms-cli import-seed --mnemonic "abandon abandon ... about"

# List keys
softkms-cli list

# Get key info
softkms-cli info --key <uuid>

# Delete key
softkms-cli delete --key <uuid> --force
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
