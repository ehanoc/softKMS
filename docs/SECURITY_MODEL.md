# softKMS Security Model

## Overview

softKMS implements a secure key management system where cryptographic keys are **NEVER stored in plaintext**. This document describes the security model, key lifecycle, and guarantees provided by the system.

## System Context

```mermaid
C4Context
  title softKMS System Context - Security Model

  Person(user, "User", "Person or application")
  
  System_Boundary(softKMS, "softKMS") {
    System(cli, "CLI Client", "Command line interface")
    System(daemon, "softKMS Daemon", "Key management service")
  }
  
  System_Ext(storage, "Encrypted Storage", "~/.softKMS/data/")
  
  Rel(user, cli, "Uses", "CLI commands")
  Rel(cli, daemon, "gRPC API", "Passphrase + operations")
  Rel(daemon, storage, "Reads/Writes", "AES-256-GCM encrypted")

```

## Security Boundaries

```mermaid
C4Context
  title softKMS Security Boundaries

  Person(user, "User")
  
  Enterprise_Boundary(untrusted, "Untrusted Zone") {
    System(cli, "CLI Client")
  }
  
  Enterprise_Boundary(trusted, "Trusted Zone") {
    System(daemon, "softKMS Daemon")
    SystemDb(storage, "Encrypted Storage")
  }
  
  Rel(user, cli, "Interacts")
  Rel(cli, daemon, "gRPC", "TLS (production)")
  Rel(daemon, storage, "Encrypt/Decrypt")

```

## Core Security Principles

### 1. Keys Never Exist in Plaintext at Rest

All keys (including seeds, derived keys, and imported keys) are encrypted before being written to storage. The encryption uses:

- **AES-256-GCM** with per-key unique salts (32 bytes)
- **Master key** derived from user passphrase via PBKDF2-HMAC-SHA256 (210,000 iterations)
- **Authenticated encryption** - metadata bound to key material via AAD

### 2. Keys Only Unwrapped in Memory When Needed

```mermaid
flowchart TB
    subgraph Rest["At Rest"]
        R1["Encrypted Key File\nAES-256-GCM"]
    end
    
    subgraph Memory["In Memory"]
        M1["Wrapped Key"]
        M2["Master Key"]
        M3["Plaintext Key"]
    end
    
    subgraph Operation["Operation"]
        O1["Sign / Derive"]
    end
    
    subgraph Clear["Clear"]
        C1["Zeroize\nMemory"]
    end
    
    R1 -->|"1. Load"| M1
    M1 -->|"2. Unwrap\n(with Master Key)"| M2
    M2 -->|"3. Decrypt"| M3
    M3 -->|"4. Use"| O1
    O1 -->|"5. Immediately"| C1
    C1 -->|"6. Return to"| Rest
    
    style R1 fill:#e0e0e0,stroke:#666,stroke-width:2px
    style M1 fill:#f5f5f5,stroke:#666,stroke-width:2px
    style M2 fill:#c0c0c0,stroke:#333,stroke-width:3px
    style M3 fill:#c0c0c0,stroke:#333,stroke-width:3px
    style O1 fill:#d0d0d0,stroke:#444,stroke-width:3px
    style C1 fill:#e8e8e8,stroke:#555,stroke-width:2px
```

**Timeline:**
1. Key exists encrypted on disk (AES-256-GCM)
2. When needed: decrypted in memory
3. Operation performed (sign, verify, etc.)
4. **Immediately cleared** from memory using `zeroize`
5. Key returns to encrypted state

### 3. Client-Daemon Isolation

```mermaid
C4Container
  title softKMS Security Architecture

  Person(user, "User")
  
  Container_Boundary(cli_boundary, "CLI Process") {
    Container(cli, "CLI Client", "Rust", "User interface")
  }
  
  Container_Boundary(daemon_boundary, "Daemon Process") {
    Container(api, "gRPC API", "tonic", "API endpoints")
    Container(key_service, "Key Service", "Rust", "Business logic")
    Container(security, "Security Manager", "Rust", "Encryption/decryption")
    ContainerDb(memory, "Key Cache", "Memory", "Master key (5 min TTL)")
  }
  
  ContainerDb(storage, "Encrypted Files", "File System", "~/.softKMS/data/")
  
  Rel(user, cli, "Commands")
  Rel(cli, api, "gRPC", "Metadata only")
  Rel(api, key_service, "Operations")
  Rel(key_service, security, "Wrap/Unwrap")
  Rel(security, memory, "Cache master key")
  Rel(key_service, storage, "Store/Retrieve")

```

- **Daemon** holds all key material - runs as isolated process
- **Client (CLI)** only sends requests and receives metadata/signatures
- **Keys NEVER leave the daemon** - only signatures and public metadata
- Communication via gRPC over localhost

## Key Lifecycle

### Generation Flow

```mermaid
sequenceDiagram
    participant S as SecurityManager
    participant K as KeyService
    participant E as Ed25519Engine
    participant St as Storage
    
    Note over K: create_key()
    
    K->>E: generate_key()
    E-->>K: (secret, public_key)
    
    K->>S: derive_master_key(passphrase)
    Note right of S: PBKDF2(210k rounds)
    S-->>K: master_key
    
    K->>S: wrap(key_material, aad)
    Note right of S: AES-256-GCM + salt
    S-->>K: wrapped_key
    
    Note over K: zeroize(plaintext)
    
    K->>St: store_key(id, metadata, encrypted)
    St-->>K: OK
```

```rust
// 1. Generate key in memory
let (secret_key, public_key) = Ed25519Engine::generate_key()?;

// 2. Get master key (prompts for passphrase if not cached)
let master_key = security_manager.get_master_key()?;

// 3. Wrap key material
let wrapper = security_manager.create_wrapper(&master_key);
let aad = build_aad(&metadata);  // Bind to metadata
let wrapped = wrapper.wrap(&key_material, &aad)?;

// 4. Clear plaintext
secret_key.zeroize();
drop(master_key);

// 5. Store encrypted
storage.store_key(id, &metadata, &wrapped.to_bytes()).await?;
```

### Signing Flow

```mermaid
sequenceDiagram
    participant S as SecurityManager
    participant K as KeyService
    participant E as Ed25519Engine
    participant St as Storage
    
    Note over K: sign(key_id, data)
    
    K->>St: retrieve_key(key_id)
    St-->>K: (metadata, encrypted_data)
    
    K->>S: derive_master_key(passphrase)
    S-->>K: master_key
    
    K->>S: unwrap(encrypted_data, aad)
    Note right of S: AES-256-GCM decrypt
    S-->>K: key_material (plaintext)
    
    K->>E: sign(data, key_material)
    E-->>K: signature
    
    Note over K: zeroize(key_material)
    
    K-->>K: return signature
```

```rust
// 1. Retrieve encrypted key from storage
let (metadata, encrypted_data) = storage.retrieve_key(key_id).await?;

// 2. Get master key
let master_key = security_manager.get_master_key()?;

// 3. Unwrap
let wrapper = security_manager.create_wrapper(&master_key);
let wrapped = WrappedKey::from_bytes(&encrypted_data)?;
let key_material = wrapper.unwrap(&wrapped, &aad)?;

// 4. Sign
let signature = Ed25519Engine::sign(&key_material, data)?;

// 5. IMMEDIATELY clear from memory
key_material.zeroize();
drop(master_key);

// Return only signature
Ok(signature)
```

## Encryption Details

### Wrapped Key Format

Binary format: `[version:1][salt:32][nonce:12][tag:16][aad_hash:32][ciphertext:N]`

- **version**: Format version (currently 1)
- **salt**: Unique per-key salt for additional entropy
- **nonce**: AES-GCM nonce (12 bytes, randomly generated)
- **tag**: Authentication tag (16 bytes)
- **aad_hash**: SHA-256 hash of authenticated additional data
- **ciphertext**: The encrypted key material

### Master Key Derivation

```mermaid
flowchart LR
    subgraph Input["Input"]
        P[User Passphrase]
    end
    
    subgraph Derive["Derivation"]
        PBKDF2["PBKDF2-HMAC-SHA256\n210,000 iterations"]
        Salt["Random Salt\n32 bytes"]
    end
    
    subgraph Output["Output"]
        MK["Master Key\n256 bits"]
    end
    
    subgraph Usage["Usage"]
        Wrap["Wrap Keys\nAES-256-GCM"]
        Unwrap["Unwrap Keys\nAES-256-GCM"]
    end
    
    P -->|"+"| Salt
    Salt --> PBKDF2
    PBKDF2 --> MK
    MK --> Wrap
    MK --> Unwrap
    
    style P fill:#f5f5f5,stroke:#666,stroke-width:2px
    style MK fill:#c0c0c0,stroke:#333,stroke-width:3px
    style Wrap fill:#e8e8e8,stroke:#555,stroke-width:2px
    style Unwrap fill:#e8e8e8,stroke:#555,stroke-width:2px
```

### Additional Authenticated Data (AAD)

The AAD binds the encrypted key to its metadata:

```rust
format!("softkms:key:{}:{}:{:?}:{}",
    metadata.id, metadata.algorithm, metadata.key_type, metadata.created_at
)
```

This prevents:
- **Tampering**: Changing metadata invalidates the authentication tag
- **Replay attacks**: Each key is uniquely bound to its creation context
- **Algorithm confusion**: Key type is cryptographically bound

## Memory Protection

### Automatic Zeroization

Sensitive data uses `secrecy::Secret<T>` and `zeroize::ZeroizeOnDrop`:

```rust
use secrecy::Secret;
use zeroize::{Zeroize, ZeroizeOnDrop};

pub struct Ed25519Key {
    #[zeroize(skip)]  // Don't zeroize non-sensitive data
    pub id: KeyId,
    pub secret_key: Secret<[u8; 32]>,  // Auto-zeroized on drop
    #[zeroize(skip)]
    pub metadata: KeyMetadata,
}
```

### Memory Flow

```mermaid
flowchart TB
    subgraph Generation["Key Generation"]
        G1[Generate Key] --> G2[Wrap Key]
        G2 --> G3[Store Encrypted]
        G2 --> G4[Zeroize Plaintext]
    end
    
    subgraph Signing["Signing Operation"]
        S1[Load Encrypted] --> S2[Unwrap]
        S2 --> S3[Sign Data]
        S3 --> S4[Zeroize]
        S4 --> S5[Return Signature]
    end
    
    subgraph Memory["Memory State"]
        M1[Only briefly unwrapped]
        M2[Always zeroized after use]
    end
    
    G4 --> M2
    S4 --> M2
    
    style G1 fill:#f5f5f5,stroke:#666,stroke-width:2px
    style G2 fill:#e8e8e8,stroke:#555,stroke-width:2px
    style G3 fill:#e0e0e0,stroke:#666,stroke-width:2px
    style G4 fill:#d0d0d0,stroke:#444,stroke-width:3px
    style S1 fill:#e0e0e0,stroke:#666,stroke-width:2px
    style S2 fill:#e8e8e8,stroke:#555,stroke-width:2px
    style S3 fill:#d0d0d0,stroke:#444,stroke-width:3px
    style S4 fill:#c0c0c0,stroke:#333,stroke-width:3px
    style S5 fill:#f5f5f5,stroke:#666,stroke-width:2px
    style M1 fill:#e8e8e8,stroke:#555,stroke-width:2px
    style M2 fill:#c0c0c0,stroke:#333,stroke-width:3px
```

### Memory Locking (Optional)

On Unix systems, the master key can be locked in RAM:

```rust
#[cfg(unix)]
pub fn try_mlock(&self) -> Result<()> {
    use libc::{c_void, mlock};
    let ptr = self.key.expose_secret().as_ptr() as *const c_void;
    unsafe { mlock(ptr, 32) }
}
```

This prevents sensitive key material from being swapped to disk.

## Threat Model

### Trusted Components

```mermaid
flowchart TB
    subgraph Trusted["Trusted"]
        T1[softKMS Daemon]
        T2[User Passphrase]
        T3[Rust Memory Safety]
    end
    
    subgraph Untrusted["Untrusted"]
        U1[CLI Client]
        U2[Storage Medium]
        U3[Network]
        U4[Other Processes]
    end
    
    T1 -->|"Protects against"| Untrusted
    
    style T1 fill:#c0c0c0,stroke:#333,stroke-width:3px
    style T2 fill:#c0c0c0,stroke:#333,stroke-width:3px
    style T3 fill:#d0d0d0,stroke:#444,stroke-width:2px
    style U1 fill:#e8e8e8,stroke:#555,stroke-width:2px
    style U2 fill:#e8e8e8,stroke:#555,stroke-width:2px
    style U3 fill:#e8e8e8,stroke:#555,stroke-width:2px
    style U4 fill:#e8e8e8,stroke:#555,stroke-width:2px
```

- The softKMS daemon process
- The user's passphrase (secret)
- The operating system's memory management (with caveats)

### Untrusted Components

- Client applications (CLI, other software)
- Network (even localhost is treated as untrusted)
- Storage medium (disk can be inspected by attackers)
- Other processes on the system

### Security Guarantees

1. **Confidentiality**: Keys encrypted at rest with AES-256-GCM
2. **Integrity**: Metadata bound to keys via AAD
3. **Availability**: Master key cached for 5 minutes (configurable) to avoid repeated passphrase prompts
4. **Forward secrecy**: Each key has unique salt, compromise of one key doesn't expose others
5. **Memory safety**: Rust memory safety + automatic zeroization

### Limitations

```mermaid
flowchart LR
    subgraph Attacks["Potential Attacks"]
        A1[Memory Dump]
        A2[Weak Passphrase]
        A3[Side Channel]
        A4[Root Access]
    end
    
    subgraph Mitigations["Mitigations"]
        M1[Zeroization\nMemory Locking]
        M2[PBKDF2\n210k rounds]
        M3[Rust Safety\nConstant Time]
        M4[mlock\nPermissions]
    end
    
    A1 -->|"Limited by"| M1
    A2 -->|"Slowed by"| M2
    A3 -->|"Protected by"| M3
    A4 -->|"Hardened by"| M4
    
    style A1 fill:#e8e8e8,stroke:#555,stroke-width:2px
    style A2 fill:#e8e8e8,stroke:#555,stroke-width:2px
    style A3 fill:#e8e8e8,stroke:#555,stroke-width:2px
    style A4 fill:#e8e8e8,stroke:#555,stroke-width:2px
    style M1 fill:#c0c0c0,stroke:#333,stroke-width:3px
    style M2 fill:#d0d0d0,stroke:#444,stroke-width:3px
    style M3 fill:#d0d0d0,stroke:#444,stroke-width:3px
    style M4 fill:#d0d0d0,stroke:#444,stroke-width:3px
```

1. **Memory dumps**: If an attacker can read daemon memory while keys are unwrapped, keys are exposed
2. **Passphrase attacks**: Weak passphrases can be brute-forced offline if storage is accessed
3. **Side channels**: Timing/power analysis not currently mitigated
4. **Root access**: If attacker has root, they can read memory (mlock helps but isn't absolute)

## Passphrase Best Practices

The security of the entire system rests on the passphrase:

- **Minimum 12 characters** recommended
- **Mix of uppercase, lowercase, numbers, symbols**
- **No dictionary words or personal information**
- **Use a password manager if possible**

The PBKDF2 iterations (210,000) provide resistance to brute-force attacks but cannot compensate for weak passphrases.

## Audit Logging

Future versions will include:
- Key generation events
- Signing operations (without exposing key material)
- Passphrase changes
- Failed authentication attempts

## Comparison to SoftHSM

| Feature | SoftHSM | softKMS |
|---------|---------|---------|
| Encryption at rest | ✓ | ✓ (AES-256-GCM) |
| Keys in memory | Always | Only when needed |
| Memory zeroization | No | Yes (zeroize) |
| Master key derivation | Fixed | PBKDF2 (210k rounds) |
| Client-daemon model | No | Yes (gRPC) |
| HD wallet support | No | Yes |

## Summary

softKMS provides strong security guarantees:

✓ **Keys never exist plaintext at rest**  
✓ **Keys only in memory when actively being used**  
✓ **Automatic memory clearing after operations**  
✓ **Client cannot access raw key material**  
✓ **Metadata cryptographically bound to keys**  
✓ **Modern Rust memory safety**

The security model ensures that even if an attacker:
- Gains access to the storage files → Only sees encrypted data
- Intercepts gRPC communication → Only sees metadata/signatures
- Has access to client application → Cannot extract private keys

The only way to access keys is to:
1. Compromise the running daemon
2. Extract the master key from memory (only valid for 5 minutes)
3. Have the user's passphrase

This defense-in-depth approach provides enterprise-grade key security in a software-based solution.
