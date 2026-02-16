# softKMS API Reference

Complete reference for the softKMS gRPC API.

## Overview

- **Protocol**: gRPC with Protocol Buffers
- **Default Address**: `127.0.0.1:50051`
- **Authentication**: Passphrase-based (via request fields)

## Services

### KeyManagement Service

Manages key lifecycle: creation, listing, deletion.

#### CreateKey

Generate a new cryptographic key.

```protobuf
rpc CreateKey(CreateKeyRequest) returns (KeyMetadata);

message CreateKeyRequest {
    string algorithm = 1;           // "ed25519" or "p256"
    optional string label = 2;      // Human-readable label
    map<string, string> attributes = 3; // Custom metadata
    string passphrase = 4;          // Master passphrase
}

message KeyMetadata {
    string key_id = 1;
    string algorithm = 2;
    string key_type = 3;            // "signing", "seed", "derived"
    string created_at = 4;
    optional string label = 5;
    map<string, string> attributes = 6;
}
```

**Example:**
```bash
softkms generate --algorithm ed25519 --label mykey
```

#### ListKeys

List all keys in the keystore.

```protobuf
rpc ListKeys(ListKeysRequest) returns (ListKeysResponse);

message ListKeysRequest {
    bool include_public_keys = 1;
}

message ListKeysResponse {
    repeated KeyInfo keys = 1;
}

message KeyInfo {
    string key_id = 1;
    string algorithm = 2;
    string key_type = 3;
    string created_at = 4;
    string label = 5;
    map<string, string> attributes = 6;
}
```

**Example:**
```bash
softkms list
```

#### GetKey

Get details for a specific key.

```protobuf
rpc GetKey(GetKeyRequest) returns (GetKeyResponse);

message GetKeyRequest {
    string key_id = 1;
    bool include_public_key = 2;
}

message GetKeyResponse {
    optional KeyInfo key = 1;
}
```

**Example:**
```bash
softkms info --label mykey
```

#### DeleteKey

Delete a key from the keystore.

```protobuf
rpc DeleteKey(DeleteKeyRequest) returns (DeleteKeyResponse);

message DeleteKeyRequest {
    string key_id = 1;
    bool force = 2;  // Skip confirmation
}

message DeleteKeyResponse {
    bool success = 1;
}
```

**Example:**
```bash
softkms delete --label mykey
```

### Signing Service

Cryptographic signing and verification operations.

#### Sign

Sign data with a key.

```protobuf
rpc Sign(SignRequest) returns (SignResponse);

message SignRequest {
    string key_id = 1;
    bytes data = 2;           // Data to sign
    string passphrase = 3;  // For master key derivation
}

message SignResponse {
    bytes signature = 1;
    string algorithm = 2;
}
```

**Example:**
```bash
softkms sign --label mykey --data "Hello World"
```

#### Verify

Verify a signature.

```protobuf
rpc Verify(VerifyRequest) returns (VerifyResponse);

message VerifyRequest {
    string key_id = 1;
    bytes data = 2;
    bytes signature = 3;
}

message VerifyResponse {
    bool valid = 1;
}
```

**Example:**
```bash
softkms verify --label mykey --data "Hello" --signature "..."
```

### HD Wallet Service

Hierarchical deterministic key operations.

#### ImportSeed

Import a BIP39 mnemonic or raw seed.

```protobuf
rpc ImportSeed(ImportSeedRequest) returns (ImportSeedResponse);

message ImportSeedRequest {
    string mnemonic = 1;      // BIP39 words (optional)
    optional string label = 2;
    string passphrase = 3;
}

message ImportSeedResponse {
    string seed_id = 1;
    string created_at = 2;
}
```

**Example:**
```bash
softkms import-seed --mnemonic "word1 word2 ..." --label mywallet
```

#### DeriveKey

Derive a child key from a seed using BIP32 path.

```protobuf
rpc DeriveKey(DeriveKeyRequest) returns (DeriveKeyResponse);

message DeriveKeyRequest {
    string seed_id = 1;
    string path = 2;          // BIP32 path, e.g., "m/44'/283'/0'/0/0"
    optional string label = 3;
    string passphrase = 4;
}

message DeriveKeyResponse {
    string key_id = 1;
    string derived_at = 2;
}
```

**Example:**
```bash
softkms derive --seed mywallet --path "m/44'/283'/0'/0/0" --label algo-key
```

### Health Service

Daemon status and initialization.

#### Health

Check daemon health and initialization status.

```protobuf
rpc Health(HealthRequest) returns (HealthResponse);

message HealthRequest {}

message HealthResponse {
    bool healthy = 1;
    string version = 2;
    bool storage_ready = 3;
    bool api_ready = 4;
    bool initialized = 5;
}
```

**Example:**
```bash
softkms health
```

**Response:**
```
Daemon is healthy
  Version: 0.1.0
  Storage: ready
  API: ready
  Initialized: yes
```

#### Init

Initialize the keystore with a passphrase.

```protobuf
rpc Init(InitRequest) returns (InitResponse);

message InitRequest {
    string passphrase = 1;
}

message InitResponse {
    bool success = 1;
    string message = 2;
}
```

**Example:**
```bash
softkms init
```

### ChangePassphrase

Change the master passphrase.

```protobuf
rpc ChangePassphrase(ChangePassphraseRequest) returns (ChangePassphraseResponse);

message ChangePassphraseRequest {
    string old_passphrase = 1;
    string new_passphrase = 2;
}

message ChangePassphraseResponse {
    bool success = 1;
    string message = 2;
}
```

**Example:**
```bash
softkms change-passphrase
```

## Error Handling

All RPCs return standard gRPC status codes:

| Code | Meaning | Example |
|------|---------|---------|
| `OK` | Success | - |
| `INVALID_ARGUMENT` | Bad request | Wrong algorithm |
| `NOT_FOUND` | Key not found | Invalid key_id |
| `PERMISSION_DENIED` | Auth failed | Wrong passphrase |
| `ALREADY_EXISTS` | Duplicate | Key already exists |
| `INTERNAL` | Server error | Storage failure |
| `UNAVAILABLE` | Not ready | Daemon not initialized |

## Protobuf Definitions

```protobuf
// File: proto/softkms.proto
syntax = "proto3";

package softkms;

// Enums
enum Algorithm {
    UNSPECIFIED = 0;
    ED25519 = 1;
    ECDSA_SECP256K1 = 2;
    ECDSA_SECP256R1 = 3;
    RSA = 4;
}

enum KeyType {
    UNSPECIFIED = 0;
    SEED = 1;
    DERIVED = 2;
    IMPORTED = 3;
    EXTENDED_PUBLIC = 4;
}

// See individual services above for full definitions
```

## Client Examples

### Python (grpcio)

```python
import grpc
from softkms_pb2 import CreateKeyRequest, SignRequest
from softkms_pb2_grpc import KeyManagementStub, SigningStub

channel = grpc.insecure_channel('localhost:50051')
key_stub = KeyManagementStub(channel)
sign_stub = SigningStub(channel)

# Create key
response = key_stub.CreateKey(CreateKeyRequest(
    algorithm="ed25519",
    label="mykey",
    passphrase="mypassword"
))
key_id = response.key_id

# Sign data
sign_response = sign_stub.Sign(SignRequest(
    key_id=key_id,
    data=b"Hello World",
    passphrase="mypassword"
))
signature = sign_response.signature
```

### Go

```go
package main

import (
    "context"
    "log"
    "google.golang.org/grpc"
    pb "softkms/api"
)

func main() {
    conn, err := grpc.Dial("localhost:50051", grpc.WithInsecure())
    if err != nil {
        log.Fatal(err)
    }
    defer conn.Close()
    
    client := pb.NewKeyManagementClient(conn)
    
    resp, err := client.CreateKey(context.Background(), &pb.CreateKeyRequest{
        Algorithm:  "ed25519",
        Label:      "mykey",
        Passphrase: "mypassword",
    })
    if err != nil {
        log.Fatal(err)
    }
    
    log.Printf("Created key: %s", resp.KeyId)
}
```

### Rust (tonic)

```rust
use tonic::Request;
use softkms::api::{
    KeyManagementClient,
    CreateKeyRequest,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut client = KeyManagementClient::connect("http://127.0.0.1:50051").await?;
    
    let request = Request::new(CreateKeyRequest {
        algorithm: "ed25519".to_string(),
        label: Some("mykey".to_string()),
        passphrase: "mypassword".to_string(),
        ..Default::default()
    });
    
    let response = client.create_key(request).await?;
    println!("Created key: {}", response.into_inner().key_id);
    
    Ok(())
}
```

## CLI to API Mapping

| CLI Command | RPC Method | Service |
|-------------|------------|---------|
| `init` | `Init` | Health |
| `health` | `Health` | Health |
| `generate` | `CreateKey` | KeyManagement |
| `list` | `ListKeys` | KeyManagement |
| `info` | `GetKey` | KeyManagement |
| `delete` | `DeleteKey` | KeyManagement |
| `sign` | `Sign` | Signing |
| `verify` | `Verify` | Signing |
| `import-seed` | `ImportSeed` | HDWallet |
| `derive` | `DeriveKey` | HDWallet |
| `change-passphrase` | `ChangePassphrase` | Health |

## See Also

- [Usage Guide](USAGE.md) - Practical API usage examples
- [Architecture](ARCHITECTURE.md) - How the API layer works
- [Security](SECURITY.md) - API security considerations
