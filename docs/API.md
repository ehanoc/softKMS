# softKMS API Reference

Complete reference for the softKMS gRPC API with identity-based authentication.

## Overview

- **Protocol**: gRPC with Protocol Buffers
- **Default Address**: `127.0.0.1:50051`
- **Authentication**: Token-based (for clients) or Passphrase (for admin)

## Authentication

### Token-Based (Clients)

All requests must include a token in the `Authorization` header or request field.

**Token Format:** `base64(key_type:public_key:secret)`

**Example:**
```
ZGlkOmtleTp6Nk1rLi4uOnNlY3JldDEyMw==
# Decodes to: ed25519:MCowBQY...:secret123
```

### Admin (Passphrase)

Admin operations require passphrase (with `pass:` prefix for PKCS#11):

```bash
# CLI
softkms -p admin_pass identity list

# PKCS#11
pkcs11-tool ... --pin "pass:admin_pass"
```

## Services

### Identity Service

**NEW** - Manages client identities and authentication.

#### CreateIdentity

Create a new client identity.

**Required:** Admin authentication (passphrase)

```protobuf
rpc CreateIdentity(CreateIdentityRequest) returns (CreateIdentityResponse);

message CreateIdentityRequest {
    // Admin authentication
    string passphrase = 1;
    
    // Identity configuration
    string client_type = 2;      // "ai-agent", "service", "user", "pkcs11"
    string key_type = 3;         // "ed25519" (default) or "p256"
    string description = 4;      // Optional human-readable description
}

message CreateIdentityResponse {
    string token = 1;              // Bearer token (SHOW ONCE, SAVE IT!)
    string public_key = 2;       // "ed25519:MCowBQY..." or "p256:BL5a5t..."
    string created_at = 3;         // ISO 8601 timestamp
}
```

**Example:**
```bash
# Create Ed25519 identity (default)
softkms identity create --type ai-agent --description "Trading Bot"
# Output:
# Token: ZGlkOmtleTp6Nk1rLi4uOnNlY3JldDEyMw==
# Public Key: ed25519:MCowBQYDK2VwAyE...

# Create P-256 identity
softkms identity create --type service --key-type p256 --description "Payment API"
# Token: cDI1NjpCTDVhNXRENHgwdk0...
```

**Client Example:**
```python
# Create identity (admin only)
response = stub.CreateIdentity(CreateIdentityRequest(
    passphrase="admin_pass",
    client_type="ai-agent",
    key_type="ed25519",
    description="Trading Bot"
))
print(f"Token: {response.token}")  # SAVE THIS!
print(f"Public Key: {response.public_key}")
```

#### ListIdentities

List all identities in the system.

**Required:** Admin authentication

```protobuf
rpc ListIdentities(ListIdentitiesRequest) returns (ListIdentitiesResponse);

message ListIdentitiesRequest {
    string passphrase = 1;         // Admin passphrase
    bool include_inactive = 2;     // Also show revoked identities
}

message IdentityInfo {
    string public_key = 1;
    string key_type = 2;
    string client_type = 3;
    string description = 4;
    string created_at = 5;
    string last_used = 6;
    bool is_active = 7;
    uint32 key_count = 8;
}

message ListIdentitiesResponse {
    repeated IdentityInfo identities = 1;
}
```

**Example:**
```bash
softkms identity list
# ed25519:MCowBQY... | ai-agent | Trading Bot | Active | 3 keys
# p256:BL5a5tD5... | service | Payment API | Active | 5 keys
# ed25519:ZZ9y... | ai-agent | Old Bot | Revoked | 0 keys
```

#### RevokeIdentity

Revoke an identity (disables token).

**Required:** Admin authentication

```protobuf
rpc RevokeIdentity(RevokeIdentityRequest) returns (RevokeIdentityResponse);

message RevokeIdentityRequest {
    string passphrase = 1;         // Admin passphrase
    string public_key = 2;         // Identity to revoke
    bool force = 3;               // Skip confirmation
}

message RevokeIdentityResponse {
    bool success = 1;
    string message = 2;
}
```

**Example:**
```bash
softkms identity revoke ed25519:MCowBQY...
Identity ed25519:MCowBQY... has been revoked

# Token no longer works
softkms --token "..." list
Error: Invalid or revoked identity
```

#### GetIdentity

Get details for a specific identity.

```protobuf
rpc GetIdentity(GetIdentityRequest) returns (GetIdentityResponse);

message GetIdentityRequest {
    // Either token or admin passphrase
    oneof auth {
        string token = 1;
        string passphrase = 2;
    }
    string public_key = 3;         // Optional: if admin, can query any
}

message GetIdentityResponse {
    IdentityInfo identity = 1;
}
```

**Example:**
```bash
# Query own identity
softkms --token $TOKEN identity info

# Admin queries any identity
softkms -p admin_pass identity info ed25519:MCowBQY...
```

### KeyManagement Service

**Modified** - Now requires identity context.

#### CreateKey

Generate a new cryptographic key (owned by current identity).

```protobuf
rpc CreateKey(CreateKeyRequest) returns (KeyMetadata);

message CreateKeyRequest {
    // Authentication (one of)
    oneof auth {
        string token = 1;          // Client token
        string passphrase = 2;     // Admin passphrase
    }
    
    // Key configuration
    string algorithm = 3;          // "ed25519" or "p256"
    optional string label = 4;     // Human-readable label
    map<string, string> attributes = 5; // Custom metadata
}

message KeyMetadata {
    string key_id = 1;
    string algorithm = 2;
    string key_type = 3;
    string created_at = 4;
    string owner_identity = 5;     // NEW: "ed25519:MCowBQY..."
    optional string label = 6;
    map<string, string> attributes = 7;
}
```

**Example:**
```bash
# Client creates key (owned by identity)
softkms --token $TOKEN generate --algorithm ed25519 --label mykey

# Admin creates key (no owner, global)
softkms -p admin_pass generate --algorithm ed25519 --label admin-key
```

**Behavior:**
- Client: Key created in `{pubkey}/keys/` namespace
- Admin: Key created in `admin/` namespace (no owner)

#### ListKeys

List keys accessible to current identity.

```protobuf
rpc ListKeys(ListKeysRequest) returns (ListKeysResponse);

message ListKeysRequest {
    // Authentication
    oneof auth {
        string token = 1;
        string passphrase = 2;
    }
    
    bool include_public_keys = 3;
}

message ListKeysResponse {
    repeated KeyInfo keys = 1;
}

message KeyInfo {
    string key_id = 1;
    string algorithm = 2;
    string key_type = 3;
    string created_at = 4;
    string owner_identity = 5;     // NEW
    string label = 6;
    map<string, string> attributes = 7;
}
```

**Example:**
```bash
# Client sees only their keys
softkms --token $TOKEN list
# Shows: mykey, bot-key-1, bot-key-2

# Admin sees all keys
softkms -p admin_pass list
# Shows: all keys from all identities + admin keys
```

**Scope:**
- Client: Returns keys where `owner_identity == requester.pubkey`
- Admin: Returns all keys

#### GetKey

Get key details (with ownership check).

```protobuf
rpc GetKey(GetKeyRequest) returns (GetKeyResponse);

message GetKeyRequest {
    oneof auth {
        string token = 1;
        string passphrase = 2;
    }
    string key_id = 3;
    bool include_public_key = 4;
}

message GetKeyResponse {
    optional KeyInfo key = 1;
}
```

**Access Control:**
- Client: Can only access own keys
- Admin: Can access any key
- Returns `NOT_FOUND` if key exists but not accessible

#### DeleteKey

Delete a key (with ownership check).

```protobuf
rpc DeleteKey(DeleteKeyRequest) returns (DeleteKeyResponse);

message DeleteKeyRequest {
    oneof auth {
        string token = 1;
        string passphrase = 2;
    }
    string key_id = 3;
    bool force = 4;
}

message DeleteKeyResponse {
    bool success = 1;
}
```

**Access Control:**
- Client: Can only delete own keys
- Admin: Can delete any key
- Returns `PERMISSION_DENIED` if not owner

### Signing Service

**Modified** - Requires identity context and ownership verification.

#### Sign

Sign data with a key (must be owner).

```protobuf
rpc Sign(SignRequest) returns (SignResponse);

message SignRequest {
    oneof auth {
        string token = 1;
        string passphrase = 2;
    }
    string key_id = 3;
    bytes data = 4;
}

message SignResponse {
    bytes signature = 1;
    string algorithm = 2;
}
```

**Access Control:**
```rust
// Server-side validation
let identity = authenticate(&req.auth)?;
let key = storage.get_key(&req.key_id)?;

// Check ownership
if identity.role == "client" && key.owner != identity.pubkey {
    return Err(PERMISSION_DENIED);
}

// Proceed with signing
```

**Example:**
```bash
# Sign with own key
softkms --token $TOKEN sign --label mykey --data "Hello"

# Admin can sign any key
softkms -p admin_pass sign --label any-key --data "Hello"
```

#### Verify

Verify a signature.

```protobuf
rpc Verify(VerifyRequest) returns (VerifyResponse);

message VerifyRequest {
    oneof auth {
        string token = 1;
        string passphrase = 2;
    }
    string key_id = 3;
    bytes data = 4;
    bytes signature = 5;
}

message VerifyResponse {
    bool valid = 1;
}
```

**Access Control:**
- Verification requires access to public key
- Client can verify with any accessible key
- Public key verification doesn't require private key access

### HD Wallet Service

**Modified** - Seeds are owned by identities.

#### ImportSeed

Import a BIP39 mnemonic or raw seed.

```protobuf
rpc ImportSeed(ImportSeedRequest) returns (ImportSeedResponse);

message ImportSeedRequest {
    oneof auth {
        string token = 1;
        string passphrase = 2;
    }
    string mnemonic = 3;
    optional string label = 4;
}

message ImportSeedResponse {
    string seed_id = 1;
    string created_at = 2;
    string owner_identity = 3;     // NEW
}
```

**Ownership:** Seed is owned by the authenticated identity.

#### DeriveKey

Derive a child key from a seed.

```protobuf
rpc DeriveKey(DeriveKeyRequest) returns (DeriveKeyResponse);

message DeriveKeyRequest {
    oneof auth {
        string token = 1;
        string passphrase = 2;
    }
    string seed_id = 3;
    string path = 4;
    optional string label = 5;
}

message DeriveKeyResponse {
    string key_id = 1;
    string derived_at = 2;
    string owner_identity = 3;     // NEW
}
```

**Access Control:** Can only derive from own seeds.

### Audit Service

**NEW** - Audit logging operations.

#### QueryAuditLog

Query audit log entries.

**Required:** Admin authentication

```protobuf
rpc QueryAuditLog(QueryAuditLogRequest) returns (QueryAuditLogResponse);

message QueryAuditLogRequest {
    string passphrase = 1;
    
    // Filters
    string identity_pubkey = 2;    // Filter by identity
    string action = 3;             // Filter by action
    bool allowed_only = 4;         // Only successful operations
    string start_time = 5;         // ISO 8601
    string end_time = 6;           // ISO 8601
    uint32 limit = 7;              // Max results
}

message AuditLogEntry {
    uint64 sequence = 1;
    string timestamp = 2;
    string identity_pubkey = 3;
    string identity_type = 4;      // "admin" | "client"
    string action = 5;
    string resource = 6;
    bool allowed = 7;
    string reason = 8;             // If denied
    string source_ip = 9;
}

message QueryAuditLogResponse {
    repeated AuditLogEntry entries = 1;
    bool has_more = 2;
}
```

**Example:**
```bash
# Query all access by specific identity
softkms -p admin_pass audit query --identity ed25519:MCowBQY...

# Query all denied access
softkms -p admin_pass audit query --denied
```

### Health Service

**Enhanced** - Shows identity context.

#### Health

Check daemon health and current identity.

```protobuf
rpc Health(HealthRequest) returns (HealthResponse);

message HealthRequest {
    // Optional: verify specific token
    string token = 1;
}

message HealthResponse {
    bool healthy = 1;
    string version = 2;
    bool storage_ready = 3;
    bool api_ready = 4;
    bool initialized = 5;
    
    // Identity info (if token provided)
    string identity_pubkey = 6;    // Optional
    string identity_role = 7;      // "admin" | "client"
    bool identity_active = 8;      // Optional
}
```

**Example:**
```bash
# Check health
softkms health

# Check health with token (shows identity info)
softkms --token $TOKEN health
```

#### Init

Initialize the keystore (creates admin identity).

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

## Error Handling

All RPCs return standard gRPC status codes:

| Code | Meaning | Example |
|------|---------|---------|
| `OK` | Success | - |
| `INVALID_ARGUMENT` | Bad request | Wrong algorithm |
| `NOT_FOUND` | Key/identity not found | Invalid key_id |
| `PERMISSION_DENIED` | Access denied | Not owner, revoked identity |
| `UNAUTHENTICATED` | Invalid auth | Wrong token, expired |
| `ALREADY_EXISTS` | Duplicate | Key already exists |
| `INTERNAL` | Server error | Storage failure |
| `UNAVAILABLE` | Not ready | Daemon not initialized |

### Identity-Specific Errors

```protobuf
// Token invalid
status: UNAUTHENTICATED
message: "Invalid or malformed token"

// Identity revoked
status: UNAUTHENTICATED
message: "Identity has been revoked"

// Access denied
status: PERMISSION_DENIED
message: "Access denied: not owner of key"

// Identity not found
status: NOT_FOUND
message: "Identity not found: ed25519:..."
```

## Protobuf Definitions

```protobuf
// File: proto/softkms.proto
syntax = "proto3";

package softkms;

// Enums
enum Algorithm {
    UNSPECIFIED = 0;
    ED25519 = 1;
    P256 = 2;
}

enum KeyType {
    UNSPECIFIED = 0;
    SEED = 1;
    DERIVED = 2;
    IMPORTED = 3;
}

enum IdentityRole {
    UNSPECIFIED = 0;
    ADMIN = 1;
    CLIENT = 2;
}

enum ClientType {
    UNSPECIFIED = 0;
    AI_AGENT = 1;
    SERVICE = 2;
    USER = 3;
    PKCS11 = 4;
}

// Authentication can be token or passphrase
message AuthContext {
    oneof auth {
        string token = 1;
        string passphrase = 2;
    }
}

// See individual services above for complete definitions
```

## Client Examples

### Python (grpcio)

```python
import grpc
from softkms_pb2 import (
    CreateIdentityRequest,
    CreateKeyRequest,
    SignRequest,
    AuthContext
)
from softkms_pb2_grpc import IdentityServiceStub, KeyManagementStub

channel = grpc.insecure_channel('localhost:50051')
identity_stub = IdentityServiceStub(channel)
key_stub = KeyManagementStub(channel)

# Create identity (admin only)
identity_resp = identity_stub.CreateIdentity(CreateIdentityRequest(
    passphrase="admin_pass",
    client_type="ai-agent",
    key_type="ed25519",
    description="Trading Bot"
))
token = identity_resp.token  # SAVE THIS!

# Create key with token
key_resp = key_stub.CreateKey(CreateKeyRequest(
    token=token,  # Client uses token
    algorithm="ed25519",
    label="bot-key"
))

# Sign with token
sign_resp = key_stub.Sign(SignRequest(
    token=token,
    key_id=key_resp.key_id,
    data=b"Hello World"
))
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
    
    // Create identity
    identityClient := pb.NewIdentityServiceClient(conn)
    identityResp, err := identityClient.CreateIdentity(context.Background(), &pb.CreateIdentityRequest{
        Passphrase: "admin_pass",
        ClientType: pb.ClientType_AI_AGENT,
        KeyType:    "ed25519",
        Description: "Trading Bot",
    })
    if err != nil {
        log.Fatal(err)
    }
    
    token := identityResp.Token  // SAVE THIS!
    
    // Use token for operations
    keyClient := pb.NewKeyManagementClient(conn)
    resp, err := keyClient.CreateKey(context.Background(), &pb.CreateKeyRequest{
        Auth: &pb.AuthContext{
            Auth: &pb.AuthContext_Token{Token: token},
        },
        Algorithm: "ed25519",
        Label:     "mykey",
    })
    
    log.Printf("Created key: %s", resp.KeyId)
}
```

### Rust (tonic)

```rust
use tonic::Request;
use softkms::api::{
    IdentityServiceClient,
    KeyManagementClient,
    CreateIdentityRequest,
    CreateKeyRequest,
    AuthContext,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut identity_client = IdentityServiceClient::connect("http://127.0.0.1:50051").await?;
    
    // Create identity (admin only)
    let identity_request = Request::new(CreateIdentityRequest {
        passphrase: "admin_pass".to_string(),
        client_type: "ai-agent".to_string(),
        key_type: "ed25519".to_string(),
        description: Some("Trading Bot".to_string()),
    });
    
    let identity_response = identity_client.create_identity(identity_request).await?;
    let token = identity_response.into_inner().token;  // SAVE THIS!
    
    // Use token for key operations
    let mut key_client = KeyManagementClient::connect("http://127.0.0.1:50051").await?;
    
    let key_request = Request::new(CreateKeyRequest {
        auth: Some(AuthContext {
            auth: Some(softkms::api::auth_context::Auth::Token(token)),
        }),
        algorithm: "ed25519".to_string(),
        label: Some("mykey".to_string()),
        ..Default::default()
    });
    
    let response = key_client.create_key(key_request).await?;
    println!("Created key: {}", response.into_inner().key_id);
    
    Ok(())
}
```

## CLI to API Mapping

| CLI Command | RPC Method | Service | Auth |
|-------------|------------|---------|------|
| `identity create` | `CreateIdentity` | Identity | Admin passphrase |
| `identity list` | `ListIdentities` | Identity | Admin passphrase |
| `identity revoke` | `RevokeIdentity` | Identity | Admin passphrase |
| `init` | `Init` | Health | Admin passphrase |
| `health` | `Health` | Health | Optional token |
| `generate` | `CreateKey` | KeyManagement | Token or passphrase |
| `list` | `ListKeys` | KeyManagement | Token or passphrase |
| `info` | `GetKey` | KeyManagement | Token or passphrase |
| `delete` | `DeleteKey` | KeyManagement | Token or passphrase |
| `sign` | `Sign` | Signing | Token or passphrase |
| `verify` | `Verify` | Signing | Token or passphrase |
| `import-seed` | `ImportSeed` | HDWallet | Token or passphrase |
| `derive` | `DeriveKey` | HDWallet | Token or passphrase |
| `audit query` | `QueryAuditLog` | Audit | Admin passphrase |

## See Also

- [Usage Guide](USAGE.md) - Practical API usage examples
- [Identity Management](IDENTITIES.md) - Identity system details
- [Architecture](ARCHITECTURE.md) - How the identity layer works
- [Security](SECURITY.md) - Identity and token security
