# softKMS Implementation Plan

## Document Information
- **Version**: 1.0
- **Date**: 2026-02-17
- **Status**: Approved for Implementation

---

## Executive Summary

This document outlines the implementation plan for softKMS identity-based authentication and authorization system. The plan addresses three main areas:

1. **Documentation Updates** - Align docs with actual implementation
2. **Policy Engine** - Role-based access control with JSON policies
3. **Token-Based Authentication** - Full identity auth flow

Additionally, it includes PKCS#11 integration design.

---

## Design Decisions

### Authentication Methods (Mutually Exclusive)
- **Admin**: Uses `--passphrase` / `-p` flag
- **Client**: Uses `--auth-token` / `-t` flag or `SOFTKMS_TOKEN` env var
- **Error Differentiation**: 
  - Invalid token → "Invalid identity token"
  - Invalid passphrase → "Invalid admin passphrase"

### Token Header Format
- Simple header: `auth_token: <base64_token>`
- No Bearer prefix

### Policy System
- **Phase 1**: Simple role-based (Admin/Client)
- **Phase 2**: JSON policies with default templates
- **Admin Policy**: Allow all actions on all resources
- **Client Policy**: Allow CreateKey, ListKeys, Sign, DeleteKey on own resources only

### PKCS#11 PIN Mapping
- **Option B**: Hash PIN → derive deterministic identity
- Identity persisted in IdentityStore
- Enables revocation and audit trails

---

## Phase 1: Core Token Authentication

### Task 1.1: Protobuf Updates (1 hour)

**File**: `proto/softkms.proto`

**Changes**:
Add `auth_token` field to ALL key operation requests:

```protobuf
message CreateKeyRequest {
    string algorithm = 1;
    optional string label = 2;
    map<string, string> attributes = 3;
    string passphrase = 4;      // Admin auth (keystore passphrase)
    string auth_token = 5;      // Client auth (identity token) - NEW
}

message ListKeysRequest {
    bool include_public_keys = 1;
    string auth_token = 2;      // NEW
}

message SignRequest {
    string key_id = 1;
    bytes data = 2;
    string passphrase = 3;
    string auth_token = 4;      // NEW
}

message DeleteKeyRequest {
    string key_id = 1;
    bool force = 2;
    string passphrase = 3;
    string auth_token = 4;      // NEW
}

message GetKeyRequest {
    string key_id = 1;
    bool include_public_key = 2;
    string auth_token = 3;      // NEW
}

message ImportSeedRequest {
    string mnemonic = 1;
    optional string label = 2;
    string passphrase = 3;
    string auth_token = 4;      // NEW
}

message DeriveP256Request {
    string seed_id = 1;
    string origin = 2;
    optional string user_handle = 3;
    uint32 counter = 4;
    optional string label = 5;
    string passphrase = 6;
    string auth_token = 7;      // NEW
}

message DeriveEd25519Request {
    string seed_id = 1;
    string derivation_path = 2;
    uint32 coin_type = 3;
    DerivationScheme scheme = 4;
    bool store_key = 5;
    optional string label = 6;
    string passphrase = 7;
    string auth_token = 8;      // NEW
}

// Note: IdentityService requests (CreateIdentity, ListIdentities, RevokeIdentity) 
// remain passphrase-only since they are admin operations
```

**Regeneration Command**:
```bash
rm src/api/softkms.rs && PROTOC=/tmp/protoc/bin/protoc cargo build
```

---

### Task 1.2: CLI Auth Support (1 hour)

**File**: `cli/src/main.rs`

**Changes**:

1. Add auth_token field to Cli struct:
```rust
#[derive(Parser)]
#[command(name = "softkms")]
#[command(about = "SoftKMS - Modern Software Key Management System")]
#[command(version = "0.1.0")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
    
    /// Server address
    #[arg(short, long, default_value = "http://127.0.0.1:50051")]
    server: String,
    
    /// Passphrase for keystore (if not provided, will prompt interactively)
    /// Mutually exclusive with --auth-token
    #[arg(short = 'p', long, group = "auth")]
    passphrase: Option<String>,
    
    /// Auth token for identity authentication (alternative to passphrase)
    /// Can also be set via SOFTKMS_TOKEN environment variable
    /// Mutually exclusive with --passphrase
    #[arg(short = 't', long, env = "SOFTKMS_TOKEN", group = "auth")]
    auth_token: Option<String>,
}
```

2. Add auth extraction function:
```rust
/// Extract authentication from CLI args
/// Returns: (auth_token, passphrase)
fn get_auth(cli: &Cli) -> Result<(Option<String>, Option<String>), String> {
    match (&cli.auth_token, &cli.passphrase) {
        (Some(_), Some(_)) => {
            Err("Cannot use both --passphrase and --auth-token".to_string())
        }
        (None, None) => {
            Err("Must provide either --passphrase or --auth-token".to_string())
        }
        (Some(token), None) => Ok((Some(token.clone()), None)),
        (None, Some(pass)) => Ok((None, Some(pass.clone()))),
    }
}
```

3. Update error handling for different auth failures:
```rust
// In error handling:
match e {
    // ... other errors ...
    Error::InvalidAuthToken => {
        eprintln!("Error: Invalid identity token");
        std::process::exit(1);
    }
    Error::InvalidPassphrase => {
        eprintln!("Error: Invalid admin passphrase");
        std::process::exit(1);
    }
    // ... other errors ...
}
```

---

### Task 1.3: Auth Interceptor (4 hours)

**File**: `src/api/interceptor.rs` (NEW)

```rust
//! gRPC authentication interceptor
//!
//! This module handles authentication for all gRPC requests.
//! Supports both identity tokens (clients) and admin passphrases.

use tonic::{Request, Status};
use crate::identity::storage::IdentityStore;
use crate::identity::types::{Identity, IdentityRole};
use crate::security::SecurityManager;
use std::sync::Arc;

/// Authentication context extracted from request
#[derive(Debug, Clone)]
pub struct AuthContext {
    pub identity: Option<Identity>,
    pub is_admin: bool,
}

/// Extract auth_token from request metadata
pub fn extract_auth_token<T>(request: &Request<T>) -> Option<String> {
    request.metadata()
        .get("auth_token")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
}

/// Extract passphrase from request body (for admin operations)
/// This is called by individual handlers since it requires request type knowledge

/// Validate authentication and return context
pub async fn validate_auth(
    auth_token: Option<String>,
    passphrase: Option<String>,
    identity_store: &IdentityStore,
    security_manager: &SecurityManager,
) -> Result<AuthContext, Status> {
    // Validate identity token first
    if let Some(token) = auth_token {
        return validate_identity_token(&token, identity_store).await;
    }
    
    // Validate admin passphrase
    if let Some(pass) = passphrase {
        return validate_admin_passphrase(&pass, security_manager).await;
    }
    
    Err(Status::unauthenticated("No authentication provided"))
}

async fn validate_identity_token(
    token: &str,
    identity_store: &IdentityStore,
) -> Result<AuthContext, Status> {
    use crate::identity::validation::validate_token;
    
    match validate_token(token, identity_store).await {
        Ok(identity) => {
            if !identity.is_active {
                return Err(Status::permission_denied("Identity has been revoked"));
            }
            
            Ok(AuthContext {
                is_admin: identity.role == IdentityRole::Admin,
                identity: Some(identity),
            })
        }
        Err(_) => Err(Status::permission_denied("Invalid identity token")),
    }
}

async fn validate_admin_passphrase(
    passphrase: &str,
    security_manager: &SecurityManager,
) -> Result<AuthContext, Status> {
    match security_manager.verify_passphrase(passphrase) {
        Ok(true) => Ok(AuthContext {
            identity: None,
            is_admin: true,
        }),
        Ok(false) => Err(Status::permission_denied("Invalid admin passphrase")),
        Err(_) => Err(Status::internal("Authentication error")),
    }
}

/// Interceptor function for tonic::service::interceptor
pub fn create_interceptor(
    identity_store: Arc<IdentityStore>,
    security_manager: Arc<SecurityManager>,
) -> impl Fn(Request<()>) -> Result<Request<()>, Status> {
    move |mut request: Request<()>| {
        // Extract auth_token from metadata
        let auth_token = extract_auth_token(&request);
        
        // For now, we can't do async validation in the interceptor
        // The actual validation will happen in the handlers
        // We just store the token in extensions for handlers to use
        
        if let Some(token) = auth_token {
            request.extensions_mut().insert(token);
        }
        
        Ok(request)
    }
}
```

**Wire into Server** (`src/api/grpc.rs`):
```rust
pub async fn start(
    config: &Config,
    key_service: Arc<KeyService>,
    security_manager: Arc<SecurityManager>,
    identity_store: Arc<IdentityStore>,
) -> crate::Result<()> {
    let addr: SocketAddr = config
        .api
        .grpc_addr
        .parse()
        .map_err(|e| Error::InvalidParams(format!("Invalid gRPC address: {}", e)))?;

    info!("Starting gRPC server on {}", addr);
    
    let service = GrpcKeyStore::new(key_service, security_manager.clone(), identity_store.clone());
    let key_store_server = KeyStoreServer::new(service.clone());
    let identity_server = IdentityServiceServer::new(service);

    // Create auth interceptor
    let auth_interceptor = create_interceptor(identity_store, security_manager);

    Server::builder()
        .layer(tonic::service::interceptor(auth_interceptor))
        .add_service(key_store_server)
        .add_service(identity_server)
        .serve(addr)
        .await
        .map_err(|e| Error::Internal(format!("gRPC server error: {}", e)))?;

    Ok(())
}
```

---

### Task 1.4: Policy Evaluator (3 hours)

**File**: `src/identity/policy.rs` (NEW)

```rust
//! Policy evaluator for role-based access control
//!
//! This module implements a simple policy system for softKMS.
//! Future versions will support custom JSON policies.

use crate::identity::types::{Identity, IdentityRole};
use crate::Error;

/// Permission actions
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Permission {
    CreateKey,
    ListKeys,
    GetKey,
    Sign,
    DeleteKey,
    CreateIdentity,
    ListIdentities,
    RevokeIdentity,
    ImportSeed,
    DeriveKey,
}

impl Permission {
    pub fn as_str(&self) -> &'static str {
        match self {
            Permission::CreateKey => "CreateKey",
            Permission::ListKeys => "ListKeys",
            Permission::GetKey => "GetKey",
            Permission::Sign => "Sign",
            Permission::DeleteKey => "DeleteKey",
            Permission::CreateIdentity => "CreateIdentity",
            Permission::ListIdentities => "ListIdentities",
            Permission::RevokeIdentity => "RevokeIdentity",
            Permission::ImportSeed => "ImportSeed",
            Permission::DeriveKey => "DeriveKey",
        }
    }
}

/// Check if identity has permission to perform action on resource
/// 
/// # Arguments
/// * `identity` - The requesting identity (None for admin via passphrase)
/// * `permission` - The action being requested
/// * `resource_owner` - The owner of the resource (None for admin resources)
/// 
/// # Returns
/// * `Ok(())` if allowed
/// * `Err(Error::AccessDenied)` if not allowed
pub fn check_permission(
    identity: Option<&Identity>,
    permission: Permission,
    resource_owner: Option<&str>,
) -> Result<(), Error> {
    match identity {
        None => {
            // Admin via passphrase - check if admin operation
            match permission {
                Permission::CreateIdentity
                | Permission::ListIdentities
                | Permission::RevokeIdentity => Ok(()),
                _ => {
                    // Admin via passphrase can do anything (legacy behavior)
                    Ok(())
                }
            }
        }
        Some(id) => match id.role {
            IdentityRole::Admin => {
                // Admin identity can do everything
                Ok(())
            }
            IdentityRole::Client => {
                // Client can only perform specific actions
                match permission {
                    Permission::CreateKey
                    | Permission::ListKeys
                    | Permission::GetKey
                    | Permission::Sign
                    | Permission::DeleteKey
                    | Permission::ImportSeed
                    | Permission::DeriveKey => {
                        // Check resource ownership
                        if let Some(owner) = resource_owner {
                            if owner == &id.public_key {
                                Ok(())
                            } else {
                                Err(Error::AccessDenied)
                            }
                        } else {
                            // No owner specified - allow (creating new resource)
                            Ok(())
                        }
                    }
                    Permission::CreateIdentity
                    | Permission::ListIdentities
                    | Permission::RevokeIdentity => {
                        // Client cannot perform identity management
                        Err(Error::AccessDenied)
                    }
                }
            }
        }
    }
}

/// Get the namespace prefix for an identity's resources
pub fn get_resource_namespace(identity: &Identity) -> String {
    format!("{}/keys/", identity.public_key)
}

/// Check if resource belongs to identity
pub fn is_own_resource(identity: &Identity, resource: &str) -> bool {
    let namespace = get_resource_namespace(identity);
    resource.starts_with(&namespace)
}
```

**Export in src/identity/mod.rs**:
```rust
pub mod policy;
pub use policy::{Permission, check_permission, get_resource_namespace, is_own_resource};
```

---

### Task 1.5: KeyStore Identity Integration (4 hours)

**File**: `src/key_service.rs`

**1. Update `create_key()`**:
```rust
pub async fn create_key(
    &self,
    algorithm: String,
    label: Option<String>,
    attributes: HashMap<String, String>,
    passphrase: &str,
    owner_identity: Option<String>,  // Now properly used
) -> Result<KeyMetadata> {
    // ... existing validation ...
    
    let key_id = KeyId::generate();
    let created_at = Utc::now();
    
    let metadata = KeyMetadata {
        id: key_id,
        label: label.clone(),
        algorithm: algorithm.clone(),
        key_type: KeyType::Imported,
        created_at,
        attributes: attributes.clone(),
        public_key: Vec::new(), // Will be populated after generation
        owner_identity: owner_identity.clone(),  // Set owner
    };
    
    // ... rest of key generation ...
    
    // Store with owner
    self.storage.store_key(key_id, &encrypted_key, &metadata).await?;
    
    // Audit log
    if let Some(owner) = &owner_identity {
        self.audit_log.record(AuditEvent {
            identity: owner.clone(),
            action: "CreateKey".to_string(),
            resource: key_id.to_string(),
            allowed: true,
            timestamp: created_at,
        }).await?;
    }
    
    Ok(metadata)
}
```

**2. Update `list_keys()`**:
```rust
pub async fn list_keys(
    &self,
    requesting_identity: Option<&Identity>,
) -> Result<Vec<KeyMetadata>> {
    let all_keys = self.storage.list_keys().await?;
    
    match requesting_identity {
        None => {
            // Admin via passphrase - return all keys
            Ok(all_keys)
        }
        Some(identity) => {
            match identity.role {
                IdentityRole::Admin => {
                    // Admin identity - return all keys
                    Ok(all_keys)
                }
                IdentityRole::Client => {
                    // Client - filter to own keys only
                    Ok(all_keys.into_iter()
                        .filter(|k| {
                            k.owner_identity.as_ref() == Some(&identity.public_key)
                        })
                        .collect())
                }
            }
        }
    }
}
```

**3. Update `sign()`**:
```rust
pub async fn sign(
    &self,
    key_id: KeyId,
    data: &[u8],
    passphrase: &str,
    requesting_identity: Option<&Identity>,
) -> Result<Signature> {
    // ... retrieve key ...
    let metadata = self.storage.get_key_metadata(key_id).await?;
    
    // Check ownership
    if let Some(identity) = requesting_identity {
        if let Some(ref owner) = metadata.owner_identity {
            if owner != &identity.public_key && identity.role != IdentityRole::Admin {
                return Err(Error::AccessDenied);
            }
        }
    }
    
    // ... rest of signing logic ...
}
```

**4. Update `delete_key()`**:
```rust
pub async fn delete_key(
    &self,
    key_id: KeyId,
    requesting_identity: Option<&Identity>,
) -> Result<()> {
    let metadata = self.storage.get_key_metadata(key_id).await?;
    
    // Check ownership
    if let Some(identity) = requesting_identity {
        if let Some(ref owner) = metadata.owner_identity {
            if owner != &identity.public_key && identity.role != IdentityRole::Admin {
                return Err(Error::AccessDenied);
            }
        }
    }
    
    // ... delete logic ...
}
```

**5. Update `get_key()`**:
```rust
pub async fn get_key(
    &self,
    key_id: KeyId,
    requesting_identity: Option<&Identity>,
) -> Result<Option<KeyMetadata>> {
    let metadata = self.storage.get_key_metadata(key_id).await?;
    
    // Check ownership
    if let Some(identity) = requesting_identity {
        if let Some(ref owner) = metadata.owner_identity {
            if owner != &identity.public_key && identity.role != IdentityRole::Admin {
                return Err(Error::AccessDenied);
            }
        }
    }
    
    Ok(Some(metadata))
}
```

---

### Task 1.6: gRPC Handlers Update (3 hours)

**File**: `src/api/grpc.rs`

**Pattern for each handler**:

```rust
async fn create_key(
    &self,
    request: Request<CreateKeyRequest>,
) -> Result<Response<CreateKeyResponse>, Status> {
    let req = request.into_inner();
    
    // Extract authentication
    let auth_token = if req.auth_token.is_empty() { None } else { Some(req.auth_token) };
    let passphrase = if req.passphrase.is_empty() { None } else { Some(req.passphrase) };
    
    // Validate authentication
    let auth_ctx = validate_auth(
        auth_token,
        passphrase,
        &self.identity_store,
        &self.security_manager,
    )
    .await
    .map_err(|e| e)?;
    
    // Set owner based on identity
    let owner_identity = auth_ctx.identity.as_ref().map(|i| i.public_key.clone());
    
    // Execute with proper authentication
    let metadata = self
        .key_service
        .create_key(req.algorithm, req.label, req.attributes, &req.passphrase, owner_identity)
        .await
        .map_err(map_error)?;
    
    let response = CreateKeyResponse {
        key_id: metadata.id.to_string(),
        algorithm: metadata.algorithm,
        public_key: base64_encode(&metadata.public_key),
        created_at: metadata.created_at.to_rfc3339(),
        label: metadata.label.unwrap_or_default(),
    };
    
    Ok(Response::new(response))
}

async fn list_keys(
    &self,
    request: Request<ListKeysRequest>,
) -> Result<Response<ListKeysResponse>, Status> {
    let req = request.into_inner();
    
    // Extract and validate auth
    let auth_token = if req.auth_token.is_empty() { None } else { Some(req.auth_token) };
    let passphrase = if req.passphrase.is_empty() { None } else { Some(req.passphrase) };
    
    let auth_ctx = validate_auth(auth_token, passphrase, &self.identity_store, &self.security_manager)
        .await
        .map_err(|e| e)?;
    
    // Get keys with identity filtering
    let metadatas = self
        .key_service
        .list_keys(auth_ctx.identity.as_ref())
        .await
        .map_err(map_error)?;
    
    // Transform to response...
}

// Similar pattern for sign, delete_key, get_key, import_seed, derive_p256, derive_ed25519
```

---

### Task 1.7: Import Seed Ownership (2 hours)

**File**: `src/key_service.rs`

```rust
pub async fn import_seed(
    &self,
    seed: Vec<u8>,
    label: Option<String>,
    passphrase: &str,
    owner_identity: Option<String>,  // NEW PARAMETER
) -> Result<KeyMetadata> {
    // ... existing validation ...
    
    let metadata = KeyMetadata {
        // ... other fields ...
        owner_identity: owner_identity.clone(),  // Set owner
    };
    
    // Store seed
    self.storage.store_key(key_id, &encrypted_seed, &metadata).await?;
    
    // Audit log
    if let Some(owner) = &owner_identity {
        self.audit_log.record(AuditEvent {
            identity: owner.clone(),
            action: "ImportSeed".to_string(),
            resource: key_id.to_string(),
            allowed: true,
            timestamp: Utc::now(),
        }).await?;
    }
    
    Ok(metadata)
}

pub async fn derive_p256_key(
    &self,
    seed_id: KeyId,
    // ... other params ...
    requesting_identity: Option<&Identity>,
) -> Result<KeyMetadata> {
    // Get seed metadata
    let seed_metadata = self.storage.get_key_metadata(seed_id).await?;
    
    // Check seed ownership
    if let Some(identity) = requesting_identity {
        if let Some(ref owner) = seed_metadata.owner_identity {
            if owner != &identity.public_key {
                return Err(Error::AccessDenied);
            }
        }
    }
    
    // Derive key
    // ... derivation logic ...
    
    // Create metadata with owner from seed
    let derived_metadata = KeyMetadata {
        // ... other fields ...
        owner_identity: seed_metadata.owner_identity.clone(),  // Inherit ownership
    };
    
    Ok(derived_metadata)
}
```

**Update CLI output format** (`cli/src/main.rs`):
```rust
Commands::List { detailed } => {
    // Separate keys and seeds
    let (seeds, keys): (Vec<_>, Vec<_>) = keys.iter()
        .partition(|k| k.algorithm == "bip32-seed");
    
    // Print seeds section
    if !seeds.is_empty() {
        println!("Seeds:");
        for seed in seeds {
            println!("  {}:", seed.key_id);
            println!("    Type: {}", seed.algorithm);
            if let Some(ref label) = seed.label {
                println!("    Label: {}", label);
            }
            println!("    Created: {}", seed.created_at);
        }
        println!();
    }
    
    // Print keys section
    println!("Keys:");
    for key in keys {
        // ... existing print logic ...
    }
}
```

---

### Task 1.8: Documentation Updates (2 hours)

**File**: `docs/USAGE.md`

**Add new section after "Initialization"**:
```markdown
## Authentication Methods

softKMS supports two mutually exclusive authentication methods:

### 1. Admin Authentication (Passphrase)

For system administrators with full access:

```bash
# Using --passphrase flag
softkms --server http://localhost:50051 -p "admin-passphrase" generate --algorithm ed25519

# Or prompting interactively
softkms --server http://localhost:50051 generate --algorithm ed25519
# Will prompt: Passphrase: ********
```

**Use cases:**
- Initialize keystore
- Create/manage identities
- Access all keys (admin view)
- Emergency recovery

### 2. Identity Authentication (Token)

For clients/identities with restricted access:

```bash
# Using --auth-token flag
softkms --server http://localhost:50051 -t "eyJhbGc..." generate --algorithm ed25519

# Or via environment variable
export SOFTKMS_TOKEN="eyJhbGc..."
softkms --server http://localhost:50051 generate --algorithm ed25519
```

**Getting a token:**
First, an admin creates an identity:
```bash
softkms -p "admin-passphrase" identity create --type ai-agent --description "My Bot"
# Output:
# Identity created successfully:
#   Public Key: ed25519:abc123...
#   Token: eyJhbGc...  <-- SAVE THIS!
#   Created At: 2026-02-17T10:00:00Z
#
# IMPORTANT: Save this token - it will never be shown again!
```

**Token limitations:**
- Can only create/list/delete own keys
- Cannot create/revoke other identities
- Cannot access other identities' keys
- Cannot view audit logs

### Error Messages

**Invalid identity token:**
```
Error: Invalid identity token
```

**Invalid admin passphrase:**
```
Error: Invalid admin passphrase
```

**Using both auth methods:**
```
Error: Cannot use both --passphrase and --auth-token
```
```

**Update Identity section**:
```markdown
## Identity Management

### Create Identity (Admin only)

```bash
softkms -p "admin-passphrase" identity create --type ai-agent --description "Trading Bot"
```

**Types:** `ai-agent`, `service`, `user`, `pkcs11`

**Key types:** `ed25519` (default) or `p256`

### List Identities (Admin only)

```bash
softkms -p "admin-passphrase" identity list
```

### Revoke Identity (Admin only)

```bash
softkms -p "admin-passphrase" identity revoke --public-key "ed25519:abc123..." --force
```

**Note:** Revoked identities cannot access their keys until re-enabled.
```

**Update Key Operations section** to show token-based examples:
```markdown
### Create Key (with identity token)

```bash
softkms -t "$SOFTKMS_TOKEN" generate --algorithm ed25519 --label "my-key"
```

### List Keys (with identity token)

```bash
softkms -t "$SOFTKMS_TOKEN" list
```

Shows only keys owned by this identity.
```

---

### Task 1.9: Test Scripts (3 hours)

**Create test scripts:**

**`tests/validate_admin.sh`**:
```bash
#!/bin/bash
# Admin validation tests

source ./tests/test_common.sh

run_test "Health check" \
    $CLI --server "http://$GRPC_ADDR" health

run_test "Initialize keystore" \
    $CLI --server "http://$GRPC_ADDR" -p "$ADMIN_PASS" init

run_test "Create Ed25519 key (admin)" \
    $CLI --server "http://$GRPC_ADDR" -p "$ADMIN_PASS" generate --algorithm ed25519 --label "admin-ed25519"

run_test "Create P-256 key (admin)" \
    $CLI --server "http://$GRPC_ADDR" -p "$ADMIN_PASS" generate --algorithm p256 --label "admin-p256"

run_test "List all keys (admin sees all)" \
    $CLI --server "http://$GRPC_ADDR" -p "$ADMIN_PASS" list

run_test "Sign with admin" \
    $CLI --server "http://$GRPC_ADDR" -p "$ADMIN_PASS" sign --key "$KEY_ID" --data "test"

run_test "Wrong passphrase rejected" \
    expect_fail "$CLI --server 'http://$GRPC_ADDR' -p 'wrongpass' list"
```

**`tests/validate_identity.sh`**:
```bash
#!/bin/bash
# Identity/token validation tests

source ./tests/test_common.sh

# Create identity first (as admin)
OUTPUT=$($CLI --server "http://$GRPC_ADDR" -p "$ADMIN_PASS" identity create --type ai-agent --description "Test Bot")
IDENTITY_TOKEN=$(echo "$OUTPUT" | grep "Token:" | awk '{print $2}')
IDENTITY_PUBKEY=$(echo "$OUTPUT" | grep "Public Key:" | awk '{print $3}')

run_test "Create key with token" \
    $CLI --server "http://$GRPC_ADDR" -t "$IDENTITY_TOKEN" generate --algorithm ed25519 --label "token-key"

run_test "List keys with token (sees only own)" \
    $CLI --server "http://$GRPC_ADDR" -t "$IDENTITY_TOKEN" list

run_test "Sign with token" \
    $CLI --server "http://$GRPC_ADDR" -t "$IDENTITY_TOKEN" sign --key "$KEY_ID" --data "test"

run_test "Cannot access other identity's keys" \
    expect_fail "$CLI --server 'http://$GRPC_ADDR' -t '$IDENTITY_TOKEN' sign --key '$ADMIN_KEY_ID' --data 'test'"

run_test "Cannot create identity with token" \
    expect_fail "$CLI --server 'http://$GRPC_ADDR' -t '$IDENTITY_TOKEN' identity create --type user --description 'Should Fail'"

run_test "Wrong token rejected" \
    expect_fail "$CLI --server 'http://$GRPC_ADDR' -t 'invalid-token-123' list"

run_test "Import seed with token" \
    $CLI --server "http://$GRPC_ADDR" -t "$IDENTITY_TOKEN" import-seed --mnemonic "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about" --label "token-seed"
```

**`tests/validate_policy.sh`**:
```bash
#!/bin/bash
# Policy validation tests

source ./tests/test_common.sh

run_test "Admin can create identity" \
    $CLI --server "http://$GRPC_ADDR" -p "$ADMIN_PASS" identity create --type service --description "Policy Test"

run_test "Admin can list identities" \
    $CLI --server "http://$GRPC_ADDR" -p "$ADMIN_PASS" identity list

run_test "Admin can revoke identity" \
    $CLI --server "http://$GRPC_ADDR" -p "$ADMIN_PASS" identity revoke --public-key "$IDENTITY_PUBKEY" --force

run_test "Client cannot create identity" \
    expect_fail "$CLI --server 'http://$GRPC_ADDR' -t '$CLIENT_TOKEN' identity create --type user --description 'Fail'"

run_test "Client cannot revoke identity" \
    expect_fail "$CLI --server 'http://$GRPC_ADDR' -t '$CLIENT_TOKEN' identity revoke --public-key '$OTHER_PUBKEY' --force"

run_test "Client cannot list all identities" \
    expect_fail "$CLI --server 'http://$GRPC_ADDR' -t '$CLIENT_TOKEN' identity list"
```

**`tests/test_common.sh`**:
```bash
#!/bin/bash
# Common test utilities

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

TESTS_PASSED=0
TESTS_FAILED=0

pass_test() {
    echo -e "${GREEN}[PASS]${NC} $1"
    TESTS_PASSED=$((TESTS_PASSED + 1))
}

fail_test() {
    echo -e "${RED}[FAIL]${NC} $1"
    TESTS_FAILED=$((TESTS_FAILED + 1))
    exit 1
}

run_test() {
    echo "[TEST] $1"
    if eval "$2"; then
        pass_test "$1"
    else
        fail_test "$1"
    fi
}

expect_fail() {
    if eval "$1" 2>/dev/null; then
        return 1
    else
        return 0
    fi
}

# Setup and teardown functions
cleanup() {
    echo -e "\n${YELLOW}Cleaning up...${NC}"
    # ... cleanup logic ...
    echo -e "${GREEN}Done.${NC}"
}

trap cleanup EXIT
```

---

## Phase 2: PKCS#11 Integration (After Phase 1 Complete)

### Task 2.1: Session State Extension (1 hour)

**File**: `src/pkcs11/session.rs`

```rust
pub struct SessionState {
    pub handle: u64,
    pub is_logged_in: bool,
    pub is_read_only: bool,
    pub passphrase: Option<String>,
    pub identity: Option<String>,        // NEW: owner_identity public key
    pub client_type: Option<ClientType>, // NEW: Pkcs11
    pub active_key_handle: Option<u64>,
    pub active_key_id: Option<String>,
    pub signing_algorithm: Option<String>,
}
```

---

### Task 2.2: PIN-to-Identity Mapping (4 hours)

**File**: `src/pkcs11/mod.rs`

```rust
/// Derive deterministic identity from PIN hash
fn derive_identity_from_pin(pin: &str) -> String {
    use sha2::{Sha256, Digest};
    use ed25519_dalek::{SigningKey, VerifyingKey};
    
    // Hash the PIN
    let mut hasher = Sha256::new();
    hasher.update(pin.as_bytes());
    let hash = hasher.finalize();
    
    // Use hash as seed for Ed25519 keypair
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&hash[..32]);
    
    // Derive public key (we only need pubkey for identity)
    let signing_key = SigningKey::from_bytes(&seed);
    let verifying_key = signing_key.verifying_key();
    
    // Format as identity public key
    format!("ed25519:{}", base64_encode(verifying_key.as_bytes()))
}

pub extern "C" fn C_Login(
    sess: CK_SESSION,
    user_type: CK_ULONG,
    pin: *const u8,
    pin_len: CK_ULONG,
) -> CK_RV {
    // Extract PIN
    let pin_bytes = unsafe { std::slice::from_raw_parts(pin, pin_len as usize) };
    let pin_str = match String::from_utf8(pin_bytes.to_vec()) {
        Ok(s) => s,
        Err(_) => return CKR_ARGUMENTS_BAD,
    };
    
    // Derive identity from PIN
    let identity_pubkey = derive_identity_from_pin(&pin_str);
    
    // Look up or create identity
    let identity = match lookup_or_create_pkcs11_identity(&identity_pubkey).await {
        Ok(id) => id,
        Err(_) => return CKR_GENERAL_ERROR,
    };
    
    // Update session
    if let Ok(ref mut sessions) = SESSIONS.lock() {
        if let Some(session) = sessions.get_mut(&sess) {
            session.identity = Some(identity_pubkey);
            session.client_type = Some(ClientType::Pkcs11);
            session.is_logged_in = true;
            return CKR_OK;
        }
    }
    
    CKR_SESSION_INVALID
}

async fn lookup_or_create_pkcs11_identity(pubkey: &str) -> Result<Identity, Error> {
    let identity_store = get_global_identity_store()?; // Needs implementation
    
    // Try to find existing identity
    match identity_store.load(pubkey).await {
        Ok(identity) => Ok(identity),
        Err(_) => {
            // Create new PKCS#11 identity
            let (token, token_hash) = Token::generate(pubkey.to_string(), IdentityKeyType::Ed25519);
            
            let identity = Identity::new(
                pubkey.to_string(),
                IdentityKeyType::Ed25519,
                token_hash,
                IdentityRole::Client,
                ClientType::Pkcs11,
                Some("PKCS#11 client".to_string()),
            );
            
            identity_store.store(&identity).await?;
            Ok(identity)
        }
    }
}
```

---

### Task 2.3: PKCS#11 Key Operations (3 hours)

Update PKCS#11 functions to pass identity context:

```rust
pub extern "C" fn C_GenerateKeyPair(
    sess: CK_SESSION,
    mechanism: *const CK_MECHANISM,
    pub_template: *const CK_ATTRIBUTE,
    pub_count: CK_ULONG,
    priv_template: *const CK_ATTRIBUTE,
    priv_count: CK_ULONG,
    pub_key: *mut CK_OBJECT_HANDLE,
    priv_key: *mut CK_OBJECT_HANDLE,
) -> CK_RV {
    // Get session and identity
    let session = get_session(sess)?;
    let identity = session.identity.as_ref().ok_or(CKR_USER_NOT_LOGGED_IN)?;
    
    // Generate key via daemon with identity context
    let result = generate_key_with_identity(identity, mechanism).await;
    
    // ... rest of logic ...
}

async fn generate_key_with_identity(
    identity_pubkey: &str,
    mechanism: &CK_MECHANISM,
) -> Result<KeyId, Error> {
    // Call daemon with identity context
    // Similar to CLI but via PKCS#11 interface
}
```

---

### Task 2.4: PKCS#11 Tests (2 hours)

**`tests/validate_pkcs11.sh`**:
```bash
#!/bin/bash
# PKCS#11 validation tests

source ./tests/test_common.sh

run_test "PKCS#11 login with PIN" \
    pkcs11_login --pin "test-pin-123"

run_test "Generate key via PKCS#11" \
    pkcs11_generate_keypair --algorithm ed25519

run_test "Sign data via PKCS#11" \
    pkcs11_sign --key "$KEY_HANDLE" --data "test"

run_test "Re-login with same PIN sees same keys" \
    pkcs11_login --pin "test-pin-123" && pkcs11_list_keys

run_test "Different PIN sees different keys" \
    pkcs11_login --pin "different-pin" && pkcs11_list_keys_is_empty
```

---

## Summary

### Total Effort Estimate

| Phase | Tasks | Hours |
|-------|-------|-------|
| **Phase 1.1** | Protobuf updates | 1h |
| **Phase 1.2** | CLI auth support | 1h |
| **Phase 1.3** | Auth interceptor | 4h |
| **Phase 1.4** | Policy evaluator | 3h |
| **Phase 1.5** | KeyStore integration | 4h |
| **Phase 1.6** | gRPC handlers | 3h |
| **Phase 1.7** | Seed ownership | 2h |
| **Phase 1.8** | Documentation | 2h |
| **Phase 1.9** | Test scripts | 3h |
| **Phase 1 Total** | | **23h** |
| **Phase 2** | PKCS#11 integration | **10h** |
| **Grand Total** | | **33h** |

### Files Created/Modified

**New Files:**
- `src/api/interceptor.rs`
- `src/identity/policy.rs`
- `tests/validate_admin.sh`
- `tests/validate_identity.sh`
- `tests/validate_policy.sh`
- `tests/validate_pkcs11.sh`
- `tests/test_common.sh`

**Modified Files:**
- `proto/softkms.proto`
- `cli/src/main.rs`
- `src/api/grpc.rs`
- `src/key_service.rs`
- `src/identity/mod.rs`
- `src/pkcs11/session.rs`
- `src/pkcs11/mod.rs`
- `docs/USAGE.md`
- `docs/IDENTITIES.md`
- `docs/ARCHITECTURE.md`

### Testing Strategy

1. **Unit Tests**: Policy evaluator, auth validation
2. **Integration Tests**: Full flow via validation scripts
3. **Security Tests**: Auth bypass attempts, permission escalation
4. **Regression Tests**: All existing tests must still pass

---

## Appendix: Quick Reference

### Auth Flow
```
Client Request
    ↓
[auth_token header?]
    ↓ Yes              ↓ No
Validate Token    [passphrase field?]
    ↓                  ↓ Yes              ↓ No
Load Identity    Validate Passphrase    Error: No auth
    ↓                  ↓
Check is_active  Create Admin Context
    ↓                  ↓
Inject Identity    Inject Admin
    ↓                  ↓
Handler Execution
    ↓
Policy Check
    ↓
Execute Operation
```

### Error Codes
- `Unauthenticated`: No auth provided
- `PermissionDenied`: Invalid token/passphrase or insufficient permissions
- `Internal`: Auth system error

### Security Considerations
1. Tokens never stored server-side (only hash)
2. Passphrases never logged
3. Identity context validated on every operation
4. Namespace isolation enforced at storage layer
5. Audit trail for all authenticated operations

---

**Document Version History:**
- v1.0 (2026-02-17): Initial comprehensive plan

**Approval:**
- [ ] Technical review
- [ ] Security review  
- [ ] Implementation approval
