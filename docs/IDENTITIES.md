# Identity Management

softKMS uses ECC public keys for client identity and provides isolated access between identities. This guide covers the identity system, token authentication, and access control.

## Overview

### Key Concepts

- **Identity**: An ECC public key that uniquely identifies a client
- **Token**: A bearer token used for authentication (base64 encoded)
- **Isolation**: Each identity can only access keys they create
- **Admin**: Full access via passphrase

### Identity Types

| Identity | Auth Method | Scope | Use Case |
|----------|-------------|-------|----------|
| **Admin** | Passphrase | All keys | System administrator |
| **Client** | Token | Own keys only | Services, AI agents, applications |

## Supported Key Types

### Ed25519 (Default)

- **Algorithm**: EdDSA with Edwards-curve Digital Signature Algorithm
- **Key size**: 32 bytes
- **Benefits**: Fast signing, compact keys, modern and secure
- **Use case**: General purpose, recommended for most applications

```bash
# Create Ed25519 identity (default)
softkms identity create --type ai-agent
# Public Key: ed25519:MCowBQYDK2VwAyE...
```

### P-256 (Optional)

- **Algorithm**: ECDSA with NIST P-256 curve
- **Key size**: 33 bytes (compressed)
- **Benefits**: Industry standard, PKCS#11 compatible, FIPS compliant
- **Use case**: PKCS#11 clients, compliance requirements

```bash
# Create P-256 identity
softkms identity create --type service --key-type p256
# Public Key: p256:BL5a5tD5x0vM...
```

## Creating Identities

### CLI Commands

```bash
# Create identity (Ed25519 by default)
$ softkms identity create --type ai-agent --description "Trading Bot"
Public Key: ed25519:MCowBQYDK2VwAyE...
Token: ZGlkOmtleTp6Nk1rLi4uOnNlY3JldDEyMw==
# SAVE THIS TOKEN - never shown again!

# Create P-256 identity
$ softkms identity create --type service --key-type p256 --description "Payment API"
Public Key: p256:BL5a5tD5x0vM...
Token: cDI1NjpCTDVhNXRENHgwdk0...
# SAVE THIS TOKEN!
```

### Programmatic

```rust
use softkms::identity::{Identity, IdentityType};

// Create identity
let identity = Identity::create(
    IdentityType::Ed25519,
    "ai-agent",
    Some("Trading Bot")
)?;

// Get token (SHOW ONCE)
let token = identity.generate_token();
println!("Token: {}", token);  // Save this securely!

// Later: validate token
let identity = Identity::validate_token(&token)?;
```

## Token Format

### Structure

```
token = base64(identity_format)

identity_format = "{key_type}:{base64_public_key}:{secret}"

Where:
- key_type: "ed25519" or "p256"
- public_key: Base64-encoded public key (32 or 33 bytes)
- secret: Random 32-byte secret (base64-encoded)
```

### Example

```
Raw: ed25519:MCowBQYDK2VwAyE...:MTIzNDQ0NTU2Njc3
Base64: ZWQyNTUxOTpNQ293QlFZREsyVndBeUU...6TTEyek5EVTRRNVUyTmpjMw==
```

### Decoding

```bash
# Decode token
echo "ZGlkOmtleTp6Nk1rLi4uOnNlY3JldDEyMw==" | base64 -d
# Output: ed25519:MCowBQYDK2VwAyE...:123444556677
```

## Using Tokens

### Environment Variable

```bash
# Set token
export SOFTKMS_TOKEN="ZGlkOmtleTp6Nk1rLi4uOnNlY3JldDEyMw=="

# Use in commands
softkms list
softkms generate --algorithm ed25519 --label mykey
softkms sign --label mykey --data "Hello"
```

### Command Line Flag

```bash
# Pass token directly
softkms --token "ZGlkOmtleTp6Nk1rLi4uOnNlY3JldDEyMw==" list
softkms --token "..." generate --algorithm ed25519 --label mykey
```

### PKCS#11

```bash
# Use token as PIN
pkcs11-tool --module libsoftkms.so \
  --login --pin "ZGlkOmtleTp6Nk1rLi4uOnNlY3JldDEyMw==" \
  --keypairgen --key-type EC:prime256v1

# Or set environment
export PKCS11_PIN="..."
pkcs11-tool --module libsoftkms.so --login --pin "$PKCS11_PIN" --list-keys
```

## Token Security

### Best Practices

1. **Save immediately**: Token shown only once at creation
2. **Secure storage**: Use secret managers, not plaintext files
3. **Environment variables**: Set via secure deployment, not in code
4. **Rotation**: Revoke and recreate if compromised
5. **No sharing**: Each service should have its own identity

### Storage

**Server side:**
- Only stores `SHA256(secret)`, never the plaintext
- Token cannot be retrieved after creation
- Identity metadata stored separately

**Client side:**
```bash
# Good: Secret manager
export SOFTKMS_TOKEN=$(secret-tool lookup service softkms identity bot-1)

# Good: Environment file (permissions 600)
source /etc/softkms/bot-1.env

# Bad: Hardcoded in scripts
softkms --token "ZGlkOmtleTp6Nk1rLi4u..." ...  # Don't do this!
```

### Validation Flow

```rust
// 1. Client sends token
let token = "ZGlkOmtleTp6Nk1rLi4u...";

// 2. Server decodes
let parts: Vec<&str> = decode_base64(token)?.split(':').collect();
let key_type = parts[0];
let public_key = parts[1];
let secret = parts[2];

// 3. Server validates
let stored_hash = get_stored_hash(public_key)?;
if sha256(secret) != stored_hash {
    return Err(InvalidToken);
}

// 4. Check if active
let identity = get_identity(public_key)?;
if !identity.is_active {
    return Err(RevokedIdentity);
}

// 5. Grant access (filtered by identity)
```

## Access Control

### Default Policy

Currently, softKMS uses a simple role-based model:

**Admin (passphrase):**
- ✅ Full access to all keys
- ✅ Create identities
- ✅ Revoke identities
- ✅ View audit logs

**Client (token):**
- ✅ Create keys (in their namespace)
- ✅ List keys (only their own)
- ✅ Sign with their keys
- ✅ Delete their keys
- ❌ Access other identities' keys
- ❌ Create/revoke identities
- ❌ View audit logs

### Namespace Isolation

```
~/.softKMS/keys/
├── admin/                          # Admin keys
│   └── {key_id}.json
├── ed25519_AAA.../                 # Client A (isolated)
│   └── keys/
│       ├── key_001.json
│       └── key_002.json
└── ed25519_BBB.../                 # Client B (isolated)
    └── keys/
        └── key_001.json
```

**Access Rules:**
- Client A sees: `ed25519_AAA.../keys/*` only
- Client B sees: `ed25519_BBB.../keys/*` only
- Admin sees: All of the above

### Example Access Matrix

| Operation | Admin | Client A | Client B |
|-----------|-------|----------|----------|
| Create key | ✅ | ✅ (own only) | ✅ (own only) |
| List keys | ✅ All | ✅ Own only | ✅ Own only |
| Sign | ✅ All | ✅ Own only | ✅ Own only |
| Delete key | ✅ All | ✅ Own only | ❌ No access |
| Access A's keys | ✅ | ✅ | ❌ |
| Access B's keys | ✅ | ❌ | ✅ |
| Create identity | ✅ | ❌ | ❌ |
| Revoke identity | ✅ | ❌ | ❌ |

## Managing Identities

### List Identities (Admin only)

```bash
$ softkms identity list
ed25519:MCowBQY... | ai-agent | Trading Bot | Active | 3 keys
p256:BL5a5tD5... | service | Payment API | Active | 5 keys
ed25519:ZZ9ybmQ... | ai-agent | Revoked Bot | Revoked | 0 keys
```

### Revoke Identity (Admin only)

```bash
# Revoke an identity
$ softkms identity revoke ed25519:MCowBQY...
Identity ed25519:MCowBQY... has been revoked

# Token no longer works
$ softkms --token "..." list
Error: Invalid or revoked identity
```

**Revocation effects:**
- Token immediately invalid
- Existing keys remain but inaccessible via token
- Can be reactivated by admin (future feature)

### Identity Metadata

**Storage:** `~/.softKMS/identities/{public_key}.json`

```json
{
  "public_key": "ed25519:MCowBQYDK2VwAyE...",
  "key_type": "ed25519",
  "token_hash": "a1b2c3d4...",
  "created_at": "2026-02-16T14:30:00Z",
  "last_used": "2026-02-16T15:45:00Z",
  "is_active": true,
  "role": "client",
  "client_type": "ai-agent",
  "description": "Trading Bot",
  "key_count": 3
}
```

## Policies (Future)

### Planned Features

**Custom Policies:**
```json
{
  "name": "limited-signing",
  "statements": [
    {
      "effect": "Allow",
      "actions": ["Sign", "GetPublicKey"],
      "resources": ["ed25519:AAA.../keys/*"]
    },
    {
      "effect": "Deny",
      "actions": ["DeleteKey", "CreateKey"]
    }
  ]
}
```

**Policy Examples:**
- **Read-only**: Can sign but not create/delete keys
- **Time-bound**: Access only during business hours
- **Rate-limited**: Max 100 operations per minute
- **Shared keys**: Access to specific shared keys

## Troubleshooting

### Token Invalid

```
Error: Invalid token
```

**Causes:**
- Token expired (if we add expiration later)
- Identity revoked
- Token malformed
- Server restarted (unlikely with current implementation)

**Solution:** Create new identity

### Access Denied

```
Error: Access denied to key
```

**Causes:**
- Trying to access another identity's key
- Identity doesn't have permission for operation
- Key doesn't exist

**Solution:** Check identity ownership

### PKCS#11 Login Failed

```
CKR_USER_NOT_LOGGED_IN
```

**Causes:**
- Token not provided in PIN
- Admin passphrase wrong (if using pass: prefix)

**Solution:**
```bash
# For clients: use token as PIN
pkcs11-tool ... --pin "$TOKEN"

# For admin: use pass: prefix
pkcs11-tool ... --pin "pass:admin_passphrase"
```

## Best Practices

### For Service Operators

1. **One identity per service**: Don't share tokens between services
2. **Descriptive names**: Use `--description` to identify services
3. **Monitor audit logs**: Watch for unauthorized access attempts
4. **Rotate tokens**: Revoke and recreate periodically
5. **Store securely**: Use Kubernetes secrets, AWS Secrets Manager, etc.

### For AI Agents

1. **Ephemeral tokens**: Create identity per agent instance
2. **Scope minimization**: Agents only get access they need
3. **Key cleanup**: Delete keys when agent terminates
4. **Audit trail**: Log all agent operations

### For Development

1. **Separate identities**: Dev, staging, production
2. **Admin for setup**: Use admin for initial configuration
3. **Client for testing**: Create test identities

## Security Considerations

### Threat Model

**Protected against:**
- ✅ Token interception (TLS in transit)
- ✅ Token replay (bound to identity)
- ✅ Cross-identity access (namespace isolation)
- ✅ Token guessing (256-bit random secret)

**Assumed:**
- Token stored securely by client
- Admin passphrase strong
- Server process protected

### Compliance

**Audit Requirements:**
- All operations logged with identity
- Who accessed what key, when
- Failed authentication attempts
- Identity creation/revocation

**Data Residency:**
- Keys encrypted at rest
- Identity metadata stored locally
- Audit logs can be exported

## See Also

- [Architecture](../ARCHITECTURE.md) - System design
- [Usage Guide](../USAGE.md) - Practical examples
- [Security Model](../SECURITY.md) - Detailed security design
- [API Reference](../API.md) - Identity RPCs
