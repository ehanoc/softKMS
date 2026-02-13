# CLI to Daemon Communication Architecture

## Security Principle: Isolation

The CLI **NEVER** accesses keys directly. All key operations go through the daemon.

```
┌──────────────┐      HTTP/REST      ┌──────────────┐
│     CLI      │  ────────────────▶  │    Daemon    │
│              │                     │              │
│  • Prompts   │                     │  • Security  │
│    for       │                     │    Layer     │
│    pass-     │                     │              │
│    phrase    │                     │  • Key       │
│              │                     │    storage   │
│  • Sends     │                     │              │
│    commands  │                     │  • Encryp-   │
│              │                     │    tion      │
└──────────────┘                     └──────────────┘
```

## CLI Responsibilities

1. **Prompt user for passphrase** (securely via rpassword)
2. **Cache passphrase** temporarily (optional)
3. **Send REST API requests** to daemon
4. **Display results** to user

## Daemon Responsibilities

1. **Receive passphrase via API**
2. **Derive master key** (Security Layer)
3. **Generate/derive keys**
4. **Encrypt keys** (AES-256-GCM)
5. **Store to disk**
6. **Return key metadata** (NOT key material)

## API Flow

### Creating a Standalone Key

```bash
CLI                              Daemon
  │                                │
  │  POST /v1/keys                 │
  │  {                             │
  │    "algorithm": "ed25519",    │
  │    "label": "My Key",         │
  │    "passphrase": "*******"    │
  │  }                             │
  │ ──────────────────────────────▶│
  │                                │
  │                                │ Derive master key
  │                                │ Generate key
  │                                │ Encrypt key
  │                                │ Store to disk
  │                                │
  │  {                             │
  │    "id": "uuid",              │
  │    "algorithm": "ed25519",    │
  │    "label": "My Key",         │
  │    "created_at": "..."         │
  │  }                             │
  │◀───────────────────────────────│
```

### Importing a Seed

```bash
CLI                              Daemon
  │                                │
  │  POST /v1/seeds               │
  │  {                             │
  │    "mnemonic": "...",         │
  │    "label": "My Seed",        │
  │    "passphrase": "*******"    │
  │  }                             │
  │ ──────────────────────────────▶│
  │                                │
  │                                │ Convert mnemonic to seed
  │                                │ Derive master key
  │                                │ Encrypt seed
  │                                │ Store to disk
  │                                │
  │  {                             │
  │    "id": "uuid",              │
  │    "label": "My Seed",        │
  │    "created_at": "..."         │
  │  }                             │
  │◀───────────────────────────────│
```

### Deriving a Key from Seed

```bash
CLI                              Daemon
  │                                │
  │  POST /v1/keys/derive         │
  │  {                             │
  │    "seed_id": "uuid",         │
  │    "path": "m/44'/0'/0'/0/0", │
  │    "label": "Derived",        │
  │    "passphrase": "*******"    │
  │  }                             │
  │ ──────────────────────────────▶│
  │                                │
  │                                │ Decrypt seed (passphrase)
  │                                │ BIP32 derive child key
  │                                │ Encrypt child key
  │                                │ Store to disk
  │                                │
  │  {                             │
  │    "id": "uuid",              │
  │    "parent_seed": "uuid",     │
  │    "derivation_path": "...",  │
  │    "label": "Derived",        │
  │    "created_at": "..."         │
  │  }                             │
  │◀───────────────────────────────│
```

## Passphrase Flow

```
User enters passphrase in CLI
         │
         ▼
┌─────────────────────┐
│ CLI prompts securely │
│ (rpassword, hidden)  │
└──────────┬──────────┘
           │
           │ Passphrase sent in API request
           │ (over HTTPS in production)
           ▼
┌─────────────────────┐
│   Daemon receives    │
│   passphrase         │
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│ Security Layer      │
│ derives master key   │
│ (PBKDF2, 210k iter) │
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│ Master key cached   │
│ in daemon memory    │
│ (5 min TTL)         │
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│ Encrypt/Decrypt     │
│ operations using    │
│ master key          │
└─────────────────────┘
```

## Security Benefits

1. **Isolation**: Keys never leave daemon
2. **Single passphrase**: User enters once per session
3. **Memory protection**: mlock in daemon process
4. **Audit trail**: All operations logged by daemon
5. **Access control**: Daemon can enforce policies

## Implementation Files

### New Files Needed

1. `src/api/handlers/keys.rs` - REST handlers for key operations
2. `src/api/handlers/seeds.rs` - REST handlers for seed operations
3. `cli/src/api_client.rs` - HTTP client for CLI
4. `cli/src/commands/` - Individual command implementations

### Modified Files

1. `src/api/rest.rs` - Add new routes
2. `src/daemon/mod.rs` - Initialize handlers
3. `cli/src/main.rs` - New command structure

## API Endpoints

```rust
// Keys
POST   /v1/keys              // Create standalone key
POST   /v1/keys/derive       // Derive from seed
GET    /v1/keys              // List all keys
GET    /v1/keys/:id          // Get key info
DELETE /v1/keys/:id          // Delete key
POST   /v1/keys/:id/sign     // Sign data

// Seeds
POST   /v1/seeds             // Import mnemonic
GET    /v1/seeds             // List seeds
GET    /v1/seeds/:id         // Get seed info
DELETE /v1/seeds/:id         // Delete seed

// Misc
POST   /v1/passphrase/change // Change passphrase
```

## Request/Response Examples

### Create Key Request
```json
{
  "algorithm": "ed25519",
  "label": "My Key",
  "passphrase": "my_secret_passphrase",
  "options": {
    "extractable": false
  }
}
```

### Create Key Response
```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "algorithm": "ed25519",
  "label": "My Key",
  "created_at": "2024-02-13T16:00:00Z",
  "key_type": "standalone"
}
```

### Import Seed Request
```json
{
  "mnemonic": "abandon abandon abandon ... about",
  "label": "My Seed",
  "passphrase": "my_secret_passphrase"
}
```

### Import Seed Response
```json
{
  "id": "550e8400-e29b-41d4-a716-446655440001",
  "label": "My Seed",
  "created_at": "2024-02-13T16:00:00Z",
  "seed_type": "bip39"
}
```

### Derive Key Request
```json
{
  "seed_id": "550e8400-e29b-41d4-a716-446655440001",
  "derivation_path": "m/44'/0'/0'/0/0",
  "label": "Address 0",
  "passphrase": "my_secret_passphrase"
}
```

### Derive Key Response
```json
{
  "id": "550e8400-e29b-41d4-a716-446655440002",
  "algorithm": "ed25519",
  "label": "Address 0",
  "parent_seed": "550e8400-e29b-41d4-a716-446655440001",
  "derivation_path": "m/44'/0'/0'/0/0",
  "created_at": "2024-02-13T16:00:00Z",
  "key_type": "derived"
}
```

## CLI Commands

```bash
# Create standalone key
softkms-cli key create \
  --algorithm ed25519 \
  --label "My Key"
# Prompts: Enter passphrase

# Import seed (BIP39)
softkms-cli seed import \
  --mnemonic "abandon abandon ... about" \
  --label "My Seed"
# Prompts: Enter passphrase

# Derive key from seed
softkms-cli key derive \
  --seed-id <uuid> \
  --path "m/44'/0'/0'/0/0" \
  --label "Address 0"
# Prompts: Enter passphrase (or uses cache)

# List keys
softkms-cli key list

# Change passphrase
softkms-cli passphrase change
# Prompts: Old passphrase
# Prompts: New passphrase (twice)
```

## Security Considerations

### Passphrase Transmission
- Always over HTTPS in production
- Never logged
- Cleared from memory after use
- HTTP Basic Auth or Bearer token

### Key Material
- **NEVER** returned to CLI
- Only metadata (ID, algorithm, label) returned
- Signing done by daemon, returns signature only

### Session Management
- Optional: Session token after first passphrase
- Token cached by CLI
- Token expires with master key cache

## Next Steps

1. Implement REST handlers in daemon
2. Implement HTTP client in CLI
3. Add passphrase prompting
4. Test end-to-end flow
5. Add error handling
6. Add logging

Does this architecture meet your requirements?
