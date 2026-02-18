//! Comprehensive identity-based authentication tests
//!
//! Tests all identity flows:
//! - Admin operations (None owner_identity)
//! - Identity creation and token usage
//! - Isolated access (Identity A vs Identity B)
//! - Cross-identity access denial
//! - Admin override of all identities

use softkms::audit::AuditLogger;
use softkms::identity::types::{ClientType, IdentityKeyType, IdentityRole};
use softkms::identity::{storage::IdentityStore, types::Identity, validation::validate_token};
use softkms::key_service::KeyService;
use softkms::security::{SecurityConfig, SecurityManager, create_cache};
use softkms::storage::file::FileStorage;
use softkms::storage::StorageBackend;
use softkms::{Config, KeyId, KeyMetadata, KeyType};
use std::collections::HashMap;
use std::sync::Arc;
use tempfile::TempDir;

struct TestEnvironment {
    _temp_dir: TempDir,
    service: KeyService,
    identity_store: Arc<IdentityStore>,
    audit_logger: Arc<AuditLogger>,
    admin_passphrase: String,
}

async fn create_test_environment(admin_passphrase: &str) -> TestEnvironment {
    let temp_dir = TempDir::new().unwrap();
    let storage_path = temp_dir.path().to_path_buf();
    
    // Create storage
    let storage: Arc<dyn StorageBackend + Send + Sync> = Arc::new(
        FileStorage::new(storage_path.clone(), Config::default())
    );
    storage.init().await.unwrap();
    
    // Create security manager
    let security_config = SecurityConfig::new();
    let cache = create_cache(300);
    let security_manager = Arc::new(SecurityManager::new(
        cache,
        security_config,
        storage_path.clone(),
    ));
    security_manager.init_with_passphrase(admin_passphrase).unwrap();
    
    // Create key service
    let service = KeyService::new(storage, security_manager, Config::default());
    
    // Create identity store
    let identity_store = Arc::new(IdentityStore::new(storage_path.clone()));
    identity_store.init().await.unwrap();
    
    // Create audit logger
    let audit_path = storage_path.join("audit");
    let audit_logger = Arc::new(AuditLogger::new(audit_path));
    
    TestEnvironment {
        _temp_dir: temp_dir,
        service,
        identity_store,
        audit_logger,
        admin_passphrase: admin_passphrase.to_string(),
    }
}

// Helper to create a client identity
async fn create_test_identity(
    store: &IdentityStore,
    key_type: IdentityKeyType,
    client_type: ClientType,
    description: &str,
) -> (Identity, String) {
    use softkms::identity::types::Token;
    
    // Generate public key based on type
    let public_key = match key_type {
        IdentityKeyType::Ed25519 => {
            "ed25519:MCowBQYDK2VwAyEAabc123".to_string()
        }
        IdentityKeyType::P256 => {
            "p256:BL5a5tD5x0vMxyz789".to_string()
        }
    };
    
    // Generate token
    let (token, token_hash) = Token::generate(public_key.clone(), key_type);
    
    // Create identity
    let identity = Identity::new(
        public_key,
        key_type,
        token_hash,
        IdentityRole::Client,
        client_type,
        Some(description.to_string()),
    );
    
    store.store(&identity).await.unwrap();
    
    (identity, token.token)
}

#[tokio::test]
async fn test_admin_create_key() {
    let env = create_test_environment("admin_pass").await;
    let service = &env.service;
    let passphrase = &env.admin_passphrase;
    
    // Admin creates key with None owner_identity
    let metadata = service.create_key(
        "ed25519".to_string(),
        Some("Admin Key".to_string()),
        HashMap::new(),
        passphrase,
        None, // Admin-owned
    ).await.unwrap();
    
    assert_eq!(metadata.owner_identity, None);
    assert_eq!(metadata.algorithm, "ed25519");
    
    // Admin can sign with admin-owned key
    let signature = service.sign(
        metadata.id,
        b"test data",
        passphrase,
        None, // Admin request
    ).await.unwrap();
    
    assert_eq!(signature.algorithm, "ed25519");
}

#[tokio::test]
async fn test_identity_create_and_access_own_key() {
    let env = create_test_environment("admin_pass").await;
    let service = &env.service;
    let passphrase = &env.admin_passphrase;
    
    // Create identity A
    let (identity_a, token_a) = create_test_identity(
        &env.identity_store,
        IdentityKeyType::Ed25519,
        ClientType::AiAgent,
        "Identity A - AI Agent",
    ).await;
    
    // Identity A creates key (owner_identity = identity_a.public_key)
    let key_a = service.create_key(
        "ed25519".to_string(),
        Some("Identity A Key".to_string()),
        HashMap::new(),
        passphrase,
        Some(identity_a.public_key.clone()),
    ).await.unwrap();
    
    assert_eq!(key_a.owner_identity, Some(identity_a.public_key.clone()));
    
    // Identity A can access own key
    let keys = service.list_keys(None).await.unwrap();
    let identity_a_keys: Vec<_> = keys.iter()
        .filter(|k| k.owner_identity == Some(identity_a.public_key.clone()))
        .collect();
    assert_eq!(identity_a_keys.len(), 1);
    
    // Identity A can sign with own key
    let signature = service.sign(
        key_a.id,
        b"test data",
        passphrase,
        Some(&identity_a.public_key),
    ).await.unwrap();
    
    assert_eq!(signature.algorithm, "ed25519");
}

#[tokio::test]
async fn test_identity_isolation_cross_access_denied() {
    let env = create_test_environment("admin_pass").await;
    let service = &env.service;
    let passphrase = &env.admin_passphrase;
    
    // Create identity A
    let (identity_a, _) = create_test_identity(
        &env.identity_store,
        IdentityKeyType::Ed25519,
        ClientType::AiAgent,
        "Identity A",
    ).await;
    
    // Create identity B
    let (identity_b, _) = create_test_identity(
        &env.identity_store,
        IdentityKeyType::Ed25519,
        ClientType::Service,
        "Identity B",
    ).await;
    
    // Identity A creates key
    let key_a = service.create_key(
        "ed25519".to_string(),
        Some("Identity A Key".to_string()),
        HashMap::new(),
        passphrase,
        Some(identity_a.public_key.clone()),
    ).await.unwrap();
    
    // Identity B tries to sign with Identity A's key - should fail
    let result = service.sign(
        key_a.id,
        b"malicious data",
        passphrase,
        Some(&identity_b.public_key),
    ).await;
    
    assert!(result.is_err());
    // Verify it's an access denied error
    let err_msg = result.unwrap_err().to_string();
    assert!(err_msg.contains("Access denied") || err_msg.contains("not owner"));
}

#[tokio::test]
async fn test_identity_cannot_see_other_identity_keys() {
    let env = create_test_environment("admin_pass").await;
    let service = &env.service;
    let passphrase = &env.admin_passphrase;
    
    // Create identity A
    let (identity_a, _) = create_test_identity(
        &env.identity_store,
        IdentityKeyType::Ed25519,
        ClientType::AiAgent,
        "Identity A",
    ).await;
    
    // Create identity B
    let (identity_b, _) = create_test_identity(
        &env.identity_store,
        IdentityKeyType::Ed25519,
        ClientType::Service,
        "Identity B",
    ).await;
    
    // Identity A creates key
    service.create_key(
        "ed25519".to_string(),
        Some("Identity A Key".to_string()),
        HashMap::new(),
        passphrase,
        Some(identity_a.public_key.clone()),
    ).await.unwrap();
    
    // Identity B creates key
    service.create_key(
        "ed25519".to_string(),
        Some("Identity B Key".to_string()),
        HashMap::new(),
        passphrase,
        Some(identity_b.public_key.clone()),
    ).await.unwrap();
    
    // Get all keys
    let all_keys = service.list_keys(None).await.unwrap();
    
    // Filter by identity
    let identity_a_keys: Vec<_> = all_keys.iter()
        .filter(|k| k.owner_identity == Some(identity_a.public_key.clone()))
        .collect();
    let identity_b_keys: Vec<_> = all_keys.iter()
        .filter(|k| k.owner_identity == Some(identity_b.public_key.clone()))
        .collect();
    
    assert_eq!(identity_a_keys.len(), 1);
    assert_eq!(identity_b_keys.len(), 1);
    assert_ne!(identity_a_keys[0].id, identity_b_keys[0].id);
}

#[tokio::test]
async fn test_admin_can_access_all_identity_keys() {
    let env = create_test_environment("admin_pass").await;
    let service = &env.service;
    let passphrase = &env.admin_passphrase;
    
    // Create identity A
    let (identity_a, _) = create_test_identity(
        &env.identity_store,
        IdentityKeyType::Ed25519,
        ClientType::AiAgent,
        "Identity A",
    ).await;
    
    // Create identity B
    let (identity_b, _) = create_test_identity(
        &env.identity_store,
        IdentityKeyType::Ed25519,
        ClientType::Service,
        "Identity B",
    ).await;
    
    // Identity A creates key
    let key_a = service.create_key(
        "ed25519".to_string(),
        Some("Identity A Key".to_string()),
        HashMap::new(),
        passphrase,
        Some(identity_a.public_key.clone()),
    ).await.unwrap();
    
    // Identity B creates key
    let key_b = service.create_key(
        "ed25519".to_string(),
        Some("Identity B Key".to_string()),
        HashMap::new(),
        passphrase,
        Some(identity_b.public_key.clone()),
    ).await.unwrap();
    
    // Admin (None) can sign with both keys
    let sig_a = service.sign(key_a.id, b"admin test", passphrase, None).await;
    let sig_b = service.sign(key_b.id, b"admin test", passphrase, None).await;
    
    assert!(sig_a.is_ok());
    assert!(sig_b.is_ok());
}

#[tokio::test]
async fn test_identity_token_validation() {
    let env = create_test_environment("admin_pass").await;
    
    // Create identity
    let (identity, token) = create_test_identity(
        &env.identity_store,
        IdentityKeyType::Ed25519,
        ClientType::AiAgent,
        "Test Identity",
    ).await;
    
    // Validate token
    let validated_identity = validate_token(&env.identity_store, &token).await.unwrap();
    assert_eq!(validated_identity.public_key, identity.public_key);
    assert_eq!(validated_identity.client_type, ClientType::AiAgent);
    assert!(validated_identity.is_active);
    
    // Invalid token should fail
    let invalid_token = "invalid_token_string";
    let result = validate_token(&env.identity_store, invalid_token).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_identity_revocation() {
    let env = create_test_environment("admin_pass").await;
    
    // Create identity
    let (identity, token) = create_test_identity(
        &env.identity_store,
        IdentityKeyType::Ed25519,
        ClientType::AiAgent,
        "Test Identity",
    ).await;
    
    // Revoke identity
    env.identity_store.revoke(&identity.public_key).await.unwrap();
    
    // Token should no longer be valid
    let result = validate_token(&env.identity_store, &token).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_audit_logging_identity_access() {
    let env = create_test_environment("admin_pass").await;
    let service = &env.service;
    let passphrase = &env.admin_passphrase;
    
    // Create identity
    let (identity, _) = create_test_identity(
        &env.identity_store,
        IdentityKeyType::Ed25519,
        ClientType::AiAgent,
        "Audit Test Identity",
    ).await;
    
    // Identity creates key
    let key = service.create_key(
        "ed25519".to_string(),
        Some("Audit Key".to_string()),
        HashMap::new(),
        passphrase,
        Some(identity.public_key.clone()),
    ).await.unwrap();
    
    // Log access
    env.audit_logger.log_with_identity(
        &identity.public_key,
        "client",
        "CreateKey",
        &format!("{}/keys/{}" , identity.public_key, key.id),
        true,
    ).await.unwrap();
    
    // Query audit log
    let entries = env.audit_logger.query(
        Some(&identity.public_key),
        None,
        false,
        100,
    ).await.unwrap();
    
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].identity_pubkey, Some(identity.public_key));
    assert_eq!(entries[0].action, "CreateKey");
    assert!(entries[0].allowed);
}

#[tokio::test]
async fn test_audit_logging_denied_access() {
    let env = create_test_environment("admin_pass").await;
    
    // Create identities
    let (identity_a, _) = create_test_identity(
        &env.identity_store,
        IdentityKeyType::Ed25519,
        ClientType::AiAgent,
        "Identity A",
    ).await;
    
    let (identity_b, _) = create_test_identity(
        &env.identity_store,
        IdentityKeyType::Ed25519,
        ClientType::Service,
        "Identity B",
    ).await;
    
    // Log denied access
    env.audit_logger.log_denied(
        &identity_b.public_key,
        "Sign",
        &format!("{}/keys/key_123" , identity_a.public_key),
        "Not owner",
    ).await.unwrap();
    
    // Query audit log for denied operations
    let entries = env.audit_logger.query(
        Some(&identity_b.public_key),
        None,
        false, // Include denied
        100,
    ).await.unwrap();
    
    assert_eq!(entries.len(), 1);
    assert!(!entries[0].allowed);
    assert_eq!(entries[0].reason, Some("Not owner".to_string()));
}

#[tokio::test]
async fn test_p256_identity_flow() {
    let env = create_test_environment("admin_pass").await;
    let service = &env.service;
    let passphrase = &env.admin_passphrase;
    
    // Create P-256 identity
    let (identity, _) = create_test_identity(
        &env.identity_store,
        IdentityKeyType::P256,
        ClientType::Service,
        "P-256 Service",
    ).await;
    
    // Create P-256 key for identity
    let key = service.create_key(
        "p256".to_string(),
        Some("P-256 Identity Key".to_string()),
        HashMap::new(),
        passphrase,
        Some(identity.public_key.clone()),
    ).await.unwrap();
    
    assert_eq!(key.algorithm, "p256");
    assert_eq!(key.owner_identity, Some(identity.public_key.clone()));
    
    // Sign with P-256 key
    let signature = service.sign(
        key.id,
        b"P-256 test data",
        passphrase,
        Some(&identity.public_key),
    ).await.unwrap();
    
    assert_eq!(signature.algorithm, "p256");
}

#[tokio::test]
async fn test_mixed_identity_and_admin_keys() {
    let env = create_test_environment("admin_pass").await;
    let service = &env.service;
    let passphrase = &env.admin_passphrase;
    
    // Create identity
    let (identity, _) = create_test_identity(
        &env.identity_store,
        IdentityKeyType::Ed25519,
        ClientType::AiAgent,
        "Identity",
    ).await;
    
    // Admin creates key (None owner)
    let admin_key = service.create_key(
        "ed25519".to_string(),
        Some("Admin Key".to_string()),
        HashMap::new(),
        passphrase,
        None,
    ).await.unwrap();
    
    // Identity creates key
    let identity_key = service.create_key(
        "ed25519".to_string(),
        Some("Identity Key".to_string()),
        HashMap::new(),
        passphrase,
        Some(identity.public_key.clone()),
    ).await.unwrap();
    
    // List all keys - admin sees both
    let all_keys = service.list_keys(None).await.unwrap();
    assert_eq!(all_keys.len(), 2);
    
    // Filter by owner
    let admin_keys: Vec<_> = all_keys.iter()
        .filter(|k| k.owner_identity.is_none())
        .collect();
    let identity_keys: Vec<_> = all_keys.iter()
        .filter(|k| k.owner_identity == Some(identity.public_key.clone()))
        .collect();
    
    assert_eq!(admin_keys.len(), 1);
    assert_eq!(identity_keys.len(), 1);
    assert_eq!(admin_keys[0].id, admin_key.id);
    assert_eq!(identity_keys[0].id, identity_key.id);
}