//! Unit tests for IdentityService gRPC implementation
//!
//! These tests verify identity creation, listing, and revocation work correctly.

use softkms::identity::storage::IdentityStore;
use softkms::identity::types::{Identity, IdentityRole, ClientType, IdentityKeyType};
use softkms::security::{SecurityConfig, SecurityManager, create_cache};
use softkms::api::softkms::{
    CreateIdentityRequest, ListIdentitiesRequest, GetIdentityRequest, RevokeIdentityRequest,
    ClientType as ProtoClientType, IdentityKeyType as ProtoIdentityKeyType
};
use std::sync::Arc;
use tempfile::TempDir;

/// Helper to create test security manager
fn create_test_security_manager(temp_dir: &TempDir) -> Arc<SecurityManager> {
    let security_config = SecurityConfig::new();
    let cache = create_cache(300);
    let storage_path = temp_dir.path().to_path_buf();
    let security_manager = Arc::new(SecurityManager::new(
        cache,
        security_config,
        storage_path,
    ));
    
    // Initialize with passphrase
    security_manager.init_with_passphrase("test123").unwrap();
    
    security_manager
}

/// Helper to create test identity store
async fn create_test_identity_store(temp_dir: &TempDir) -> Arc<IdentityStore> {
    let identity_store = Arc::new(IdentityStore::new(temp_dir.path().to_path_buf()));
    identity_store.init().await.unwrap();
    identity_store
}

#[tokio::test]
async fn test_identity_store_operations() {
    let temp_dir = TempDir::new().unwrap();
    let identity_store = create_test_identity_store(&temp_dir).await;
    
    // Create test identity
    let identity = Identity::new(
        "ed25519:test_public_key".to_string(),
        IdentityKeyType::Ed25519,
        "test_token_hash".to_string(),
        IdentityRole::Client,
        ClientType::AiAgent,
        Some("Test Bot".to_string()),
    );
    
    // Store identity
    identity_store.store(&identity).await.unwrap();
    
    // Load identity
    let loaded = identity_store.load(&identity.public_key).await.unwrap();
    assert_eq!(loaded.public_key, identity.public_key);
    assert_eq!(loaded.token_hash, identity.token_hash);
    assert!(loaded.is_active);
    
    // List all identities
    let identities = identity_store.list_all().await.unwrap();
    assert_eq!(identities.len(), 1);
    
    // Revoke identity
    identity_store.revoke(&identity.public_key).await.unwrap();
    
    // Verify revoked
    let revoked = identity_store.load(&identity.public_key).await.unwrap();
    assert!(!revoked.is_active);
}

#[tokio::test]
async fn test_identity_creation_with_p256() {
    let temp_dir = TempDir::new().unwrap();
    let identity_store = create_test_identity_store(&temp_dir).await;
    
    // Create P-256 identity
    let identity = Identity::new(
        "p256:test_public_key".to_string(),
        IdentityKeyType::P256,
        "test_token_hash".to_string(),
        IdentityRole::Client,
        ClientType::Service,
        Some("Test Service".to_string()),
    );
    
    identity_store.store(&identity).await.unwrap();
    
    let loaded = identity_store.load(&identity.public_key).await.unwrap();
    assert_eq!(loaded.key_type, IdentityKeyType::P256);
    assert_eq!(loaded.client_type, ClientType::Service);
}

#[tokio::test]
async fn test_identity_isolation() {
    let temp_dir = TempDir::new().unwrap();
    let identity_store = create_test_identity_store(&temp_dir).await;
    
    // Create two identities
    let identity_a = Identity::new(
        "ed25519:identity_a".to_string(),
        IdentityKeyType::Ed25519,
        "hash_a".to_string(),
        IdentityRole::Client,
        ClientType::AiAgent,
        Some("Identity A".to_string()),
    );
    
    let identity_b = Identity::new(
        "ed25519:identity_b".to_string(),
        IdentityKeyType::Ed25519,
        "hash_b".to_string(),
        IdentityRole::Client,
        ClientType::Service,
        Some("Identity B".to_string()),
    );
    
    identity_store.store(&identity_a).await.unwrap();
    identity_store.store(&identity_b).await.unwrap();
    
    // Verify both can be loaded independently
    let loaded_a = identity_store.load("ed25519:identity_a").await.unwrap();
    let loaded_b = identity_store.load("ed25519:identity_b").await.unwrap();
    
    assert_eq!(loaded_a.public_key, "ed25519:identity_a");
    assert_eq!(loaded_b.public_key, "ed25519:identity_b");
    
    // Verify namespaces are different
    assert_ne!(loaded_a.key_namespace(), loaded_b.key_namespace());
    
    // List should show both
    let identities = identity_store.list_all().await.unwrap();
    assert_eq!(identities.len(), 2);
}

#[tokio::test]
async fn test_identity_namespace_generation() {
    let identity = Identity::new(
        "ed25519:MCowBQYDK2VwAyEAabc123".to_string(),
        IdentityKeyType::Ed25519,
        "hash".to_string(),
        IdentityRole::Client,
        ClientType::User,
        None,
    );
    
    let namespace = identity.key_namespace();
    assert!(namespace.contains("ed25519:"));
    assert!(namespace.contains("/keys/"));
    assert_eq!(namespace, "ed25519:MCowBQYDK2VwAyEAabc123/keys/");
}
