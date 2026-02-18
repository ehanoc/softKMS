//! Integration tests for storage backends
//!
//! These tests verify that storage implementations work correctly.

use softkms::storage::file::FileStorage;
use softkms::storage::StorageBackend;
use softkms::{KeyId, KeyMetadata, KeyType};

mod common;

/// Test FileStorage initialization
#[tokio::test]
async fn test_file_storage_init() {
    let temp_dir = tempfile::tempdir().unwrap();
    let storage_path = temp_dir.path().join("storage");
    
    // Create config
    let config = softkms::Config::default();
    
    // Create storage
    let storage = FileStorage::new(storage_path.clone(), config);
    
    // Initialize storage
    storage.init().await.unwrap();
    
    // Verify directory was created
    assert!(storage_path.exists());
    assert!(storage_path.is_dir());
}

/// Test storing and retrieving a key
#[tokio::test]
async fn test_file_storage_store_and_retrieve() {
    let temp_dir = tempfile::tempdir().unwrap();
    let storage_path = temp_dir.path().join("storage");
    let config = softkms::Config::default();
    let storage = FileStorage::new(storage_path, config);
    
    storage.init().await.unwrap();
    
    // Create test data
    let key_id = KeyId::new_v4();
    let metadata = KeyMetadata {
        id: key_id,
        label: Some("Test Key".to_string()),
        algorithm: "ed25519".to_string(),
        key_type: KeyType::Imported,
        created_at: chrono::Utc::now(),
        attributes: std::collections::HashMap::new(),
        public_key: vec![],
        owner_identity: None,
    };
    let encrypted_data = vec![1, 2, 3, 4, 5]; // Fake encrypted data
    
    // Store key
    storage.store_key(key_id, &metadata, &encrypted_data).await.unwrap();
    
    // Retrieve key
    let result = storage.retrieve_key(key_id).await.unwrap();
    
    // Verify
    assert!(result.is_some());
    let (retrieved_metadata, retrieved_data) = result.unwrap();
    assert_eq!(retrieved_metadata.id, key_id);
    assert_eq!(retrieved_metadata.algorithm, "ed25519");
    assert_eq!(retrieved_data, encrypted_data);
}

/// Test retrieving non-existent key
#[tokio::test]
async fn test_file_storage_retrieve_nonexistent() {
    let temp_dir = tempfile::tempdir().unwrap();
    let storage_path = temp_dir.path().join("storage");
    let config = softkms::Config::default();
    let storage = FileStorage::new(storage_path, config);
    
    storage.init().await.unwrap();
    
    let key_id = KeyId::new_v4();
    
    // Try to retrieve non-existent key
    let result = storage.retrieve_key(key_id).await.unwrap();
    
    assert!(result.is_none());
}

/// Test exists check
#[tokio::test]
async fn test_file_storage_exists() {
    let temp_dir = tempfile::tempdir().unwrap();
    let storage_path = temp_dir.path().join("storage");
    let config = softkms::Config::default();
    let storage = FileStorage::new(storage_path, config);
    
    storage.init().await.unwrap();
    
    let key_id = KeyId::new_v4();
    
    // Should not exist initially
    assert!(!storage.exists(key_id).await.unwrap());
    
    // Store a key
    let metadata = KeyMetadata {
        id: key_id,
        label: None,
        algorithm: "test".to_string(),
        key_type: KeyType::Imported,
        created_at: chrono::Utc::now(),
        attributes: std::collections::HashMap::new(),
        public_key: vec![],
        owner_identity: None,
    };
    storage.store_key(key_id, &metadata, b"test").await.unwrap();
    
    // Should exist now
    assert!(storage.exists(key_id).await.unwrap());
}

/// Test list keys
#[tokio::test]
async fn test_file_storage_list_keys() {
    let temp_dir = tempfile::tempdir().unwrap();
    let storage_path = temp_dir.path().join("storage");
    let config = softkms::Config::default();
    let storage = FileStorage::new(storage_path, config);
    
    storage.init().await.unwrap();
    
    // Initially empty (admin namespace)
    let keys = storage.list_keys(None).await.unwrap();
    assert!(keys.is_empty());
    
    // Store multiple keys
    for i in 0..3 {
        let key_id = KeyId::new_v4();
        let metadata = KeyMetadata {
            id: key_id,
            label: Some(format!("Key {}", i)),
            algorithm: "ed25519".to_string(),
            key_type: KeyType::Imported,
            created_at: chrono::Utc::now(),
            attributes: std::collections::HashMap::new(),
            public_key: vec![],
            owner_identity: None,  // Admin-owned for test
        };
        storage.store_key(key_id, &metadata, b"test").await.unwrap();
    }
    
    // List should return 3 keys from admin namespace
    let keys = storage.list_keys(None).await.unwrap();
    assert_eq!(keys.len(), 3);
}

/// Test delete key
#[tokio::test]
async fn test_file_storage_delete() {
    let temp_dir = tempfile::tempdir().unwrap();
    let storage_path = temp_dir.path().join("storage");
    let config = softkms::Config::default();
    let storage = FileStorage::new(storage_path, config);
    
    storage.init().await.unwrap();
    
    let key_id = KeyId::new_v4();
    let metadata = KeyMetadata {
        id: key_id,
        label: None,
        algorithm: "test".to_string(),
        key_type: KeyType::Imported,
        created_at: chrono::Utc::now(),
        attributes: std::collections::HashMap::new(),
        public_key: vec![],
        owner_identity: None,
    };
    
    // Store and verify exists
    storage.store_key(key_id, &metadata, b"test").await.unwrap();
    assert!(storage.exists(key_id).await.unwrap());
    
    // Delete
    storage.delete_key(key_id).await.unwrap();
    
    // Should not exist anymore
    assert!(!storage.exists(key_id).await.unwrap());
    
    // Retrieve should return None
    let result = storage.retrieve_key(key_id).await.unwrap();
    assert!(result.is_none());
}
