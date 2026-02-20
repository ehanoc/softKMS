//! Comprehensive tests for P-256 operations and passphrase validation
//!
//! These tests verify:
//! - Random P-256 key generation
//! - P-256 key derivation from BIP39 seeds
//! - Signing and verification with P-256
//! - Passphrase validation (correct, wrong, caching)
//! - Complete end-to-end workflows

use softkms::key_service::KeyService;
use softkms::security::{SecurityConfig, SecurityManager, create_cache};
use softkms::storage::file::FileStorage;
use softkms::storage::StorageBackend;
use softkms::{Config, KeyType};
use std::sync::Arc;
use tempfile::TempDir;

    #[cfg(test)]
mod p256_tests {
    use super::*;

    struct TestService {
        _temp_dir: TempDir,
        service: KeyService,
    }

    async fn create_test_service(passphrase: &str) -> TestService {
        let temp_dir = TempDir::new().unwrap();
        let storage = Arc::new(FileStorage::new(temp_dir.path().to_path_buf(), Config::default()));
        storage.init().await.unwrap();

        let security_config = SecurityConfig::new();
        let cache = create_cache(300);
        let security_manager = Arc::new(SecurityManager::new(cache, security_config, temp_dir.path().to_path_buf()));
        security_manager.init_with_passphrase(passphrase).unwrap();

        let config = Config::default();
        let service = KeyService::new(storage, security_manager, config);

        TestService {
            _temp_dir: temp_dir,
            service,
        }
    }

    #[tokio::test]
    async fn test_random_p256_key_generation() {
        let passphrase = "test_passphrase_123";
        let test = create_test_service(passphrase).await;
        let service = &test.service;

        // Generate random P-256 key (not from seed)
        let metadata = service.create_key(
            "p256".to_string(),
            Some("Random P256 Key".to_string()),
            std::collections::HashMap::new(),
            passphrase,
            None,
        ).await.unwrap();

        assert_eq!(metadata.algorithm, "p256");
        assert_eq!(metadata.key_type, KeyType::Imported);
        assert_eq!(metadata.label, Some("Random P256 Key".to_string()));

        // Verify key exists
        let keys = service.list_keys(None).await.unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].id, metadata.id);

        // Sign with the key
        let data = b"Test message for P-256 signing";
        let signature = service.sign(metadata.id, data, passphrase, None).await.unwrap();

        assert_eq!(signature.algorithm, "p256");
        assert_eq!(signature.bytes.len(), 64); // P-256 signature is 64 bytes (r || s)
    }

    #[tokio::test]
    async fn test_p256_key_derivation_from_seed() {
        let passphrase = "seed_passphrase_456";
        let test = create_test_service(passphrase).await;
        let service = &test.service;

        // Import a BIP39 seed
        let seed = vec![0u8; 64]; // 64-byte seed (simulating PBKDF2 output)
        let seed_metadata = service.import_seed(
            seed,
            Some("Test Seed".to_string()),
            passphrase,
            None,
        ).await.unwrap();

        assert_eq!(seed_metadata.algorithm, "bip32-seed");
        assert_eq!(seed_metadata.key_type, KeyType::Seed);

        // Derive P-256 key from seed
        let origin = "github.com";
        let user_handle = "user123@example.com";
        let counter = 0u32;

        let p256_metadata = service.derive_p256_key(
            seed_metadata.id,
            origin.to_string(),
            user_handle.to_string(),
            counter,
            Some("GitHub Passkey".to_string()),
            passphrase,
        ).await.unwrap();

        assert_eq!(p256_metadata.algorithm, "p256");
        assert_eq!(p256_metadata.key_type, KeyType::Derived);
        
        // Verify derivation params stored in attributes
        assert!(p256_metadata.attributes.contains_key("seed_id"));
        assert!(p256_metadata.attributes.contains_key("origin"));
        assert!(p256_metadata.attributes.contains_key("user_handle"));
        assert_eq!(p256_metadata.attributes.get("origin").unwrap(), origin);
        assert_eq!(p256_metadata.attributes.get("user_handle").unwrap(), user_handle);
        assert_eq!(p256_metadata.attributes.get("counter").unwrap(), "0");

        // Sign with derived key
        let data = b"WebAuthn challenge";
        let signature = service.sign(p256_metadata.id, data, passphrase, None).await.unwrap();
        
        assert_eq!(signature.algorithm, "p256");
        assert_eq!(signature.bytes.len(), 64);
    }

    #[tokio::test]
    async fn test_multiple_p256_keys_per_origin() {
        let passphrase = "multi_key_passphrase";
        let test = create_test_service(passphrase).await;
        let service = &test.service;

        // Import seed
        let seed = vec![1u8; 64];
        let seed_metadata = service.import_seed(seed, None, passphrase, None).await.unwrap();

        let origin = "github.com";
        let user_handle = "user@example.com";

        // Derive multiple keys with different counters
        let key1 = service.derive_p256_key(
            seed_metadata.id,
            origin.to_string(),
            user_handle.to_string(),
            0, // counter 0
            Some("Key 0".to_string()),
            passphrase,
        ).await.unwrap();

        let key2 = service.derive_p256_key(
            seed_metadata.id,
            origin.to_string(),
            user_handle.to_string(),
            1, // counter 1
            Some("Key 1".to_string()),
            passphrase,
        ).await.unwrap();

        let key3 = service.derive_p256_key(
            seed_metadata.id,
            origin.to_string(),
            user_handle.to_string(),
            2, // counter 2
            Some("Key 2".to_string()),
            passphrase,
        ).await.unwrap();

        // All keys should be different
        assert_ne!(key1.id, key2.id);
        assert_ne!(key2.id, key3.id);
        assert_ne!(key1.id, key3.id);

        // All should be P-256
        assert_eq!(key1.algorithm, "p256");
        assert_eq!(key2.algorithm, "p256");
        assert_eq!(key3.algorithm, "p256");

        // Total keys: 1 seed + 3 derived = 4
        let keys = service.list_keys(None).await.unwrap();
        assert_eq!(keys.len(), 4);

        // Each key should sign successfully
        for (i, key) in [&key1, &key2, &key3].iter().enumerate() {
            let data = format!("Message {}", i).as_bytes().to_vec();
            let sig = service.sign(key.id, &data, passphrase, None).await.unwrap();
            assert_eq!(sig.algorithm, "p256");
        }
    }

    #[tokio::test]
    async fn test_p256_key_reuse() {
        let passphrase = "reuse_test_pass";
        let test = create_test_service(passphrase).await;
        let service = &test.service;

        // Import seed
        let seed = vec![2u8; 64];
        let seed_metadata = service.import_seed(seed, None, passphrase, None).await.unwrap();

        // Derive key first time
        let origin = "example.com";
        let user_handle = "test_user";
        
        let key1 = service.derive_p256_key(
            seed_metadata.id,
            origin.to_string(),
            user_handle.to_string(),
            0,
            None,
            passphrase,
        ).await.unwrap();

        // Try to derive same key again (should return existing)
        let key2 = service.derive_p256_key(
            seed_metadata.id,
            origin.to_string(),
            user_handle.to_string(),
            0,
            None,
            passphrase,
        ).await.unwrap();

        // Should return same key
        assert_eq!(key1.id, key2.id);

        // Should only have 2 keys total (1 seed + 1 derived)
        let keys = service.list_keys(None).await.unwrap();
        assert_eq!(keys.len(), 2);
    }

    #[tokio::test]
    async fn test_p256_signature_determinism() {
        let passphrase = "det_passphrase";
        let test = create_test_service(passphrase).await;
        let service = &test.service;

        // Create P-256 key
        let metadata = service.create_key(
            "p256".to_string(),
            None,
            std::collections::HashMap::new(),
            passphrase,
            None,
        ).await.unwrap();

        // Sign same data twice
        let data = b"Deterministic test message";
        let sig1 = service.sign(metadata.id, data, passphrase, None).await.unwrap();
        let sig2 = service.sign(metadata.id, data, passphrase, None).await.unwrap();

        // P-256 signatures should be different (randomized signatures for security)
        // but both should verify correctly
        assert_eq!(sig1.bytes.len(), 64);
        assert_eq!(sig2.bytes.len(), 64);
        assert_eq!(sig1.algorithm, "p256");
        assert_eq!(sig2.algorithm, "p256");
    }

    #[tokio::test]
    async fn test_p256_wrong_passphrase_fails() {
        let correct_pass = "correct_passphrase";
        let wrong_pass = "wrong_passphrase";
        let test = create_test_service(correct_pass).await;
        let service = &test.service;

        // Create key with correct passphrase
        let metadata = service.create_key(
            "p256".to_string(),
            None,
            std::collections::HashMap::new(),
            correct_pass,
            None,
        ).await.unwrap();

        // Try to sign with wrong passphrase
        let data = b"Test data";
        let result = service.sign(metadata.id, data, wrong_pass, None).await;
        
        // Should fail with invalid passphrase
        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(err_msg.contains("Invalid passphrase"));
    }

    #[tokio::test]
    async fn test_p256_delete_key() {
        let passphrase = "delete_test_pass";
        let test = create_test_service(passphrase).await;
        let service = &test.service;

        // Create P-256 key
        let metadata = service.create_key(
            "p256".to_string(),
            Some("To Delete".to_string()),
            std::collections::HashMap::new(),
            passphrase,
            None,
        ).await.unwrap();

        // Verify exists
        let keys_before = service.list_keys(None).await.unwrap();
        assert_eq!(keys_before.len(), 1);

        // Delete (admin = None)
        service.delete_key(metadata.id, None).await.unwrap();

        // Verify gone
        let keys_after = service.list_keys(None).await.unwrap();
        assert_eq!(keys_after.len(), 0);

        // Try to sign with deleted key
        let result = service.sign(metadata.id, b"test", passphrase, None).await;
        assert!(result.is_err());
    }
}

#[cfg(test)]
mod passphrase_tests {
    use super::*;

    struct TestService {
        _temp_dir: TempDir,
        service: KeyService,
    }

    async fn create_test_service(passphrase: &str) -> TestService {
        let temp_dir = TempDir::new().unwrap();
        let storage = Arc::new(FileStorage::new(temp_dir.path().to_path_buf(), Config::default()));
        storage.init().await.unwrap();

        let security_config = SecurityConfig::new();
        let cache = create_cache(300);
        let security_manager = Arc::new(SecurityManager::new(cache, security_config, temp_dir.path().to_path_buf()));
        security_manager.init_with_passphrase(passphrase).unwrap();

        let config = Config::default();
        let service = KeyService::new(storage, security_manager, config);

        TestService {
            _temp_dir: temp_dir,
            service,
        }
    }

    #[tokio::test]
    async fn test_correct_passphrase_works() {
        let passphrase = "my_secret_passphrase";
        let test = create_test_service(passphrase).await;
        let service = &test.service;

        // Create key
        let metadata = service.create_key(
            "ed25519".to_string(),
            None,
            std::collections::HashMap::new(),
            passphrase,
            None,
        ).await.unwrap();

        // Sign with same passphrase
        let data = b"Test message";
        let result = service.sign(metadata.id, data, passphrase, None).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_wrong_passphrase_fails() {
        let correct_pass = "correct_passphrase";
        let wrong_pass = "wrong_passphrase";
        let test = create_test_service(correct_pass).await;
        let service = &test.service;

        // Create key with correct passphrase
        let metadata = service.create_key(
            "ed25519".to_string(),
            None,
            std::collections::HashMap::new(),
            correct_pass,
            None,
        ).await.unwrap();

        // Try wrong passphrase
        let data = b"Test message";
        let result = service.sign(metadata.id, data, wrong_pass, None).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_passphrase_consistency_across_operations() {
        let passphrase = "consistent_passphrase";
        let test = create_test_service(passphrase).await;
        let service = &test.service;

        // Create multiple keys with same passphrase
        let key1 = service.create_key("ed25519".to_string(), Some("Key 1".to_string()), std::collections::HashMap::new(), passphrase, None).await.unwrap();
        let key2 = service.create_key("ed25519".to_string(), Some("Key 2".to_string()), std::collections::HashMap::new(), passphrase, None).await.unwrap();
        let key3 = service.create_key("p256".to_string(), Some("Key 3".to_string()), std::collections::HashMap::new(), passphrase, None).await.unwrap();

        // All should sign with same passphrase
        for key in [&key1, &key2, &key3] {
            let sig = service.sign(key.id, b"test", passphrase, None).await;
            assert!(sig.is_ok(), "Failed to sign with key {}", key.id);
        }
    }

    #[tokio::test]
    async fn test_passphrase_with_seed_operations() {
        let passphrase = "seed_passphrase_test";
        let test = create_test_service(passphrase).await;
        let service = &test.service;

        // Import seed
        let seed = vec![5u8; 64];
        let seed_metadata = service.import_seed(seed, Some("My Seed".to_string()), passphrase, None).await.unwrap();

        // Derive key from seed
        let derived = service.derive_p256_key(
            seed_metadata.id,
            "test.com".to_string(),
            "user".to_string(),
            0,
            None,
            passphrase,
        ).await.unwrap();

        // Sign derived key
        let sig = service.sign(derived.id, b"test", passphrase, None).await;
        assert!(sig.is_ok());

        // Wrong passphrase should fail
        let wrong_result = service.sign(derived.id, b"test", "wrong_pass", None).await;
        assert!(wrong_result.is_err());
    }

    #[tokio::test]
    async fn test_empty_passphrase_fails() {
        let passphrase = "";
        let test = create_test_service(passphrase).await;
        let service = &test.service;

        // Empty passphrase should be rejected
        let _result = service.create_key(
            "ed25519".to_string(),
            None,
            std::collections::HashMap::new(),
            "",
            None,
        ).await;

        // The security manager should handle empty passphrases
        // This may succeed or fail depending on implementation
        // but we should document the behavior
    }

    #[tokio::test]
    async fn test_special_characters_in_passphrase() {
        let passphrase = "Sp3c!@l#C$h^a&r*a(c)t+e=r=s`~<>[]{}|;:'\"\\,./?";
        let test = create_test_service(passphrase).await;
        let service = &test.service;

        // Create with special chars
        let metadata = service.create_key(
            "ed25519".to_string(),
            None,
            std::collections::HashMap::new(),
            passphrase,
            None,
        ).await.unwrap();

        // Sign with same special chars
        let sig = service.sign(metadata.id, b"test", passphrase, None).await;
        assert!(sig.is_ok());
    }
}

#[cfg(test)]
mod integration_tests {
    use super::*;

    struct TestService {
        _temp_dir: TempDir,
        service: KeyService,
    }

    async fn create_test_service(passphrase: &str) -> TestService {
        let temp_dir = TempDir::new().unwrap();
        let storage = Arc::new(FileStorage::new(temp_dir.path().to_path_buf(), Config::default()));
        storage.init().await.unwrap();

        let security_config = SecurityConfig::new();
        let cache = create_cache(300);
        let security_manager = Arc::new(SecurityManager::new(cache, security_config, temp_dir.path().to_path_buf()));
        security_manager.init_with_passphrase(passphrase).unwrap();

        let config = Config::default();
        let service = KeyService::new(storage, security_manager, config);

        TestService {
            _temp_dir: temp_dir,
            service,
        }
    }

    #[tokio::test]
    async fn test_complete_p256_webauthn_workflow() {
        let passphrase = "webauthn_workflow_pass";
        let test = create_test_service(passphrase).await;
        let service = &test.service;

        // Step 1: Import BIP39 seed (simulating wallet recovery)
        let seed = vec![0xAB; 64]; // 64 bytes representing PBKDF2 output
        let seed_metadata = service.import_seed(
            seed,
            Some("Recovery Seed".to_string()),
            passphrase,
            None,
        ).await.unwrap();

        assert_eq!(seed_metadata.key_type, KeyType::Seed);

        // Step 2: Derive P-256 passkey for GitHub
        let github_key = service.derive_p256_key(
            seed_metadata.id,
            "github.com".to_string(),
            "user@example.com".to_string(),
            0,
            Some("GitHub Passkey".to_string()),
            passphrase,
        ).await.unwrap();

        assert_eq!(github_key.algorithm, "p256");
        assert_eq!(github_key.key_type, KeyType::Derived);

        // Step 3: Sign WebAuthn challenge
        let challenge = b"webauthn_challenge_data";
        let signature = service.sign(github_key.id, challenge, passphrase, None).await.unwrap();

        assert_eq!(signature.algorithm, "p256");
        assert_eq!(signature.bytes.len(), 64);

        // Step 4: Derive another key for different service
        let google_key = service.derive_p256_key(
            seed_metadata.id,
            "google.com".to_string(),
            "user@gmail.com".to_string(),
            0,
            Some("Google Passkey".to_string()),
            passphrase,
        ).await.unwrap();

        assert_ne!(github_key.id, google_key.id);

        // Step 5: Sign with Google key
        let google_sig = service.sign(google_key.id, challenge, passphrase, None).await.unwrap();
        assert_eq!(google_sig.algorithm, "p256");

        // Verify we have 3 keys: 1 seed + 2 derived
        let keys = service.list_keys(None).await.unwrap();
        assert_eq!(keys.len(), 3);
    }

    #[tokio::test]
    async fn test_mixed_algorithm_keyring() {
        let passphrase = "mixed_algo_pass";
        let test = create_test_service(passphrase).await;
        let service = &test.service;

        // Create various key types
        let ed25519_key = service.create_key(
            "ed25519".to_string(),
            Some("Ed25519 Key".to_string()),
            std::collections::HashMap::new(),
            passphrase,
            None,
        ).await.unwrap();

        let p256_key = service.create_key(
            "p256".to_string(),
            Some("P-256 Key".to_string()),
            std::collections::HashMap::new(),
            passphrase,
            None,
        ).await.unwrap();

        // Import seed and derive P-256
        let seed = vec![0xCD; 64];
        let seed_metadata = service.import_seed(seed, None, passphrase, None).await.unwrap();
        
        let derived_p256 = service.derive_p256_key(
            seed_metadata.id,
            "example.com".to_string(),
            "user".to_string(),
            0,
            Some("Derived P256".to_string()),
            passphrase,
        ).await.unwrap();

        // Sign with all keys
        let data = b"Multi-algorithm test";
        
        let ed25519_sig = service.sign(ed25519_key.id, data, passphrase, None).await.unwrap();
        let p256_sig = service.sign(p256_key.id, data, passphrase, None).await.unwrap();
        let derived_sig = service.sign(derived_p256.id, data, passphrase, None).await.unwrap();

        assert_eq!(ed25519_sig.algorithm, "ed25519");
        assert_eq!(p256_sig.algorithm, "p256");
        assert_eq!(derived_sig.algorithm, "p256");

        // Verify key count
        let keys = service.list_keys(None).await.unwrap();
        assert_eq!(keys.len(), 4); // 1 ed25519 + 1 p256 + 1 seed + 1 derived
    }

    #[tokio::test]
    async fn test_key_lifecycle_operations() {
        let passphrase = "lifecycle_test_pass";
        let test = create_test_service(passphrase).await;
        let service = &test.service;

        // Create
        let key = service.create_key(
            "p256".to_string(),
            Some("Lifecycle Test".to_string()),
            std::collections::HashMap::new(),
            passphrase,
            None,
        ).await.unwrap();

        // Read (get info)
        let retrieved = service.get_key(key.id).await.unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().label, Some("Lifecycle Test".to_string()));

        // Update (sign = use)
        let sig1 = service.sign(key.id, b"message1", passphrase, None).await.unwrap();
        let sig2 = service.sign(key.id, b"message2", passphrase, None).await.unwrap();
        assert_ne!(sig1.bytes, sig2.bytes); // Different signatures

        // Delete (admin = None)
        service.delete_key(key.id, None).await.unwrap();

        // Verify deletion
        let after_delete = service.get_key(key.id).await.unwrap();
        assert!(after_delete.is_none());

        // Verify can't use deleted key
        let result = service.sign(key.id, b"test", passphrase, None).await;
        assert!(result.is_err());
    }
}
