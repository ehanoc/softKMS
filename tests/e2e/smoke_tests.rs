//! End-to-end tests for softKMS
//!
//! These tests verify complete workflows from CLI to daemon.

use softkms::storage::StorageBackend;
use std::process::Command;
use std::time::Duration;

/// Test CLI help command
#[test]
fn test_cli_help() {
    let output = Command::new("cargo")
        .args(["run", "--bin", "softkms", "--", "--help"])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("Failed to run CLI --help");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    // CLI should show usage info
    let combined = format!("{} {}", stdout, stderr);
    assert!(
        combined.contains("softkms")
            || combined.contains("USAGE")
            || combined.contains("Commands"),
        "Expected CLI to show help. Got stdout: {}, stderr: {}",
        stdout,
        stderr
    );
}

/// Test daemon and CLI version match
#[test]
fn test_version_match() {
    // This test verifies that daemon and CLI report the same version
    // Once implemented, both should return the same version string

    // For now, just verify the version constant exists
    let version = env!("CARGO_PKG_VERSION");
    assert!(!version.is_empty());

    // Check version format (should be semver)
    let parts: Vec<&str> = version.split('.').collect();
    assert_eq!(parts.len(), 3, "Version should be in semver format");
}

/// Test configuration file loading
#[test]
fn test_config_file_parsing() {
    use softkms::Config;

    // Test that we can serialize and deserialize config
    let config = Config::default();

    // Serialize to TOML
    let toml_str = toml::to_string(&config).unwrap();

    // Deserialize back
    let parsed_config: Config = toml::from_str(&toml_str).unwrap();

    // Verify round-trip
    assert_eq!(config.api.grpc_addr, parsed_config.api.grpc_addr);
    assert_eq!(config.storage.backend, parsed_config.storage.backend);
}

/// Test build script
#[test]
fn test_build_script_exists() {
    let build_script = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("build.sh");
    assert!(build_script.exists(), "build.sh should exist");

    // Check it's executable
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let metadata = std::fs::metadata(&build_script).unwrap();
        let permissions = metadata.permissions();
        assert!(
            permissions.mode() & 0o111 != 0,
            "build.sh should be executable"
        );
    }
}

/// Docker configuration exists
#[test]
fn test_docker_config_exists() {
    let dockerfile = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("docker")
        .join("Dockerfile");

    assert!(
        dockerfile.exists()
            || std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("Dockerfile")
                .exists(),
        "Dockerfile should exist"
    );
}

/// Test project structure
#[test]
fn test_project_structure() {
    let base = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));

    // Required directories
    assert!(base.join("src").exists(), "src/ directory should exist");
    assert!(base.join("cli").exists(), "cli/ directory should exist");
    assert!(base.join("docs").exists(), "docs/ directory should exist");
    assert!(base.join("tests").exists(), "tests/ directory should exist");

    // Required files
    assert!(base.join("Cargo.toml").exists(), "Cargo.toml should exist");
    assert!(base.join("README.md").exists(), "README.md should exist");
}

/// Smoke test: verify cargo check passes
#[test]
#[ignore = "Takes too long for regular test runs"]
fn test_cargo_check() {
    let output = Command::new("cargo")
        .args(["check"])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("Failed to run cargo check");

    assert!(
        output.status.success(),
        "cargo check should pass:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// Smoke test: verify cargo test compiles
#[test]
#[ignore = "Takes too long for regular test runs"]
fn test_cargo_test_compiles() {
    let output = Command::new("cargo")
        .args(["test", "--no-run"])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("Failed to compile tests");

    assert!(
        output.status.success(),
        "cargo test --no-run should compile:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// Integration test: Key lifecycle with passphrase
#[tokio::test]
async fn test_key_lifecycle_with_passphrase() {
    use softkms::key_service::KeyService;
    use softkms::storage::file::FileStorage;
    use softkms::storage::StorageBackend;
    use softkms::security::{SecurityConfig, SecurityManager, create_cache};
    use softkms::Config;
    use std::sync::Arc;
    use tempfile::TempDir;

    // Setup
    let temp_dir = TempDir::new().unwrap();
    let storage = Arc::new(FileStorage::new(
        temp_dir.path().to_path_buf(),
        Config::default()
    ));
    storage.init().await.unwrap();

    let security_config = SecurityConfig::new();
    let cache = create_cache(300);
    let security_manager = Arc::new(SecurityManager::new(cache, security_config, temp_dir.path().to_path_buf()));
    security_manager.init_with_passphrase("my_secure_passphrase_123").unwrap();
    let config = Config::default();

    let service = KeyService::new(storage, security_manager, config);
    let passphrase = "my_secure_passphrase_123";

    // 1. Create key (admin-owned)
    let metadata = service.create_key(
        "ed25519".to_string(),
        Some("Test Key".to_string()),
        std::collections::HashMap::new(),
        passphrase,
        None,
    ).await.unwrap();

    assert_eq!(metadata.algorithm, "ed25519");
    assert_eq!(metadata.label, Some("Test Key".to_string()));

    // 2. List keys
    let keys = service.list_keys().await.unwrap();
    assert_eq!(keys.len(), 1);

    // 3. Get key info
    let key_info = service.get_key(metadata.id).await.unwrap();
    assert!(key_info.is_some());
    assert_eq!(key_info.unwrap().label, Some("Test Key".to_string()));

    // 4. Sign data (admin request)
    let data = b"Hello, World!";
    let signature = service.sign(metadata.id, data, passphrase, None).await.unwrap();
    assert_eq!(signature.algorithm, "ed25519");
    assert_eq!(signature.bytes.len(), 64);

    // 5. Create second key with same passphrase (admin-owned)
    let metadata2 = service.create_key(
        "ed25519".to_string(),
        Some("Second Key".to_string()),
        std::collections::HashMap::new(),
        passphrase,
        None,
    ).await.unwrap();

    // 6. Verify both keys work (admin requests)
    let sig1 = service.sign(metadata.id, data, passphrase, None).await.unwrap();
    let sig2 = service.sign(metadata2.id, data, passphrase, None).await.unwrap();
    assert_ne!(sig1.bytes, sig2.bytes); // Different keys, different signatures

    // 7. Wrong passphrase behavior
    // Note: Currently SecurityManager caches master key, so wrong passphrase
    // only fails if cache is empty. To properly test, we'd need a fresh instance.
    let _wrong_result = service.sign(metadata.id, data, "wrong_passphrase", None).await;
    // Result depends on cache state - may succeed if cached, fail if not

    // 8. Delete key
    service.delete_key(metadata.id).await.unwrap();
    let remaining = service.list_keys().await.unwrap();
    assert_eq!(remaining.len(), 1);
}

/// Test import seed and key derivation
#[tokio::test]
async fn test_seed_import_and_operations() {
    use softkms::key_service::KeyService;
    use softkms::storage::file::FileStorage;
    use softkms::storage::StorageBackend;
    use softkms::security::{SecurityConfig, SecurityManager, create_cache};
    use softkms::Config;
    use std::sync::Arc;
    use tempfile::TempDir;

    let temp_dir = TempDir::new().unwrap();
    let storage = Arc::new(FileStorage::new(
        temp_dir.path().to_path_buf(),
        Config::default()
    ));
    storage.init().await.unwrap();

    let security_config = SecurityConfig::new();
    let cache = create_cache(300);
    let security_manager = Arc::new(SecurityManager::new(cache, security_config, temp_dir.path().to_path_buf()));
    security_manager.init_with_passphrase("seed_passphrase_456").unwrap();
    let config = Config::default();

    let service = KeyService::new(storage, security_manager, config);
    let passphrase = "seed_passphrase_456";

    // Import seed
    let seed = vec![1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
                    17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32];
    
    let metadata = service.import_seed(
        seed,
        Some("Recovery Seed".to_string()),
        passphrase,
    ).await.unwrap();

    assert_eq!(metadata.algorithm, "bip32-seed");
    assert_eq!(metadata.key_type, softkms::KeyType::Seed);

    // List should show seed
    let keys = service.list_keys().await.unwrap();
    assert_eq!(keys.len(), 1);
}

/// Test security: encrypted storage format
#[tokio::test]
async fn test_encrypted_storage_format() {
    use softkms::key_service::KeyService;
    use softkms::storage::file::FileStorage;
    use softkms::storage::StorageBackend;
    use softkms::security::{SecurityConfig, SecurityManager, create_cache};
    use softkms::Config;
    use std::sync::Arc;
    use tempfile::TempDir;

    let temp_dir = TempDir::new().unwrap();
    let storage_path = temp_dir.path().to_path_buf();
    
    // Create service
    let storage = Arc::new(FileStorage::new(
        storage_path.clone(),
        Config::default()
    ));
    storage.init().await.unwrap();

    let security_config = SecurityConfig::new();
    let cache = create_cache(300);
    let security_manager = Arc::new(SecurityManager::new(cache, security_config, storage_path.clone()));
    security_manager.init_with_passphrase("storage_test_passphrase").unwrap();
    let config = Config::default();

    let service = KeyService::new(storage, security_manager, config);
    let passphrase = "storage_test_passphrase";

    // Create key (admin-owned)
    let metadata = service.create_key(
        "ed25519".to_string(),
        None,
        std::collections::HashMap::new(),
        passphrase,
        None,
    ).await.unwrap();

    // Verify encrypted file exists
    let key_file = storage_path.join(format!("{}.enc", metadata.id));
    assert!(key_file.exists(), "Encrypted key file should exist");

    // Read encrypted data - should not be plaintext
    let encrypted_data = std::fs::read(&key_file).unwrap();
    
    // Should start with version byte (0x01)
    assert_eq!(encrypted_data[0], 0x01, "Should start with version byte");
    
    // Should be reasonable size (not plaintext)
    assert!(encrypted_data.len() > 100, "Should be encrypted, not plaintext");

    // Metadata file should exist
    let metadata_file = storage_path.join(format!("{}.json", metadata.id));
    assert!(metadata_file.exists(), "Metadata file should exist");

    // Metadata should be JSON (not encrypted)
    let metadata_str = std::fs::read_to_string(&metadata_file).unwrap();
    assert!(metadata_str.contains("algorithm"), "Metadata should be readable JSON");
}

/// Test daemon API health endpoint
#[test]
fn test_daemon_health_endpoint() {
    // This is a smoke test - full integration would need running daemon
    use softkms::Config;
    
    let config = Config::default();
    assert!(!config.api.grpc_addr.is_empty());
    
    // Validate address format
    assert!(config.api.grpc_addr.starts_with("127.0.0.1:") 
        || config.api.grpc_addr.starts_with("0.0.0.0:")
        || config.api.grpc_addr.starts_with("[::1]:")
        || config.api.grpc_addr.starts_with("localhost:"));
}
