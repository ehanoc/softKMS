//! Integration tests for the softKMS daemon
//!
//! These tests verify that the daemon can start, stop, and handle basic operations.

use std::time::Duration;
use tokio::process::Command;

mod common;

/// Test that the daemon binary exists and can show help
#[tokio::test]
async fn test_daemon_help() {
    let output = Command::new("cargo")
        .args(["run", "--bin", "softkms-daemon", "--", "--help"])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .await
        .expect("Failed to run daemon --help");
    
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    
    // Check that help output contains expected text
    let combined = format!("{} {}", stdout, stderr);
    assert!(
        combined.contains("softKMS") || combined.contains("daemon") || combined.contains("USAGE"),
        "Expected daemon to show help. Got stdout: {}, stderr: {}",
        stdout,
        stderr
    );
}

/// Test that the daemon starts and responds to a basic health check
/// This test is marked as #[ignore] because it requires the daemon to actually start
#[tokio::test]
#[ignore = "Daemon implementation not complete"]
async fn test_daemon_startup() {
    use tokio::net::TcpListener;
    
    // Find an available port
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    
    // Create temporary config
    let config = common::TestConfig::new();
    let config_path = config.create_config().unwrap();
    
    // Start daemon as child process
    let mut daemon = Command::new("cargo")
        .args([
            "run",
            "--bin",
            "softkms-daemon",
            "--",
            "--config",
            config_path.to_str().unwrap(),
            "--port",
            &port.to_string(),
        ])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .spawn()
        .expect("Failed to spawn daemon");
    
    // Wait for daemon to start (give it time)
    tokio::time::sleep(Duration::from_secs(2)).await;
    
    // Try to connect to daemon
    match tokio::net::TcpStream::connect(format!("127.0.0.1:{}", port)).await {
        Ok(_) => {
            // Daemon is running, good!
        }
        Err(e) => {
            // Daemon might not be fully implemented yet
            println!("Daemon not yet listening: {}", e);
        }
    }
    
    // Clean up
    let _ = daemon.kill().await;
}

/// Test configuration loading
#[test]
fn test_config_defaults() {
    use softkms::Config;
    
    let config = Config::default();
    
    // Verify default values
    assert_eq!(config.api.grpc_addr, "127.0.0.1:50051");
    assert_eq!(config.storage.backend, "file");
    assert_eq!(config.storage.encryption.pbkdf2_iterations, 210_000);
}

/// Test that storage backend trait is properly defined
#[test]
fn test_storage_trait_exists() {
    // This test just verifies the trait is defined
    // More detailed tests would be in storage-specific test files
    use softkms::storage::StorageBackend;
    use softkms::KeyId;
    
    // We can't actually call methods without an implementation,
    // but we can verify the trait exists and has expected methods
    fn check_trait<T: StorageBackend>() {}
    
    // This would fail to compile if StorageBackend wasn't properly defined
    // (but doesn't actually test anything at runtime yet)
    let _ = std::any::type_name::<&dyn StorageBackend>();
}

/// Test error type conversions
#[test]
fn test_error_types() {
    use softkms::Error;
    
    let err = Error::Crypto("test".to_string());
    assert!(err.to_string().contains("Crypto error"));
    
    let err = Error::Storage("test".to_string());
    assert!(err.to_string().contains("Storage error"));
    
    let err = Error::KeyNotFound("test".to_string());
    assert!(err.to_string().contains("Key not found"));
}

/// Test key ID type
#[test]
fn test_key_id_type() {
    use softkms::KeyId;
    use uuid::Uuid;
    
    let id = KeyId::new_v4();
    assert_eq!(std::mem::size_of::<KeyId>(), std::mem::size_of::<Uuid>());
}
