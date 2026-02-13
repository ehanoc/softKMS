//! Test utilities and helpers

use std::path::PathBuf;
use tempfile::TempDir;

/// Creates a temporary directory for test data
pub fn temp_dir() -> TempDir {
    tempfile::tempdir().expect("Failed to create temp directory")
}

/// Path to test fixtures directory
pub fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
}

/// Test configuration builder
pub struct TestConfig {
    temp_dir: TempDir,
}

impl TestConfig {
    pub fn new() -> Self {
        Self {
            temp_dir: temp_dir(),
        }
    }
    
    pub fn storage_path(&self) -> PathBuf {
        self.temp_dir.path().join("storage")
    }
    
    pub fn config_path(&self) -> PathBuf {
        self.temp_dir.path().join("config.toml")
    }
    
    /// Create a minimal valid config file for testing
    pub fn create_config(&self) -> std::io::Result<PathBuf> {
        let config_content = r#"
[storage]
backend = "file"
path = "STORAGE_PATH"

[storage.encryption]
pbkdf2_iterations = 1000

[api]
grpc_addr = "127.0.0.1:0"
rest_addr = "127.0.0.1:0"
enable_pkcs11 = false

[logging]
level = "debug"
"#;
        
        let config_path = self.config_path();
        let storage_path = self.storage_path();
        
        let content = config_content.replace("STORAGE_PATH", storage_path.to_str().unwrap());
        std::fs::write(&config_path, content)?;
        
        Ok(config_path)
    }
}

impl Drop for TestConfig {
    fn drop(&mut self) {
        // TempDir automatically cleaned up on drop
    }
}

/// Wait for a condition with timeout
pub async fn wait_for<F, Fut>(
    mut condition: F, 
    timeout_ms: u64
) -> bool
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    let start = std::time::Instant::now();
    let timeout = std::time::Duration::from_millis(timeout_ms);
    
    while start.elapsed() < timeout {
        if condition().await {
            return true;
        }
        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
    }
    
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_temp_dir_creation() {
        let dir = temp_dir();
        assert!(dir.path().exists());
    }
    
    #[test]
    fn test_config_creation() {
        let config = TestConfig::new();
        let path = config.create_config().unwrap();
        assert!(path.exists());
        
        let content = std::fs::read_to_string(path).unwrap();
        assert!(content.contains("backend = \"file\""));
    }
}
