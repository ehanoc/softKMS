//! Identity storage implementation
//!
//! Stores identity metadata in JSON files with quick lookup index

use std::collections::HashMap;
use std::path::PathBuf;

use chrono::Utc;

use crate::identity::types::{Identity, IdentityError, Result};

/// Identity storage backend
pub struct IdentityStore {
    base_path: PathBuf,
}

impl IdentityStore {
    /// Create new identity store
    pub fn new(base_path: PathBuf) -> Self {
        Self { base_path }
    }

    /// Initialize storage directories
    pub async fn init(&self) -> Result<()> {
        tokio::fs::create_dir_all(&self.base_path)
            .await
            .map_err(|e| IdentityError::Storage(e.to_string()))?;
        tokio::fs::create_dir_all(self.identities_dir())
            .await
            .map_err(|e| IdentityError::Storage(e.to_string()))?;

        // Create index if it doesn't exist
        let index_path = self.index_path();
        if !index_path.exists() {
            let index: HashMap<String, String> = HashMap::new();
            let json = serde_json::to_string_pretty(&index)
                .map_err(|e| IdentityError::Storage(e.to_string()))?;
            tokio::fs::write(&index_path, json)
                .await
                .map_err(|e| IdentityError::Storage(e.to_string()))?;
        }

        Ok(())
    }

    /// Store an identity
    pub async fn store(&self, identity: &Identity) -> Result<()> {
        // Create identity file
        let identity_path = self.identity_path(&identity.public_key);
        let json = serde_json::to_string_pretty(identity)
            .map_err(|e| IdentityError::Storage(format!("Failed to serialize identity: {}", e)))?;

        tokio::fs::write(&identity_path, json)
            .await
            .map_err(|e| IdentityError::Storage(format!("Failed to write identity: {}", e)))?;

        // Update index
        self.add_to_index(&identity.public_key).await?;

        Ok(())
    }

    /// Load an identity by public key
    pub async fn load(&self, public_key: &str) -> Result<Identity> {
        let identity_path = self.identity_path(public_key);

        if !identity_path.exists() {
            return Err(IdentityError::IdentityNotFound(public_key.to_string()));
        }

        let json = tokio::fs::read_to_string(&identity_path)
            .await
            .map_err(|e| IdentityError::Storage(format!("Failed to read identity: {}", e)))?;

        let identity: Identity = serde_json::from_str(&json)
            .map_err(|e| IdentityError::Storage(format!("Failed to parse identity: {}", e)))?;

        Ok(identity)
    }

    /// Load identity by token hash
    pub async fn load_by_token_hash(&self, token_hash: &str) -> Result<Identity> {
        // Get all identities and find by token hash
        let identities = self.list_all().await?;

        identities.into_iter()
            .find(|i| i.token_hash == token_hash)
            .ok_or_else(|| IdentityError::InvalidIdentity)
    }

    /// List all identities
    pub async fn list_all(&self) -> Result<Vec<Identity>> {
        let mut identities = Vec::new();

        let mut entries = tokio::fs::read_dir(self.identities_dir())
            .await
            .map_err(|e| IdentityError::Storage(format!("Failed to read identities dir: {}", e)))?;

        while let Some(entry) = entries.next_entry()
            .await
            .map_err(|e| IdentityError::Storage(format!("Failed to read entry: {}", e)))? {
            let path = entry.path();

            // Skip the index file and non-JSON files
            if path.file_name().map(|n| n == "index.json").unwrap_or(true) {
                continue;
            }

            if path.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }

            let json = tokio::fs::read_to_string(&path)
                .await
                .map_err(|e| IdentityError::Storage(format!("Failed to read identity: {}", e)))?;

            let identity: Identity = serde_json::from_str(&json)
                .map_err(|e| IdentityError::Storage(format!("Failed to parse identity: {}", e)))?;

            identities.push(identity);
        }

        Ok(identities)
    }

    /// List active identities only
    pub async fn list_active(&self) -> Result<Vec<Identity>> {
        let all = self.list_all().await?;
        Ok(all.into_iter().filter(|i| i.is_active).collect())
    }

    /// Update an identity
    pub async fn update(&self, identity: &Identity) -> Result<()> {
        self.store(identity).await
    }

    /// Revoke an identity
    pub async fn revoke(&self, public_key: &str) -> Result<()> {
        let mut identity = self.load(public_key).await?;
        identity.revoke();
        self.update(&identity).await
    }

    /// Check if identity exists
    pub async fn exists(&self, public_key: &str) -> bool {
        self.identity_path(public_key).exists()
    }

    /// Get identity file path
    fn identity_path(&self, public_key: &str) -> PathBuf {
        // Sanitize public key for filename (replace / with _)
        let sanitized = public_key.replace('/', "_");
        self.identities_dir().join(format!("{}.json", sanitized))
    }

    /// Get identities directory
    fn identities_dir(&self) -> PathBuf {
        self.base_path.join("identities")
    }

    /// Get index file path
    fn index_path(&self) -> PathBuf {
        self.identities_dir().join("index.json")
    }

    /// Add to index
    async fn add_to_index(&self, public_key: &str) -> Result<()> {
        let index_path = self.index_path();

        let json = tokio::fs::read_to_string(&index_path)
            .await
            .map_err(|e| IdentityError::Storage(format!("Failed to read index: {}", e)))?;

        let mut index: HashMap<String, String> = serde_json::from_str(&json)
            .map_err(|e| IdentityError::Storage(format!("Failed to parse index: {}", e)))?;

        index.insert(public_key.to_string(), Utc::now().to_rfc3339());

        let json = serde_json::to_string_pretty(&index)
            .map_err(|e| IdentityError::Storage(format!("Failed to serialize index: {}", e)))?;

        tokio::fs::write(index_path, json)
            .await
            .map_err(|e| IdentityError::Storage(format!("Failed to write index: {}", e)))?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::types::{ClientType, IdentityKeyType, IdentityRole};
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_store_and_load() {
        let temp = TempDir::new().unwrap();
        let store = IdentityStore::new(temp.path().to_path_buf());
        store.init().await.unwrap();

        let identity = Identity::new(
            "ed25519:test123".to_string(),
            IdentityKeyType::Ed25519,
            "aabbccdd".to_string(),
            IdentityRole::Client,
            ClientType::AiAgent,
            Some("Test".to_string()),
        );

        // Store
        store.store(&identity).await.unwrap();

        // Load
        let loaded = store.load("ed25519:test123").await.unwrap();
        assert_eq!(loaded.public_key, identity.public_key);
        assert_eq!(loaded.client_type, ClientType::AiAgent);
    }

    #[tokio::test]
    async fn test_list_all() {
        let temp = TempDir::new().unwrap();
        let store = IdentityStore::new(temp.path().to_path_buf());
        store.init().await.unwrap();

        // Create multiple identities
        for i in 0..3 {
            let identity = Identity::new(
                format!("ed25519:test{}", i),
                IdentityKeyType::Ed25519,
                format!("hash{}", i),
                IdentityRole::Client,
                ClientType::Service,
                None,
            );
            store.store(&identity).await.unwrap();
        }

        let all = store.list_all().await.unwrap();
        assert_eq!(all.len(), 3);
    }

    #[tokio::test]
    async fn test_revoke() {
        let temp = TempDir::new().unwrap();
        let store = IdentityStore::new(temp.path().to_path_buf());
        store.init().await.unwrap();

        let identity = Identity::new(
            "ed25519:revoke_test".to_string(),
            IdentityKeyType::Ed25519,
            "hash".to_string(),
            IdentityRole::Client,
            ClientType::AiAgent,
            None,
        );
        store.store(&identity).await.unwrap();

        // Revoke
        store.revoke("ed25519:revoke_test").await.unwrap();

        // Check revoked
        let loaded = store.load("ed25519:revoke_test").await.unwrap();
        assert!(!loaded.is_active);

        // Should not be in active list
        let active = store.list_active().await.unwrap();
        assert!(active.is_empty());
    }

    #[tokio::test]
    async fn test_not_found() {
        let temp = TempDir::new().unwrap();
        let store = IdentityStore::new(temp.path().to_path_buf());
        store.init().await.unwrap();

        let result = store.load("ed25519:nonexistent").await;
        assert!(matches!(result, Err(IdentityError::IdentityNotFound(_))));
    }
}
