//! File-based encrypted storage backend

use crate::storage::StorageBackend;
use crate::{Config, KeyId, KeyMetadata, Result};
use std::path::PathBuf;

/// File-based storage backend
pub struct FileStorage {
    base_path: PathBuf,
    _config: Config,
}

impl FileStorage {
    /// Create new file storage
    pub fn new(base_path: PathBuf, config: Config) -> Self {
        Self {
            base_path,
            _config: config,
        }
    }

    /// Sanitize identity public key for use in filesystem paths
    /// Replaces filesystem-unsafe characters with underscores
    fn sanitize_identity(&self, identity: &str) -> String {
        identity.replace('/', "_").replace(':', "_")
    }

    /// Get namespace directory path for keys
    /// 
    /// # Arguments
    /// * `owner_identity` - None for admin keys, Some(identity_pubkey) for identity-scoped keys
    fn namespace_dir(&self, owner_identity: Option<&str>) -> PathBuf {
        let keys_base = self.base_path.join("keys");
        match owner_identity {
            None => keys_base.join("admin"),
            Some(id) => {
                let sanitized = self.sanitize_identity(id);
                keys_base.join(sanitized).join("keys")
            }
        }
    }

    /// Get path for key file within namespace
    fn namespaced_key_path(&self, owner_identity: Option<&str>, id: KeyId) -> PathBuf {
        self.namespace_dir(owner_identity).join(format!("{}.enc", id))
    }

    /// Get path for metadata file within namespace
    fn namespaced_metadata_path(&self, owner_identity: Option<&str>, id: KeyId) -> PathBuf {
        self.namespace_dir(owner_identity).join(format!("{}.json", id))
    }

    /// Get path for seed file within namespace (seeds/ subdirectory)
    fn namespaced_seed_path(&self, owner_identity: Option<&str>, id: KeyId) -> PathBuf {
        self.namespace_dir(owner_identity).join("seeds").join(format!("{}.enc", id))
    }

    /// Get path for seed metadata file within namespace (seeds/ subdirectory)
    fn namespaced_seed_metadata_path(&self, owner_identity: Option<&str>, id: KeyId) -> PathBuf {
        self.namespace_dir(owner_identity).join("seeds").join(format!("{}.json", id))
    }

    /// Legacy path helpers (for backward compatibility during transition)
    #[allow(dead_code)]
    fn key_path(&self, id: KeyId) -> PathBuf {
        self.base_path.join(format!("{}.enc", id))
    }

    #[allow(dead_code)]
    fn metadata_path(&self, id: KeyId) -> PathBuf {
        self.base_path.join(format!("{}.json", id))
    }
}

impl StorageBackend for FileStorage {
    fn init(&self,
    ) -> crate::storage::BoxFuture<'_, Result<()>> {
        Box::pin(async move {
            tokio::fs::create_dir_all(&self.base_path)
                .await
                .map_err(|e| {
                    crate::Error::Storage(format!(
                        "Failed to create storage directory: {}",
                        e
                    ))
                })?;
            Ok(())
        })
    }

    fn store_key(
        &self,
        id: KeyId,
        metadata: &KeyMetadata,
        encrypted_data: &[u8],
    ) -> crate::storage::BoxFuture<'_, Result<()>> {
        let metadata = metadata.clone();
        let encrypted_data = encrypted_data.to_vec();
        
        // Extract owner_identity from metadata to determine namespace
        let owner_identity = metadata.owner_identity.clone();
        let is_seed = metadata.algorithm == "bip32-seed";
        
        // Use seeds/ subdirectory for seeds, keys/ for regular keys
        let (namespace_dir, metadata_path, key_path) = if is_seed {
            let ns_dir = self.namespace_dir(owner_identity.as_deref()).join("seeds");
            let meta_path = self.namespaced_seed_metadata_path(owner_identity.as_deref(), id);
            let k_path = self.namespaced_seed_path(owner_identity.as_deref(), id);
            (ns_dir, meta_path, k_path)
        } else {
            let ns_dir = self.namespace_dir(owner_identity.as_deref());
            let meta_path = self.namespaced_metadata_path(owner_identity.as_deref(), id);
            let k_path = self.namespaced_key_path(owner_identity.as_deref(), id);
            (ns_dir, meta_path, k_path)
        };

        Box::pin(async move {
            // Create namespace directory if it doesn't exist
            tokio::fs::create_dir_all(&namespace_dir)
                .await
                .map_err(|e| crate::Error::Storage(format!(
                    "Failed to create namespace directory: {}",
                    e
                )))?;

            // Store metadata
            let metadata_json = serde_json::to_string(&metadata)
                .map_err(|e| crate::Error::Storage(format!("Failed to serialize metadata: {}", e)))?;

            tokio::fs::write(&metadata_path, metadata_json)
                .await
                .map_err(|e| crate::Error::Storage(format!("Failed to write metadata: {}", e)))?;

            // Store encrypted key data
            tokio::fs::write(&key_path, encrypted_data)
                .await
                .map_err(|e| crate::Error::Storage(format!("Failed to write key data: {}", e)))?;

            Ok(())
        })
    }

    fn retrieve_key(
        &self,
        id: KeyId,
    ) -> crate::storage::BoxFuture<'_, Result<Option<(KeyMetadata, Vec<u8>)>>> {
        Box::pin(async move {
            // Search in namespace directories - check both keys/ and seeds/ subdirectories
            
            // First check admin namespace keys/
            let admin_metadata_path = self.namespaced_metadata_path(None, id);
            let admin_key_path = self.namespaced_key_path(None, id);
            
            if tokio::fs::try_exists(&admin_metadata_path)
                .await
                .map_err(|e| crate::Error::Storage(format!("Failed to check metadata: {}", e)))?
            {
                // Found in admin namespace keys/
                let metadata_json = tokio::fs::read_to_string(&admin_metadata_path)
                    .await
                    .map_err(|e| crate::Error::Storage(format!("Failed to read metadata: {}", e)))?;

                let metadata: KeyMetadata = serde_json::from_str(&metadata_json)
                    .map_err(|e| crate::Error::Storage(format!("Failed to parse metadata: {}", e)))?;

                let encrypted_data = tokio::fs::read(&admin_key_path)
                    .await
                    .map_err(|e| crate::Error::Storage(format!("Failed to read key data: {}", e)))?;

                return Ok(Some((metadata, encrypted_data)));
            }
            
            // Check admin namespace seeds/
            let admin_seed_metadata_path = self.namespaced_seed_metadata_path(None, id);
            let admin_seed_path = self.namespaced_seed_path(None, id);
            
            if tokio::fs::try_exists(&admin_seed_metadata_path)
                .await
                .map_err(|e| crate::Error::Storage(format!("Failed to check seed metadata: {}", e)))?
            {
                // Found in admin namespace seeds/
                let metadata_json = tokio::fs::read_to_string(&admin_seed_metadata_path)
                    .await
                    .map_err(|e| crate::Error::Storage(format!("Failed to read seed metadata: {}", e)))?;

                let metadata: KeyMetadata = serde_json::from_str(&metadata_json)
                    .map_err(|e| crate::Error::Storage(format!("Failed to parse seed metadata: {}", e)))?;

                let encrypted_data = tokio::fs::read(&admin_seed_path)
                    .await
                    .map_err(|e| crate::Error::Storage(format!("Failed to read seed data: {}", e)))?;

                return Ok(Some((metadata, encrypted_data)));
            }

            // Search through identity namespaces
            let keys_dir = self.base_path.join("keys");
            if let Ok(mut entries) = tokio::fs::read_dir(&keys_dir).await {
                while let Ok(Some(entry)) = entries.next_entry().await {
                    let path = entry.path();
                    if path.is_dir() {
                        let dir_name = path.file_name()
                            .and_then(|n| n.to_str())
                            .unwrap_or("");
                        
                        // Skip admin directory (already checked)
                        if dir_name == "admin" {
                            continue;
                        }

                        // Check if key exists in this namespace keys/
                        let ns_metadata_path = path.join("keys").join(format!("{}.json", id));
                        let ns_key_path = path.join("keys").join(format!("{}.enc", id));

                        if tokio::fs::try_exists(&ns_metadata_path)
                            .await
                            .unwrap_or(false)
                        {
                            let metadata_json = tokio::fs::read_to_string(&ns_metadata_path)
                                .await
                                .map_err(|e| crate::Error::Storage(format!("Failed to read metadata: {}", e)))?;

                            let metadata: KeyMetadata = serde_json::from_str(&metadata_json)
                                .map_err(|e| crate::Error::Storage(format!("Failed to parse metadata: {}", e)))?;

                            let encrypted_data = tokio::fs::read(&ns_key_path)
                                .await
                                .map_err(|e| crate::Error::Storage(format!("Failed to read key data: {}", e)))?;

                            return Ok(Some((metadata, encrypted_data)));
                        }
                        
                        // Check if seed exists in this namespace seeds/
                        let ns_seed_metadata_path = path.join("seeds").join(format!("{}.json", id));
                        let ns_seed_path = path.join("seeds").join(format!("{}.enc", id));

                        if tokio::fs::try_exists(&ns_seed_metadata_path)
                            .await
                            .unwrap_or(false)
                        {
                            let metadata_json = tokio::fs::read_to_string(&ns_seed_metadata_path)
                                .await
                                .map_err(|e| crate::Error::Storage(format!("Failed to read seed metadata: {}", e)))?;

                            let metadata: KeyMetadata = serde_json::from_str(&metadata_json)
                                .map_err(|e| crate::Error::Storage(format!("Failed to parse seed metadata: {}", e)))?;

                            let encrypted_data = tokio::fs::read(&ns_seed_path)
                                .await
                                .map_err(|e| crate::Error::Storage(format!("Failed to read seed data: {}", e)))?;

                            return Ok(Some((metadata, encrypted_data)));
                        }
                    }
                }
            }

            // Key/seed not found in any namespace
            Ok(None)
        })
    }

    fn delete_key(&self,
        id: KeyId,
    ) -> crate::storage::BoxFuture<'_, Result<()>> {
        Box::pin(async move {
            // Find the key in namespaces and delete it
            // First check admin namespace keys/
            let admin_metadata_path = self.namespaced_metadata_path(None, id);
            let admin_key_path = self.namespaced_key_path(None, id);
            
            if tokio::fs::try_exists(&admin_metadata_path)
                .await
                .unwrap_or(false)
            {
                // Secure delete: overwrite with zeros before deletion
                if let Ok(metadata) = tokio::fs::metadata(&admin_key_path).await {
                    let size = metadata.len() as usize;
                    let zeros = vec![0u8; size];
                    let _ = tokio::fs::write(&admin_key_path, &zeros).await;
                }

                let _ = tokio::fs::remove_file(&admin_metadata_path).await;
                let _ = tokio::fs::remove_file(&admin_key_path).await;
                return Ok(());
            }

            // Check admin namespace seeds/
            let admin_seed_metadata_path = self.namespaced_seed_metadata_path(None, id);
            let admin_seed_path = self.namespaced_seed_path(None, id);
            
            if tokio::fs::try_exists(&admin_seed_metadata_path)
                .await
                .unwrap_or(false)
            {
                // Secure delete: overwrite with zeros before deletion
                if let Ok(metadata) = tokio::fs::metadata(&admin_seed_path).await {
                    let size = metadata.len() as usize;
                    let zeros = vec![0u8; size];
                    let _ = tokio::fs::write(&admin_seed_path, &zeros).await;
                }

                let _ = tokio::fs::remove_file(&admin_seed_metadata_path).await;
                let _ = tokio::fs::remove_file(&admin_seed_path).await;
                return Ok(());
            }

            // Search through identity namespaces
            let keys_dir = self.base_path.join("keys");
            if let Ok(mut entries) = tokio::fs::read_dir(&keys_dir).await {
                while let Ok(Some(entry)) = entries.next_entry().await {
                    let path = entry.path();
                    if path.is_dir() {
                        let dir_name = path.file_name()
                            .and_then(|n| n.to_str())
                            .unwrap_or("");
                        
                        if dir_name == "admin" {
                            continue;
                        }

                        // Check identity namespace keys/
                        let ns_metadata_path = path.join("keys").join(format!("{}.json", id));
                        let ns_key_path = path.join("keys").join(format!("{}.enc", id));

                        if tokio::fs::try_exists(&ns_metadata_path)
                            .await
                            .unwrap_or(false)
                        {
                            // Secure delete: overwrite with zeros before deletion
                            if let Ok(metadata) = tokio::fs::metadata(&ns_key_path).await {
                                let size = metadata.len() as usize;
                                let zeros = vec![0u8; size];
                                let _ = tokio::fs::write(&ns_key_path, &zeros).await;
                            }

                            let _ = tokio::fs::remove_file(&ns_metadata_path).await;
                            let _ = tokio::fs::remove_file(&ns_key_path).await;
                            return Ok(());
                        }

                        // Check identity namespace seeds/
                        let ns_seed_metadata_path = path.join("seeds").join(format!("{}.json", id));
                        let ns_seed_path = path.join("seeds").join(format!("{}.enc", id));

                        if tokio::fs::try_exists(&ns_seed_metadata_path)
                            .await
                            .unwrap_or(false)
                        {
                            // Secure delete: overwrite with zeros before deletion
                            if let Ok(metadata) = tokio::fs::metadata(&ns_seed_path).await {
                                let size = metadata.len() as usize;
                                let zeros = vec![0u8; size];
                                let _ = tokio::fs::write(&ns_seed_path, &zeros).await;
                            }

                            let _ = tokio::fs::remove_file(&ns_seed_metadata_path).await;
                            let _ = tokio::fs::remove_file(&ns_seed_path).await;
                            return Ok(());
                        }
                    }
                }
            }

            Ok(())
        })
    }

    fn list_keys(&self,
        namespace: Option<&str>,
    ) -> crate::storage::BoxFuture<'_, Result<Vec<KeyMetadata>>> {
        let namespace_dir = self.namespace_dir(namespace);
        let seeds_dir = namespace_dir.join("seeds");

        Box::pin(async move {
            let mut keys = Vec::new();

            // Read from the specific namespace directory (regular keys)
            if let Ok(mut entries) = tokio::fs::read_dir(&namespace_dir).await {
                while let Ok(Some(entry)) = entries.next_entry().await {
                    let path = entry.path();
                    if path.extension().map_or(false, |ext| ext == "json") {
                        if let Ok(content) = tokio::fs::read_to_string(&path).await {
                            if let Ok(metadata) = serde_json::from_str::<KeyMetadata>(&content) {
                                keys.push(metadata);
                            }
                        }
                    }
                }
            }

            // Read from seeds subdirectory
            if let Ok(mut entries) = tokio::fs::read_dir(&seeds_dir).await {
                while let Ok(Some(entry)) = entries.next_entry().await {
                    let path = entry.path();
                    if path.extension().map_or(false, |ext| ext == "json") {
                        if let Ok(content) = tokio::fs::read_to_string(&path).await {
                            if let Ok(metadata) = serde_json::from_str::<KeyMetadata>(&content) {
                                keys.push(metadata);
                            }
                        }
                    }
                }
            }

            Ok(keys)
        })
    }

    fn exists(&self, id: KeyId) -> crate::storage::BoxFuture<'_, Result<bool>> {
        Box::pin(async move {
            // Check admin namespace keys/ first
            let admin_metadata_path = self.namespaced_metadata_path(None, id);
            if tokio::fs::try_exists(&admin_metadata_path)
                .await
                .unwrap_or(false)
            {
                return Ok(true);
            }

            // Check admin namespace seeds/
            let admin_seed_metadata_path = self.namespaced_seed_metadata_path(None, id);
            if tokio::fs::try_exists(&admin_seed_metadata_path)
                .await
                .unwrap_or(false)
            {
                return Ok(true);
            }

            // Search through identity namespaces
            let keys_dir = self.base_path.join("keys");
            if let Ok(mut entries) = tokio::fs::read_dir(&keys_dir).await {
                while let Ok(Some(entry)) = entries.next_entry().await {
                    let path = entry.path();
                    if path.is_dir() {
                        let dir_name = path.file_name()
                            .and_then(|n| n.to_str())
                            .unwrap_or("");
                        
                        if dir_name == "admin" {
                            continue;
                        }

                        // Check identity namespace keys/
                        let ns_metadata_path = path.join("keys").join(format!("{}.json", id));
                        if tokio::fs::try_exists(&ns_metadata_path)
                            .await
                            .unwrap_or(false)
                        {
                            return Ok(true);
                        }

                        // Check identity namespace seeds/
                        let ns_seed_metadata_path = path.join("seeds").join(format!("{}.json", id));
                        if tokio::fs::try_exists(&ns_seed_metadata_path)
                            .await
                            .unwrap_or(false)
                        {
                            return Ok(true);
                        }
                    }
                }
            }

            Ok(false)
        })
    }
}
