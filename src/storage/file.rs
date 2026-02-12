//! File-based encrypted storage backend

use crate::{Config, KeyId, KeyMetadata, Result};
use crate::storage::StorageBackend;
use std::path::PathBuf;

/// File-based storage backend
pub struct FileStorage {
    base_path: PathBuf,
    config: Config,
}

impl FileStorage {
    /// Create new file storage
    pub fn new(base_path: PathBuf, config: Config) -> Self {
        Self {
            base_path,
            config,
        }
    }
    
    /// Get path for key file
    fn key_path(&self, id: KeyId) -> PathBuf {
        self.base_path.join(format!("{}.enc", id))
    }
    
    /// Get path for metadata file
    fn metadata_path(&self, id: KeyId) -> PathBuf {
        self.base_path.join(format!("{}.json", id))
    }
}

impl StorageBackend for FileStorage {
    async fn init(&self) -> Result<()> {
        tokio::fs::create_dir_all(&self.base_path)
            .await
            .map_err(|e| crate::Error::Storage(format!("Failed to create storage directory: {}", e)))?;
        Ok(())
    }
    
    async fn store_key(
        &self,
        id: KeyId,
        metadata: &KeyMetadata,
        encrypted_data: &[u8],
    ) -> Result<()> {
        // Store metadata
        let metadata_json = serde_json::to_string(metadata)
            .map_err(|e| crate::Error::Storage(format!("Failed to serialize metadata: {}", e)))?;
        
        tokio::fs::write(self.metadata_path(id), metadata_json)
            .await
            .map_err(|e| crate::Error::Storage(format!("Failed to write metadata: {}", e)))?;
        
        // Store encrypted key data
        tokio::fs::write(self.key_path(id), encrypted_data)
            .await
            .map_err(|e| crate::Error::Storage(format!("Failed to write key data: {}", e)))?;
        
        Ok(())
    }
    
    async fn retrieve_key(
        &self,
        id: KeyId,
    ) -> Result<Option<(KeyMetadata, Vec<u8>)>> {
        let metadata_path = self.metadata_path(id);
        let key_path = self.key_path(id);
        
        // Check if files exist
        if !tokio::fs::try_exists(&metadata_path)
            .await
            .map_err(|e| crate::Error::Storage(format!("Failed to check metadata: {}", e)))?
        {
            return Ok(None);
        }
        
        // Read metadata
        let metadata_json = tokio::fs::read_to_string(&metadata_path)
            .await
            .map_err(|e| crate::Error::Storage(format!("Failed to read metadata: {}", e)))?;
        
        let metadata: KeyMetadata = serde_json::from_str(&metadata_json)
            .map_err(|e| crate::Error::Storage(format!("Failed to parse metadata: {}", e)))?;
        
        // Read encrypted key data
        let encrypted_data = tokio::fs::read(&key_path)
            .await
            .map_err(|e| crate::Error::Storage(format!("Failed to read key data: {}", e)))?;
        
        Ok(Some((metadata, encrypted_data)))
    }
    
    async fn delete_key(&self,
        id: KeyId,
    ) -> Result<()> {
        let metadata_path = self.metadata_path(id);
        let key_path = self.key_path(id);
        
        // Secure delete: overwrite with zeros before deletion
        if let Ok(metadata) = tokio::fs::metadata(&key_path).await {
            let size = metadata.len() as usize;
            let zeros = vec![0u8; size];
            let _ = tokio::fs::write(&key_path, &zeros).await;
        }
        
        // Delete files
        let _ = tokio::fs::remove_file(&metadata_path).await;
        let _ = tokio::fs::remove_file(&key_path).await;
        
        Ok(())
    }
    
    async fn list_keys(&self) -> Result<Vec<KeyMetadata>> {
        let mut entries = tokio::fs::read_dir(&self.base_path)
            .await
            .map_err(|e| crate::Error::Storage(format!("Failed to read storage directory: {}", e)))?;
        
        let mut keys = Vec::new();
        
        while let Some(entry) = entries.next_entry()
            .await
            .map_err(|e| crate::Error::Storage(format!("Failed to read directory entry: {}", e)))?
        {
            let path = entry.path();
            if path.extension().map_or(false, |ext| ext == "json") {
                if let Ok(content) = tokio::fs::read_to_string(&path).await {
                    if let Ok(metadata) = serde_json::from_str::<KeyMetadata>(&content) {
                        keys.push(metadata);
                    }
                }
            }
        }
        
        Ok(keys)
    }
    
    async fn exists(&self, id: KeyId) -> Result<bool> {
        tokio::fs::try_exists(self.metadata_path(id))
            .await
            .map_err(|e| crate::Error::Storage(format!("Failed to check existence: {}", e)))
    }
}
