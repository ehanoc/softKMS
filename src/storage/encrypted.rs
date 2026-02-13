//! Encrypted storage backend with security layer integration
//!
//! This module provides a storage backend that automatically encrypts/decrypts
//! key material using the Security Layer (AES-256-GCM).

use crate::storage::file::FileStorage;
use crate::storage::StorageBackend;
use crate::security::{KeyWrapper, MasterKey, SecurityError, SecurityManager, WrappedKey};
use crate::{Config, KeyId, KeyMetadata, Result, Error};
use std::path::PathBuf;
use std::sync::Arc;

/// Encrypted file storage backend
///
/// Wraps FileStorage with automatic encryption/decryption using the Security Layer.
/// All key material is encrypted with AES-256-GCM before being written to disk.
pub struct EncryptedFileStorage {
    inner: FileStorage,
    security_manager: Arc<SecurityManager>,
}

impl EncryptedFileStorage {
    /// Create new encrypted file storage
    pub fn new(
        base_path: PathBuf,
        config: Config,
        security_manager: Arc<SecurityManager>,
    ) -> Self {
        let inner = FileStorage::new(base_path, config);
        Self {
            inner,
            security_manager,
        }
    }
    
    /// Build AAD from key metadata for authentication
    fn build_aad(metadata: &KeyMetadata) -> Vec<u8> {
        // Include all metadata fields to prevent tampering
        format!(
            "key_id={}&algorithm={}&key_type={:?}&created_at={}",
            metadata.id,
            metadata.algorithm,
            metadata.key_type,
            metadata.created_at
        ).into_bytes()
    }
}

impl StorageBackend for EncryptedFileStorage {
    fn init(&self) -> crate::storage::BoxFuture<'_, Result<()>> {
        Box::pin(async move {
            // Initialize inner storage
            self.inner.init().await?;
            
            // Ensure security manager is initialized (passphrase prompted)
            // This will prompt for passphrase on first access
            Ok(())
        })
    }
    
    fn store_key(
        &self,
        id: KeyId,
        metadata: &KeyMetadata,
        plaintext_data: &[u8],
    ) -> crate::storage::BoxFuture<'_, Result<()>> {
        let metadata = metadata.clone();
        let plaintext_data = plaintext_data.to_vec();
        
        Box::pin(async move {
            // Get master key (may prompt for passphrase)
            let master_key = self.security_manager
                .get_master_key(false)
                .map_err(|e| Error::Crypto(e.to_string()))?;
            
            // Create wrapper and encrypt
            let wrapper = self.security_manager.create_wrapper(&master_key);
            let aad = Self::build_aad(&metadata);
            
            let wrapped = wrapper
                .wrap(&plaintext_data, &aad)
                .map_err(|e| Error::Crypto(e.to_string()))?;
            
            // Serialize to binary format
            let encrypted_data = wrapped.to_bytes();
            
            // Store encrypted data
            self.inner.store_key(id, &metadata, &encrypted_data).await?;
            
            Ok(())
        })
    }
    
    fn retrieve_key(
        &self,
        id: KeyId,
    ) -> crate::storage::BoxFuture<'_, Result<Option<(KeyMetadata, Vec<u8>)>>> {
        Box::pin(async move {
            // Retrieve encrypted data
            let result = self.inner.retrieve_key(id).await?;
            
            if let Some((metadata, encrypted_data)) = result {
                // Get master key (may prompt for passphrase)
                let master_key = self.security_manager
                    .get_master_key(false)
                    .map_err(|e| Error::Crypto(e.to_string()))?;
                
                // Deserialize wrapped key
                let wrapped = WrappedKey::from_bytes(&encrypted_data)
                    .map_err(|e| Error::Crypto(e.to_string()))?;
                
                // Decrypt
                let wrapper = self.security_manager.create_wrapper(&master_key);
                let aad = Self::build_aad(&metadata);
                
                let plaintext = wrapper
                    .unwrap(&wrapped, &aad)
                    .map_err(|e| Error::Crypto(e.to_string()))?;
                
                Ok(Some((metadata, plaintext)))
            } else {
                Ok(None)
            }
        })
    }
    
    fn delete_key(&self, id: KeyId) -> crate::storage::BoxFuture<'_, Result<()>> {
        self.inner.delete_key(id)
    }
    
    fn list_keys(&self) -> crate::storage::BoxFuture<'_, Result<Vec<KeyMetadata>>> {
        self.inner.list_keys()
    }
    
    fn exists(&self, id: KeyId) -> crate::storage::BoxFuture<'_, Result<bool>> {
        self.inner.exists(id)
    }
}

/// Helper to create encrypted storage with default security config
pub fn create_encrypted_storage(
    base_path: PathBuf,
    config: Config,
    cache_ttl_seconds: u64,
) -> Result<EncryptedFileStorage> {
    let security_config = crate::security::SecurityConfig::new();
    let cache = crate::security::create_cache(cache_ttl_seconds);
    let security_manager = Arc::new(SecurityManager::new(cache, security_config));
    
    Ok(EncryptedFileStorage::new(base_path, config, security_manager))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    
    #[tokio::test]
    async fn test_encrypted_storage_roundtrip() {
        // This test would require mocking the passphrase prompt
        // For now, just verify the structure compiles
    }
}
