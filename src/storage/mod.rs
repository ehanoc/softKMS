//! Storage backends

pub mod file;

use crate::{KeyId, KeyMetadata, Result};

/// Storage backend trait
pub trait StorageBackend: Send + Sync {
    /// Initialize storage
    fn init(&self) -> impl std::future::Future<Output = Result<()>> + Send;
    
    /// Store key
    fn store_key(
        &self,
        id: KeyId,
        metadata: &KeyMetadata,
        encrypted_data: &[u8],
    ) -> impl std::future::Future<Output = Result<()>> + Send;
    
    /// Retrieve key
    fn retrieve_key(
        &self,
        id: KeyId,
    ) -> impl std::future::Future<Output = Result<Option<(KeyMetadata, Vec<u8>)>>> + Send;
    
    /// Delete key
    fn delete_key(&self,
        id: KeyId,
    ) -> impl std::future::Future<Output = Result<()>> + Send;
    
    /// List all keys
    fn list_keys(&self) -> impl std::future::Future<Output = Result<Vec<KeyMetadata>>> + Send;
    
    /// Check if key exists
    fn exists(&self, id: KeyId) -> impl std::future::Future<Output = Result<bool>> + Send;
}
