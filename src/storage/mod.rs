//! Storage backends

pub mod file;

use crate::{KeyId, KeyMetadata, Result};
use std::future::Future;
use std::pin::Pin;

/// Boxed future type for dyn compatibility
type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Storage backend trait
/// 
/// This trait uses boxed futures for object safety (dyn compatibility).
pub trait StorageBackend: Send + Sync {
    /// Initialize storage
    fn init(&self) -> BoxFuture<'_, Result<()>>;
    
    /// Store key
    fn store_key(
        &self,
        id: KeyId,
        metadata: &KeyMetadata,
        encrypted_data: &[u8],
    ) -> BoxFuture<'_, Result<()>>;
    
    /// Retrieve key
    fn retrieve_key(
        &self,
        id: KeyId,
    ) -> BoxFuture<'_, Result<Option<(KeyMetadata, Vec<u8>)>>>;
    
    /// Delete key
    fn delete_key(&self,
        id: KeyId,
    ) -> BoxFuture<'_, Result<()>>;
    
    /// List all keys
    fn list_keys(&self) -> BoxFuture<'_, Result<Vec<KeyMetadata>>>;
    
    /// Check if key exists
    fn exists(&self, id: KeyId) -> BoxFuture<'_, Result<bool>>;
}
