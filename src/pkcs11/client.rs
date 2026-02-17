//! Daemon client for PKCS#11 provider
//!
//! This module provides the gRPC client to communicate with the softKMS daemon.

use std::sync::Arc;
use tonic::transport::Channel;
use crate::api::softkms::key_store_client::KeyStoreClient;
use crate::api::softkms::{
    SignRequest, VerifyRequest, ListKeysRequest, GetKeyRequest,
    CreateKeyRequest, DeleteKeyRequest,
};
use tracing::{info, warn, error};

/// Result type for daemon operations
pub type DaemonResult<T> = Result<T, DaemonError>;

/// Daemon client errors
#[derive(Debug)]
pub enum DaemonError {
    /// Connection error
    Connection(String),
    
    /// gRPC error
    Rpc(String),
    
    /// Key not found
    KeyNotFound(String),
    
    /// Authentication error
    Auth(String),
    
    /// Operation not supported
    NotSupported(String),
}

impl std::fmt::Display for DaemonError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DaemonError::Connection(msg) => write!(f, "Connection: {}", msg),
            DaemonError::Rpc(msg) => write!(f, "RPC: {}", msg),
            DaemonError::KeyNotFound(id) => write!(f, "Key not found: {}", id),
            DaemonError::Auth(msg) => write!(f, "Auth: {}", msg),
            DaemonError::NotSupported(msg) => write!(f, "Not supported: {}", msg),
        }
    }
}

impl std::error::Error for DaemonError {}

/// Daemon client wrapper
pub struct DaemonClient {
    client: Option<KeyStoreClient<Channel>>,
    passphrase: Option<String>,
    server: String,
}

impl DaemonClient {
    /// Create a new daemon client
    pub fn new(server: &str) -> Self {
        Self {
            client: None,
            passphrase: None,
            server: server.to_string(),
        }
    }
    
    /// Connect to the daemon
    pub async fn connect(&mut self) -> DaemonResult<()> {
        match KeyStoreClient::connect(self.server.clone()).await {
            Ok(client) => {
                self.client = Some(client);
                info!("Connected to daemon");
                Ok(())
            }
            Err(e) => {
                error!("Failed to connect: {}", e);
                Err(DaemonError::Connection(e.to_string()))
            }
        }
    }
    
    /// Set the passphrase for authentication
    pub fn set_passphrase(&mut self, passphrase: String) {
        self.passphrase = Some(passphrase);
    }
    
    /// Initialize the keystore
    pub async fn init(&mut self, passphrase: &str) -> DaemonResult<bool> {
        let client = self.client.as_mut()
            .ok_or(DaemonError::Connection("Not connected".to_string()))?;
        
        let request = tonic::Request::new(
            crate::api::softkms::InitRequest {
                passphrase: passphrase.to_string(),
                confirm: true,
            }
        );
        
        match client.init(request).await {
            Ok(response) => {
                // Store passphrase for subsequent calls
                if response.into_inner().success {
                    self.passphrase = Some(passphrase.to_string());
                }
                Ok(true)
            },
            Err(e) => Err(DaemonError::Rpc(e.to_string())),
        }
    }
    
    /// List all keys
    pub async fn list_keys(&mut self) -> DaemonResult<Vec<KeyInfo>> {
        let client = self.client.as_mut()
            .ok_or(DaemonError::Connection("Not connected".to_string()))?;
        
        let request = tonic::Request::new(ListKeysRequest {
            include_public_keys: true,
            auth_token: String::new(),
        });
        
        match client.list_keys(request).await {
            Ok(response) => {
                let keys = response.into_inner().keys;
                Ok(keys.into_iter().map(|k| KeyInfo {
                    id: k.key_id,
                    label: k.label.unwrap_or_default(),
                    algorithm: k.algorithm,
                    created_at: k.created_at,
                }).collect())
            }
            Err(e) => Err(DaemonError::Rpc(e.to_string())),
        }
    }
    
    /// Get key info
    pub async fn get_key(&mut self, key_id: &str) -> DaemonResult<KeyInfo> {
        let client = self.client.as_mut()
            .ok_or(DaemonError::Connection("Not connected".to_string()))?;
        
        let request = tonic::Request::new(GetKeyRequest {
            key_id: key_id.to_string(),
            include_public_key: true,
            auth_token: String::new(),
        });
        
        match client.get_key(request).await {
            Ok(response) => {
                let key = response.into_inner().key
                    .ok_or(DaemonError::KeyNotFound(key_id.to_string()))?;
                Ok(KeyInfo {
                    id: key.key_id,
                    label: key.label.unwrap_or_default(),
                    algorithm: key.algorithm,
                    created_at: key.created_at,
                })
            }
            Err(e) => Err(DaemonError::Rpc(e.to_string())),
        }
    }
    
    /// Sign data
    pub async fn sign(&mut self, key_id: &str, data: &[u8]) -> DaemonResult<Vec<u8>> {
        let client = self.client.as_mut()
            .ok_or(DaemonError::Connection("Not connected".to_string()))?;
        
        let passphrase = self.passphrase.as_deref().unwrap_or("");
        
        let request = tonic::Request::new(SignRequest {
            key_id: key_id.to_string(),
            data: data.to_vec(),
            passphrase: passphrase.to_string(),
            auth_token: String::new(),
        });
        
        match client.sign(request).await {
            Ok(response) => Ok(response.into_inner().signature),
            Err(e) => Err(DaemonError::Rpc(e.to_string())),
        }
    }
    
    /// Verify a signature
    pub async fn verify(&mut self, key_id: &str, data: &[u8], signature: &[u8]) -> DaemonResult<bool> {
        let client = self.client.as_mut()
            .ok_or(DaemonError::Connection("Not connected".to_string()))?;
        
        let request = tonic::Request::new(VerifyRequest {
            key_id: key_id.to_string(),
            data: data.to_vec(),
            signature: signature.to_vec(),
        });
        
        match client.verify(request).await {
            Ok(response) => Ok(response.into_inner().valid),
            Err(e) => Err(DaemonError::Rpc(e.to_string())),
        }
    }
    
    /// Create/generate a new key
    pub async fn create_key(&mut self, algorithm: &str, label: Option<&str>, passphrase: &str) -> DaemonResult<String> {
        let client = self.client.as_mut()
            .ok_or(DaemonError::Connection("Not connected".to_string()))?;
        
        let mut attributes = std::collections::HashMap::new();
        
        let request = tonic::Request::new(CreateKeyRequest {
            algorithm: algorithm.to_string(),
            label: label.map(String::from),
            attributes,
            passphrase: passphrase.to_string(),
            auth_token: String::new(),
        });
        
        match client.create_key(request).await {
            Ok(response) => Ok(response.into_inner().key_id),
            Err(e) => Err(DaemonError::Rpc(e.to_string())),
        }
    }
}

/// Key information from the daemon
#[derive(Debug, Clone)]
pub struct KeyInfo {
    pub id: String,
    pub label: String,
    pub algorithm: String,
    pub created_at: String,
}
