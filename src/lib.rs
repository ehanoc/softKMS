//! softKMS - Modern Software Key Management System
//!
//! This is the core library for softKMS, providing:
//! - Pluggable cryptographic engines
//! - HD wallet support
//! - Multiple storage backends
//! - gRPC and REST APIs
//! - PKCS#11 compatibility

#![deny(unsafe_code)]
#![warn(missing_docs)]

pub mod api;
pub mod crypto;
pub mod daemon;
pub mod hd_wallet;
pub mod ipc;
pub mod key_service;
pub mod security;
pub mod storage;
pub mod webauthn;

// Re-export daemon for main.rs
pub use daemon::Daemon;
pub use security::{SecurityConfig, SecurityManager};

use thiserror::Error;

/// softKMS result type
pub type Result<T> = std::result::Result<T, Error>;

/// softKMS error types
#[derive(Error, Debug)]
pub enum Error {
    /// Cryptographic error
    #[error("Crypto error: {0}")]
    Crypto(String),
    
    /// Storage error
    #[error("Storage error: {0}")]
    Storage(String),
    
    /// Invalid key
    #[error("Invalid key: {0}")]
    InvalidKey(String),
    
    /// Invalid parameters
    #[error("Invalid parameters: {0}")]
    InvalidParams(String),
    
    /// Key not found
    #[error("Key not found: {0}")]
    KeyNotFound(String),
    
    /// Access denied
    #[error("Access denied")]
    AccessDenied,
    
    /// Internal error
    #[error("Internal error: {0}")]
    Internal(String),
}

impl From<std::io::Error> for Error {
    fn from(error: std::io::Error) -> Self {
        Error::Internal(error.to_string())
    }
}

/// Unique identifier for keys
pub type KeyId = uuid::Uuid;

/// Key metadata
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct KeyMetadata {
    /// Key ID
    pub id: KeyId,
    /// Human-readable label
    pub label: Option<String>,
    /// Algorithm (ed25519, ecdsa, etc.)
    pub algorithm: String,
    /// Key type (seed, derived, imported)
    pub key_type: KeyType,
    /// Creation timestamp
    pub created_at: chrono::DateTime<chrono::Utc>,
    /// Custom attributes
    pub attributes: std::collections::HashMap<String, String>,
    /// Public key (optional, for verification)
    pub public_key: Vec<u8>,
}

/// Key types
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum KeyType {
    /// HD wallet seed
    Seed,
    /// Derived key from seed
    Derived,
    /// Imported key
    Imported,
}

impl std::fmt::Display for KeyType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KeyType::Seed => write!(f, "seed"),
            KeyType::Derived => write!(f, "derived"),
            KeyType::Imported => write!(f, "imported"),
        }
    }
}

/// Key handle (opaque to clients)
pub struct KeyHandle {
    /// Key ID
    pub id: KeyId,
    /// Key metadata
    pub metadata: KeyMetadata,
}

/// Signature result
#[derive(Debug, Clone)]
pub struct Signature {
    /// Signature bytes
    pub bytes: Vec<u8>,
    /// Algorithm used
    pub algorithm: String,
}

/// Configuration for softKMS
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Config {
    /// Storage backend configuration
    pub storage: StorageConfig,
    /// API server configuration
    pub api: ApiConfig,
    /// Logging configuration
    pub logging: LoggingConfig,
}

/// Storage configuration
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct StorageConfig {
    /// Storage type (file, tpm, vault)
    pub backend: String,
    /// Path to storage directory
    pub path: std::path::PathBuf,
    /// Encryption settings
    pub encryption: EncryptionConfig,
}

/// Encryption configuration
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct EncryptionConfig {
    /// Master PIN or password file
    pub pin: Option<String>,
    /// Key derivation iterations
    pub pbkdf2_iterations: u32,
}

/// API configuration
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ApiConfig {
    /// gRPC server address
    pub grpc_addr: String,
    /// REST server address
    pub rest_addr: Option<String>,
    /// Enable PKCS#11 interface
    pub enable_pkcs11: bool,
}

/// Logging configuration
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct LoggingConfig {
    /// Log level
    pub level: String,
    /// Log file path (None for stdout)
    pub file: Option<std::path::PathBuf>,
}

impl Default for Config {
    fn default() -> Self {
        // Use user-local directory for storage
        let storage_path = std::env::var("HOME")
            .map(|home| std::path::PathBuf::from(home).join(".softKMS").join("data"))
            .unwrap_or_else(|_| std::path::PathBuf::from("/tmp/softkms-data"));
        
        Self {
            storage: StorageConfig {
                backend: "file".to_string(),
                path: storage_path,
                encryption: EncryptionConfig {
                    pin: None,
                    pbkdf2_iterations: 210_000,
                },
            },
            api: ApiConfig {
                grpc_addr: "127.0.0.1:50051".to_string(),
                rest_addr: Some("127.0.0.1:8080".to_string()),
                enable_pkcs11: true,
            },
            logging: LoggingConfig {
                level: "info".to_string(),
                file: None,
            },
        }
    }
}
