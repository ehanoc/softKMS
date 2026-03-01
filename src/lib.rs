//! softKMS - Modern Software Key Management System
//!
//! This is the core library for softKMS, providing:
//! - Pluggable cryptographic engines
//! - HD wallet support
//! - Multiple storage backends
//! - gRPC and REST APIs
//! - PKCS#11 compatibility

#![allow(missing_docs)]

pub mod api;
pub mod audit;
pub mod crypto;
pub mod daemon;
pub mod identity;
pub mod key_service;

#[allow(unsafe_code)]
pub mod pkcs11;

pub mod security;
pub mod storage;
pub mod webauthn;

// Re-export daemon for main.rs
pub use daemon::Daemon;
pub use security::{SecurityConfig, SecurityManager};

/// Run mode for softKMS daemon
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RunMode {
    /// Auto-detect based on UID and HOME
    #[default]
    Auto,
    /// Force user mode (XDG paths)
    User,
    /// Force system mode (/etc, /var paths)
    System,
}

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
    /// Owner identity public key (None = admin-owned)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner_identity: Option<String>,
}

impl KeyMetadata {
    /// Create new KeyMetadata with optional owner_identity
    pub fn new(
        id: KeyId,
        label: Option<String>,
        algorithm: String,
        key_type: KeyType,
        created_at: chrono::DateTime<chrono::Utc>,
        attributes: std::collections::HashMap<String, String>,
        public_key: Vec<u8>,
    ) -> Self {
        Self {
            id,
            label,
            algorithm,
            key_type,
            created_at,
            attributes,
            public_key,
            owner_identity: None,
        }
    }
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
    /// Extended public key (xpub) for watch-only derivation
    ExtendedPublic,
}

impl std::fmt::Display for KeyType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KeyType::Seed => write!(f, "seed"),
            KeyType::Derived => write!(f, "derived"),
            KeyType::Imported => write!(f, "imported"),
            KeyType::ExtendedPublic => write!(f, "xpub"),
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
    /// Run mode (not serialized, set at runtime)
    #[serde(skip)]
    pub run_mode: RunMode,
}

impl Config {
    /// Load configuration with automatic discovery
    /// 
    /// Search order:
    /// 1. CLI provided path (if specified)
    /// 2. $PWD/softkms.toml (project-local)
    /// 3. $XDG_CONFIG_HOME/softkms/config.toml (user config)
    /// 4. ~/.config/softkms/config.toml (fallback user config)
    /// 5. /etc/softkms/config.toml (system-wide)
    /// 6. Built-in defaults
    pub fn load(config_path: Option<std::path::PathBuf>, mode: RunMode) -> Result<Self> {
        let mode = Self::determine_mode(mode, config_path.as_ref());
        
        // Try to load from file
        let config = if let Some(path) = config_path {
            Self::load_from_file(&path)?
        } else {
            Self::discover_config()?
        };
        
        // Apply mode-specific defaults if config file didn't set paths
        let mut config = config;
        config.run_mode = mode;
        config.apply_mode_defaults(mode);
        
        Ok(config)
    }
    
    /// Determine run mode
    fn determine_mode(mode: RunMode, config_path: Option<&std::path::PathBuf>) -> RunMode {
        match mode {
            RunMode::User => RunMode::User,
            RunMode::System => RunMode::System,
            RunMode::Auto => {
                // Check config path hint first
                if let Some(path) = config_path {
                    if path.starts_with("/etc/") {
                        return RunMode::System;
                    }
                    if let Some(home) = dirs::home_dir() {
                        if path.starts_with(&home) {
                            return RunMode::User;
                        }
                    }
                }
                
                // Auto-detect from environment
                #[cfg(not(target_os = "windows"))]
                {
                    let uid = unsafe { libc::getuid() };
                    let home = std::env::var("HOME").unwrap_or_default();
                    
                    if uid == 0 || home == "/var/lib/softkms" || home == "/nonexistent" {
                        RunMode::System
                    } else {
                        RunMode::User
                    }
                }
                
                #[cfg(target_os = "windows")]
                {
                    RunMode::User
                }
            }
        }
    }
    
    /// Discover config file using XDG and system paths
    fn discover_config() -> Result<Self> {
        let search_paths: Vec<std::path::PathBuf> = vec![
            // Project-local
            std::env::current_dir().ok().map(|d| d.join("softkms.toml")).unwrap_or_default(),
            // XDG config
            dirs::config_dir().map(|d| d.join("softkms").join("config.toml")).unwrap_or_default(),
            // System-wide
            std::path::PathBuf::from("/etc/softkms/config.toml"),
        ];
        
        for path in search_paths {
            if path.exists() {
                return Self::load_from_file(&path);
            }
        }
        
        // Use defaults
        Ok(Self::default())
    }
    
    /// Load configuration from a specific file
    fn load_from_file(path: &std::path::Path) -> Result<Self> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| Error::Storage(format!("Failed to read config file: {}", e)))?;
        
        let config: Config = toml::from_str(&content)
            .map_err(|e| Error::InvalidParams(format!("Failed to parse config file: {}", e)))?;
        
        Ok(config)
    }
    
    /// Apply mode-specific default paths
    fn apply_mode_defaults(&mut self, mode: RunMode) {
        match mode {
            RunMode::System => {
                // System paths - only apply if not already set
                if self.storage.path == std::path::PathBuf::new() {
                    self.storage.path = std::path::PathBuf::from("/var/lib/softkms");
                }
                if self.logging.audit_path.is_none() {
                    self.logging.audit_path = Some(std::path::PathBuf::from("/var/log/softkms/audit.log"));
                }
            }
            RunMode::User => {
                // User paths - only apply if using default (old ~/.softKMS path)
                let is_default_path = self.storage.path.to_str()
                    .map(|s| s.contains(".softKMS"))
                    .unwrap_or(false);
                if is_default_path {
                    if let Some(data_dir) = dirs::data_dir() {
                        self.storage.path = data_dir.join("softkms");
                    } else {
                        self.storage.path = std::path::PathBuf::from("/tmp/softkms-data");
                    }
                }
                if self.logging.audit_path.is_none() {
                    if let Some(state_dir) = dirs::state_dir() {
                        self.logging.audit_path = Some(state_dir.join("softkms").join("audit.log"));
                    } else if let Some(data_dir) = dirs::data_local_dir() {
                        self.logging.audit_path = Some(data_dir.join("softkms").join("audit.log"));
                    }
                }
            }
            RunMode::Auto => {}
        }
    }
    
    /// Get the data directory based on current mode
    pub fn data_dir(&self) -> &std::path::Path {
        &self.storage.path
    }
    
    /// Get the audit log path
    pub fn audit_path(&self) -> Option<&std::path::Path> {
        self.logging.audit_path.as_deref()
    }
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

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct EncryptionConfig {
    /// Master PIN or password file
    pub pin: Option<String>,
    /// Key derivation iterations
    pub pbkdf2_iterations: u32,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ApiConfig {
    /// gRPC server address
    pub grpc_addr: String,
    /// REST server address
    pub rest_addr: Option<String>,
    /// Enable PKCS#11 interface
    pub enable_pkcs11: bool,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct LoggingConfig {
    /// Log level
    pub level: String,
    /// Log file path (None for stdout)
    pub file: Option<std::path::PathBuf>,
    /// Audit log file path
    pub audit_path: Option<std::path::PathBuf>,
}

impl Default for Config {
    fn default() -> Self {
        // Start with empty paths - apply_mode_defaults will set them based on mode
        Self {
            storage: StorageConfig {
                backend: "file".to_string(),
                path: std::path::PathBuf::new(),
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
                audit_path: None,
            },
            run_mode: RunMode::Auto,
        }
    }
}
