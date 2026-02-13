//! Security error types

use thiserror::Error;

/// Security operation result
pub type Result<T> = std::result::Result<T, SecurityError>;

/// Security-specific errors
#[derive(Error, Debug)]
pub enum SecurityError {
    /// Passphrase mismatch
    #[error("Passphrase mismatch")]
    PassphraseMismatch,

    /// Invalid passphrase
    #[error("Invalid passphrase: {0}")]
    InvalidPassphrase(String),

    /// Passphrase too weak
    #[error("Passphrase too weak: {0}")]
    PassphraseTooWeak(String),

    /// Memory locking failed
    #[error("Memory locking failed: {0}")]
    MemoryLockFailed(String),

    /// Encryption failed
    #[error("Encryption failed: {0}")]
    EncryptionFailed(String),

    /// Decryption failed
    #[error("Decryption failed: {0}")]
    DecryptionFailed(String),

    /// Invalid wrapped key format
    #[error("Invalid wrapped key format")]
    InvalidWrappedKey,

    /// Invalid salt
    #[error("Invalid salt")]
    InvalidSalt,

    /// Invalid nonce
    #[error("Invalid nonce")]
    InvalidNonce,

    /// AAD integrity check failed
    #[error("AAD integrity check failed - possible tampering")]
    AadIntegrityFailed,

    /// Algorithm not supported
    #[error("Algorithm not supported: {0}")]
    UnsupportedAlgorithm(String),

    /// Version mismatch
    #[error("Version mismatch: expected {expected}, got {actual}")]
    VersionMismatch { expected: u8, actual: u8 },

    /// Cache poisoned
    #[error("Cache lock poisoned")]
    LockPoisoned,

    /// Random generation failed
    #[error("Random generation failed: {0}")]
    RandomError(String),

    /// IO error
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
}

impl From<aes_gcm::Error> for SecurityError {
    fn from(err: aes_gcm::Error) -> Self {
        SecurityError::EncryptionFailed(err.to_string())
    }
}
