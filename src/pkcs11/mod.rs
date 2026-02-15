//! PKCS#11 Provider for softKMS
//!
//! This module implements a PKCS#11 provider that allows existing applications
//! (OpenSSH, Git, OpenSSL) to use softKMS as an HSM backend.
//!
//! ## Overview
//!
//! The PKCS#11 provider exposes softKMS keys as PKCS#11 objects, allowing
//! standard applications to interact with softKMS without modification.
//!
//! ## Usage
//!
//! ```bash
//! # Set PKCS#11 module path
//! export PKCS11_MODULE=~/.softKMS/libsoftkms-pkcs11.so
//!
//! # Use with OpenSSH
//! ssh-add -s ~/.softKMS/libsoftkms-pkcs11.so
//!
//! # Use with OpenSSL
//! openssl req -new -key ed25519 -engine pkcs11 -keyform engine
//! ```
//!
//! ## Supported Mechanisms (Planned)
//!
//! - CKM_EDDSA: EdDSA signing (Ed25519)
//! - CKM_ECDSA: ECDSA signing (P-256)
//!
//! ## Architecture
//!
//! The provider maps softKMS concepts to PKCS#11:
//!
//! | softKMS | PKCS#11 |
//! |---------|---------|
//! | Key | CKO_PRIVATE_KEY / CKO_PUBLIC_KEY |
//! | Key ID | CKA_ID |
//! | Key Label | CKA_LABEL |
//! | Passphrase | PIN |

use tracing::{error, info, warn};

/// PKCS#11 Provider Errors
#[derive(Debug, Clone)]
pub enum Pkcs11Error {
    /// Initialization failed
    Initialization(String),

    /// Slot not found
    SlotNotFound,

    /// Session error
    SessionError(String),

    /// Object not found
    ObjectNotFound,

    /// Key not found
    KeyNotFound(String),

    /// Mechanism not supported
    MechanismNotSupported(String),

    /// Cryptographic error
    CryptoError(String),

    /// Operation not supported
    NotSupported(String),
}

impl std::fmt::Display for Pkcs11Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Pkcs11Error::Initialization(msg) => write!(f, "Initialization failed: {}", msg),
            Pkcs11Error::SlotNotFound => write!(f, "Slot not found"),
            Pkcs11Error::SessionError(msg) => write!(f, "Session error: {}", msg),
            Pkcs11Error::ObjectNotFound => write!(f, "Object not found"),
            Pkcs11Error::KeyNotFound(id) => write!(f, "Key not found: {}", id),
            Pkcs11Error::MechanismNotSupported(m) => write!(f, "Mechanism not supported: {}", m),
            Pkcs11Error::CryptoError(msg) => write!(f, "Crypto error: {}", msg),
            Pkcs11Error::NotSupported(msg) => write!(f, "Not supported: {}", msg),
        }
    }
}

impl std::error::Error for Pkcs11Error {}

/// Initialize the PKCS#11 provider
pub fn initialize() -> Result<(), Pkcs11Error> {
    info!("PKCS#11 provider stub initialized");
    Ok(())
}

/// Get provider info
pub fn get_info() -> ProviderInfo {
    ProviderInfo {
        name: "softKMS PKCS#11 Provider",
        version: (0, 1),
        description: "softKMS - Modern Software Key Management System",
    }
}

/// Provider information
pub struct ProviderInfo {
    pub name: &'static str,
    pub version: (u8, u8),
    pub description: &'static str,
}

/// Get the PKCS#11 module path
pub fn get_module_path() -> String {
    // Default location: ~/.softKMS/
    if let Ok(home) = std::env::var("HOME") {
        format!("{}/.softKMS/libsoftkms-pkcs11.so", home)
    } else {
        "~/.softKMS/libsoftkms-pkcs11.so".to_string()
    }
}

/// Check if PKCS#11 is available
pub fn is_available() -> bool {
    // Check if the library can be loaded
    // For now, just check if cryptoki is available
    true
}
