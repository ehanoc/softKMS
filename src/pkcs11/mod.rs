//! PKCS#11 Provider for softKMS
//!
//! This module implements a PKCS#11 provider that allows existing applications
//! (OpenSSH, Git, OpenSSL) to use softKMS as an HSM backend.
//!
//! ## Architecture
//!
//! The PKCS#11 provider acts as a CLIENT to the softKMS daemon via gRPC:
//!
//! ```text
//! Application → PKCS#11 API → libsoftkms-pkcs11.so → gRPC → softKMS Daemon
//! ```
//!
//! ## Implementation Status
//!
//! This is a WORKING STUB that demonstrates the architecture.
//! Full PKCS#11 compliance requires more implementation.

use tracing::{info, warn, error};

mod client;
pub use client::DaemonClient;

/// PKCS#11 Result
pub type Pkcs11Result<T> = Result<T, Pkcs11Error>;

/// PKCS#11 errors
#[derive(Debug, Clone)]
pub enum Pkcs11Error {
    NotInitialized,
    SlotNotFound,
    SessionError,
    Argument,
    BufferTooSmall,
    MechanismNotSupported,
    KeyNotFound,
    NotSupported,
    FunctionFailed,
}

/// Initialize the PKCS#11 provider
pub fn initialize() -> Pkcs11Result<()> {
    info!("softKMS PKCS#11 provider initialized (stub)");
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
    if let Ok(home) = std::env::var("HOME") {
        format!("{}/.softKMS/libsoftkms-pkcs11.so", home)
    } else {
        "~/.softKMS/libsoftkms-pkcs11.so".to_string()
    }
}

/// Check if PKCS#11 is available
pub fn is_available() -> bool {
    true
}

/// Sign data via the daemon (conceptual)
///
/// This demonstrates how signing would work:
/// 1. PKCS#11 receives C_Sign request
/// 2. Calls daemon client
/// 3. Daemon performs signing
/// 4. Returns signature
pub async fn sign_via_daemon(
    daemon: &mut DaemonClient,
    key_id: &str,
    data: &[u8],
) -> Pkcs11Result<Vec<u8>> {
    warn!("sign_via_daemon: Would sign via daemon gRPC");
    Ok(vec![])
}

/// Verify via the daemon (conceptual)
pub async fn verify_via_daemon(
    daemon: &mut DaemonClient,
    key_id: &str,
    data: &[u8],
    signature: &[u8],
) -> Pkcs11Result<bool> {
    warn!("verify_via_daemon: Would verify via daemon gRPC");
    Ok(false)
}
