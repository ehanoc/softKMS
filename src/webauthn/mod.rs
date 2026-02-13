//! WebAuthn/FIDO2 Authenticator Module
//!
//! This module provides WebAuthn/Passkey support for softKMS, enabling:
//! - FIDO2 credential creation and authentication
//! - Passkey backup and recovery via HD wallet derivation
//! - Browser integration via native messaging
//! - Deterministic credential generation from seeds
//!
//! ## Overview
//!
//! softKMS can act as a software-based FIDO2 authenticator, allowing users to:
//! - Store WebAuthn credentials backed by encrypted storage
//! - Derive credentials deterministically from HD wallet seeds
//! - Recover all Passkeys from a single seed phrase
//! - Use softKMS as a security key replacement in browsers
//!
//! ## Architecture
//!
//! ```text
//! Browser Extension          softKMS Daemon
//!        │                          │
//!        │ CTAP2 via Native         │
//!        │ Messaging                  │
//!        ▼                          ▼
//! ┌──────────────┐           ┌──────────────┐
//! │ WebAuthn API │──────────▶│   CTAP2      │
//! │ (navigator.  │           │   Server     │
//! │ credentials)│           └──────┬───────┘
//! └──────────────┘                  │
//!                                   ▼
//!                          ┌──────────────┐
//!                          │ Credential   │
//!                          │ Manager      │
//!                          └──────┬───────┘
//!                                 │
//!                    ┌────────────┼────────────┐
//!                    ▼            ▼            ▼
//!              ┌────────┐  ┌──────────┐  ┌─────────┐
//!              │Storage │  │  Crypto  │  │   HD    │
//!              │ Layer  │  │  Engine  │  │ Wallet  │
//!              └────────┘  └──────────┘  └─────────┘
//! ```

pub mod types;
pub mod credential;
pub mod ctap2;
pub mod native_messaging;
pub mod derivation;

use crate::{Config, Result};

/// WebAuthn authenticator configuration
#[derive(Debug, Clone)]
pub struct WebAuthnConfig {
    /// Enable WebAuthn support
    pub enabled: bool,
    /// Require PIN for credential creation
    pub require_pin_for_creation: bool,
    /// Require PIN for authentication
    pub require_pin_for_auth: bool,
    /// Allow self-attestation (no hardware attestation)
    pub allow_self_attestation: bool,
    /// AAGUID - unique identifier for this authenticator
    pub aaguid: uuid::Uuid,
    /// Native messaging host path
    pub native_messaging_host: Option<std::path::PathBuf>,
}

impl Default for WebAuthnConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            require_pin_for_creation: false,
            require_pin_for_auth: true,
            allow_self_attestation: true,
            aaguid: uuid::Uuid::new_v4(),
            native_messaging_host: None,
        }
    }
}

/// WebAuthn authenticator handle
pub struct WebAuthnAuthenticator {
    config: WebAuthnConfig,
    credential_store: credential::CredentialStore,
}

impl WebAuthnAuthenticator {
    /// Create a new WebAuthn authenticator
    pub fn new(config: WebAuthnConfig) -> Result<Self> {
        let credential_store = credential::CredentialStore::new()?;
        
        Ok(Self {
            config,
            credential_store,
        })
    }
    
    /// Start the native messaging host for browser integration
    pub async fn start_native_messaging(&self) -> Result<()> {
        native_messaging::run_host(&self.config).await
    }
}
