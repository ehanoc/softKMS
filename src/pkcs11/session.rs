//! Session state management for PKCS#11

use tracing::info;

/// Session state
#[derive(Debug, Clone)]
pub struct SessionState {
    /// Session handle
    pub handle: u64,
    /// Is user logged in
    pub is_logged_in: bool,
    /// Is read-only session
    pub is_read_only: bool,
    /// Passphrase (PIN) for authentication
    pub passphrase: Option<String>,
    /// Active key handle for signing (set by C_SignInit)
    pub active_key_handle: Option<u64>,
    /// Key ID from daemon (for calling daemon)
    pub active_key_id: Option<String>,
    /// Algorithm for signing (e.g., "ed25519")
    pub signing_algorithm: Option<String>,
    /// Identity token for PKCS#11 authentication
    pub identity_token: Option<String>,
    /// Identity public key for key ownership
    pub identity_pubkey: Option<String>,
    /// Whether this is an identity-based session (vs admin)
    pub is_identity_session: bool,
    /// Buffer for accumulating data in multi-part signing
    pub sign_buffer: Vec<u8>,
}

impl SessionState {
    /// Create a new session
    pub fn new(handle: u64, is_read_only: bool) -> Self {
        Self {
            handle,
            is_logged_in: false,
            is_read_only,
            passphrase: None,
            active_key_handle: None,
            active_key_id: None,
            signing_algorithm: None,
            identity_token: None,
            identity_pubkey: None,
            is_identity_session: false,
            sign_buffer: Vec::new(),
        }
    }
}
