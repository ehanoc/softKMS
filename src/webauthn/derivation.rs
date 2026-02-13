//! WebAuthn Credential Derivation from HD Wallet Seeds
//!
//! This module provides deterministic credential generation from
//! HD wallet seeds, enabling backup and recovery of Passkeys.
//!
//! ## Derivation Scheme
//!
//! Credentials are derived using the path:
//! ```text
//! m / 2017' / 0' / account' / credential_type / index
//! ```
//!
//! Where:
//! - 2017': Purpose for WebAuthn credentials
//! - 0': Coin type (generic)
//! - account': Account number
//! - credential_type: 0 (non-resident) or 1 (resident)
//! - index: Sequential or hash-based
//!
//! ## Benefits
//!
//! - Same seed phrase → same credentials across devices
//! - No need to backup individual credentials
//! - Recovery: import seed, re-derive all credentials
//! - Deterministic: `derive(seed, rp_id, user_handle)` always gives same credential

use crate::webauthn::types::{CredentialAlgorithm, RelyingParty, UserInfo, WebAuthnCredential};
use crate::Result;
use sha2::{Digest, Sha256};

/// BIP32 purpose for WebAuthn credentials
pub const WEBAUTHN_PURPOSE: u32 = 2017;

/// Coin type for generic use
pub const COIN_TYPE_GENERIC: u32 = 0;

/// Credential type: non-resident
pub const CREDENTIAL_TYPE_NON_RESIDENT: u32 = 0;

/// Credential type: resident
pub const CREDENTIAL_TYPE_RESIDENT: u32 = 1;

/// Derive a credential ID deterministically
///
/// Uses HKDF-like construction from seed + RP ID + user handle
pub fn derive_credential_id(seed: &[u8], rp_id: &str, user_handle: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();

    // Mix seed
    hasher.update(seed);

    // Domain separator for WebAuthn
    hasher.update(b"webauthn:v1:credential_id:");

    // Mix RP ID (the relying party)
    hasher.update(rp_id.as_bytes());

    // Mix user handle
    hasher.update(user_handle);

    // 32-byte credential ID
    hasher.finalize().to_vec()
}

/// Derive a derivation path for a credential
///
/// Returns a BIP32 path like "m/2017'/0'/0'/0/123"
pub fn derive_credential_path(
    _seed: &[u8],
    rp_id: &str,
    user_handle: &[u8],
    is_resident: bool,
) -> String {
    // Use hash of RP ID + user handle as index
    let mut hasher = Sha256::new();
    hasher.update(rp_id.as_bytes());
    hasher.update(user_handle);
    let hash = hasher.finalize();

    // Use first 4 bytes as 32-bit unsigned index
    let index = u32::from_be_bytes([hash[0], hash[1], hash[2], hash[3]]);

    let credential_type = if is_resident {
        CREDENTIAL_TYPE_RESIDENT
    } else {
        CREDENTIAL_TYPE_NON_RESIDENT
    };

    format!(
        "m/{}'/{}'/{}'/{}/{}",
        WEBAUTHN_PURPOSE,
        COIN_TYPE_GENERIC,
        0, // account 0
        credential_type,
        index
    )
}

/// Derive a WebAuthn credential from a seed
///
/// This creates a deterministic credential that can be recovered
/// from the same seed phrase.
pub fn derive_credential(
    seed: &[u8],
    rp: &RelyingParty,
    user: &UserInfo,
    _algorithm: CredentialAlgorithm,
    is_resident: bool,
) -> Result<WebAuthnCredential> {
    // Derive credential ID
    let credential_id = derive_credential_id(seed, &rp.id, &user.id);

    // Derive BIP32 path
    let derivation_path = derive_credential_path(seed, &rp.id, &user.id, is_resident);

    // TODO: Derive key pair using BIP32
    // For now, return placeholder
    let credential = WebAuthnCredential {
        credential_id,
        rp_id: rp.id.clone(),
        user_handle: user.id.clone(),
        user_name: Some(user.name.clone()),
        display_name: user.display_name.clone(),
        public_key: vec![], // TODO: Derive from seed
        private_key_id: uuid::Uuid::new_v4(),
        sign_count: 0,
        is_resident,
        created_at: chrono::Utc::now(),
        last_used_at: None,
        derivation_path: Some(derivation_path),
    };

    Ok(credential)
}

/// Recover all credentials from a seed
///
/// This would enumerate all possible credentials by scanning
/// common RP IDs and user handles, or by using a stored index.
pub fn recover_credentials_from_seed(_seed: &[u8]) -> Result<Vec<WebAuthnCredential>> {
    // TODO: Implement credential recovery
    // This requires either:
    // 1. A stored index of RP IDs
    // 2. Scanning known/common RP IDs
    // 3. User providing RP IDs to recover

    Ok(Vec::new())
}

/// Compute the RP hash for path derivation
fn rp_hash(rp_id: &str) -> u32 {
    let mut hasher = Sha256::new();
    hasher.update(rp_id.as_bytes());
    let hash = hasher.finalize();

    // Use first 4 bytes
    u32::from_be_bytes([hash[0], hash[1], hash[2], hash[3]])
}

/// Compute the user hash for path derivation
fn user_hash(user_handle: &[u8]) -> u32 {
    let mut hasher = Sha256::new();
    hasher.update(user_handle);
    let hash = hasher.finalize();

    // Use first 4 bytes
    u32::from_be_bytes([hash[0], hash[1], hash[2], hash[3]])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_credential_id() {
        let seed = b"test seed for credential derivation";
        let rp_id = "github.com";
        let user_handle = b"user123";

        let id1 = derive_credential_id(seed, rp_id, user_handle);
        let id2 = derive_credential_id(seed, rp_id, user_handle);

        // Deterministic
        assert_eq!(id1, id2);
        assert_eq!(id1.len(), 32);

        // Different inputs give different outputs
        let id3 = derive_credential_id(seed, "google.com", user_handle);
        assert_ne!(id1, id3);
    }

    #[test]
    fn test_derive_credential_path() {
        let seed = b"test seed";
        let rp_id = "github.com";
        let user_handle = b"user123";

        let path = derive_credential_path(seed, rp_id, user_handle, false);

        // Should contain the purpose
        assert!(path.contains("2017"));
        // Should be deterministic
        let path2 = derive_credential_path(seed, rp_id, user_handle, false);
        assert_eq!(path, path2);
    }
}
