//! Master key derivation from passphrase
//!
//! This module handles the derivation of the master encryption key from the user's
//! passphrase using PBKDF2-HMAC-SHA256. The master key is never stored, always derived.

use pbkdf2::pbkdf2_hmac;
use rand::RngCore;
use secrecy::{ExposeSecret, Secret};
use sha2::Sha256;

use super::{Result, SecurityError};

/// Fixed salt for master key derivation (32 bytes for PBKDF2)
/// Using a fixed salt ensures the same passphrase always produces the same master key.
/// The salt is not secret - security comes from the passphrase strength and PBKDF2 iterations.
const MASTER_KEY_SALT: &[u8; 32] = b"softkms-master-key-salt-v1......";

/// Master key derived from passphrase
///
/// This struct holds the 256-bit master key in a `Secret` wrapper to prevent
/// accidental logging or exposure. The key is automatically zeroized when dropped.
#[derive(Clone)]
pub struct MasterKey {
    key: Secret<[u8; 32]>,
}

impl MasterKey {
    /// Generate a new random salt
    ///
    /// Returns 32 random bytes suitable for use as a PBKDF2 salt.
    pub fn generate_salt() -> [u8; 32] {
        let mut salt = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut salt);
        salt
    }

    /// Derive master key from passphrase and salt
    ///
    /// Uses PBKDF2-HMAC-SHA256 with the specified number of iterations.
    /// The derived key is suitable for use with AES-256-GCM.
    ///
    /// # Arguments
    ///
    /// * `passphrase` - The user's passphrase
    /// * `iterations` - Number of PBKDF2 iterations (recommend 210,000+)
    ///
    /// # Returns
    ///
    /// A new `MasterKey` containing the derived 256-bit key
    ///
    /// # Errors
    ///
    /// Returns an error if PBKDF2 derivation fails
    pub fn derive(passphrase: &str, iterations: u32) -> Result<Self> {
        Self::derive_with_salt(passphrase, MASTER_KEY_SALT, iterations)
    }

    /// Derive master key with specific salt
    ///
    /// This is used internally when we need to derive the same key
    /// (e.g., for unwrapping an existing key with known salt)
    pub fn derive_with_salt(passphrase: &str, salt: &[u8; 32], iterations: u32) -> Result<Self> {
        let mut key = [0u8; 32];

        pbkdf2_hmac::<Sha256>(passphrase.as_bytes(), salt, iterations, &mut key);

        Ok(Self {
            key: Secret::new(key),
        })
    }

    /// Create MasterKey from existing secret
    ///
    /// Used internally for cache operations
    pub fn from_secret(secret: std::sync::Arc<Secret<[u8; 32]>>) -> Self {
        Self {
            key: Secret::new(*secret.expose_secret()),
        }
    }

    /// Expose the key for cryptographic operations
    ///
    /// The key is returned as a reference to prevent copying.
    /// Use this only when needed for encryption/decryption.
    pub fn expose_secret(&self) -> &[u8; 32] {
        self.key.expose_secret()
    }

    /// Convert to Secret for caching
    pub fn to_secret(&self) -> Secret<[u8; 32]> {
        Secret::new(*self.key.expose_secret())
    }

    /// Try to lock memory to prevent swapping
    #[cfg(unix)]
    #[allow(unsafe_code)]
    pub fn try_mlock(&self) -> Result<()> {
        use libc::{c_void, mlock};

        let ptr = self.key.expose_secret().as_ptr() as *const c_void;
        let len = 32usize;

        let ret = unsafe { mlock(ptr, len) };

        if ret != 0 {
            let err = std::io::Error::last_os_error();
            Err(SecurityError::MemoryLockFailed(err.to_string()))
        } else {
            Ok(())
        }
    }

    /// Try to unlock memory
    #[cfg(unix)]
    #[allow(unsafe_code)]
    pub fn try_munlock(&self) -> Result<()> {
        use libc::{c_void, munlock};

        let ptr = self.key.expose_secret().as_ptr() as *const c_void;
        let len = 32usize;

        let ret = unsafe { munlock(ptr, len) };

        if ret != 0 {
            let err = std::io::Error::last_os_error();
            Err(SecurityError::MemoryLockFailed(err.to_string()))
        } else {
            Ok(())
        }
    }

    /// No-op on non-Unix systems
    #[cfg(not(unix))]
    pub fn try_mlock(&self) -> Result<()> {
        Ok(())
    }

    /// No-op on non-Unix systems
    #[cfg(not(unix))]
    pub fn try_munlock(&self) -> Result<()> {
        Ok(())
    }
}

/// Prompt user for passphrase securely
///
/// Uses rpassword to hide input from terminal and logs.
/// Returns error if input fails or passphrase is empty.
pub fn prompt_passphrase() -> Result<String> {
    let passphrase = rpassword::prompt_password("Enter passphrase: ")
        .map_err(|_| SecurityError::InvalidPassphrase("Input error".to_string()))?;

    if passphrase.is_empty() {
        return Err(SecurityError::InvalidPassphrase(
            "Passphrase cannot be empty".to_string(),
        ));
    }

    Ok(passphrase)
}

/// Prompt for passphrase with confirmation
///
/// Asks user to enter passphrase twice and verifies they match.
/// This should be used during initial setup or passphrase change.
pub fn prompt_passphrase_with_confirmation() -> Result<String> {
    let passphrase = rpassword::prompt_password("Enter passphrase: ")
        .map_err(|_| SecurityError::InvalidPassphrase("Input error".to_string()))?;

    if passphrase.is_empty() {
        return Err(SecurityError::InvalidPassphrase(
            "Passphrase cannot be empty".to_string(),
        ));
    }

    let confirm = rpassword::prompt_password("Confirm passphrase: ")
        .map_err(|_| SecurityError::InvalidPassphrase("Input error".to_string()))?;

    if passphrase != confirm {
        return Err(SecurityError::PassphraseMismatch);
    }

    Ok(passphrase)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_key() {
        let key1 = MasterKey::derive("test", 1000).unwrap();
        let key2 = MasterKey::derive("test", 1000).unwrap();

        // Same passphrase + fixed salt = same key
        assert_eq!(key1.expose_secret(), key2.expose_secret());
    }

    #[test]
    fn test_derive_with_same_salt() {
        let salt = MasterKey::generate_salt();
        let key1 = MasterKey::derive_with_salt("test", &salt, 1000).unwrap();
        let key2 = MasterKey::derive_with_salt("test", &salt, 1000).unwrap();

        // Same passphrase + same salt = same key
        assert_eq!(key1.expose_secret(), key2.expose_secret());
    }

    #[test]
    fn test_different_passphrases() {
        let salt = MasterKey::generate_salt();
        let key1 = MasterKey::derive_with_salt("test1", &salt, 1000).unwrap();
        let key2 = MasterKey::derive_with_salt("test2", &salt, 1000).unwrap();

        // Different passphrases = different keys
        assert_ne!(key1.expose_secret(), key2.expose_secret());
    }

    #[test]
    fn test_salt_randomness() {
        let salt1 = MasterKey::generate_salt();
        let salt2 = MasterKey::generate_salt();

        // Salts should be different (with extremely high probability)
        assert_ne!(salt1, salt2);
    }
}
